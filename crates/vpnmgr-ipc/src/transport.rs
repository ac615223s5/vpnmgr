//! The pipe the protocol runs over, and the access control on it.
//!
//! Two transports, one shape. On Unix it is a socket in the filesystem; on
//! Windows a named pipe. The protocol above is identical — newline-delimited
//! JSON — so everything except this module is platform-independent.
//!
//! # Access control is the transport's job
//!
//! There is no authentication in the protocol. Anyone who can open the pipe can
//! drive the daemon, which runs with full privilege, so *who can open it* is
//! the entire security boundary.
//!
//! * Unix: the socket is owned by group `vpnmgr`, mode 0660.
//! * Windows: the pipe carries an explicit DACL. This has to be set
//!   deliberately — a named pipe created with no security descriptor grants
//!   access based on the creator's default DACL, and a service running as
//!   LocalSystem would produce a pipe no ordinary user could open, making the
//!   CLI and tray useless without elevation.
//!
//! # One difference the caller cannot ignore
//!
//! A Unix listener yields the same stream type as a client connection; a
//! Windows named pipe does not — the server half and client half are distinct
//! types. Both implement `AsyncRead + AsyncWrite`, so code that is generic over
//! those works unchanged, but the aliases below are deliberately separate
//! rather than pretending otherwise.

use std::io;
use std::path::Path;

#[cfg(unix)]
pub use self::unix::{ClientStream, Listener, ServerStream, connect};
#[cfg(windows)]
pub use self::windows::{ClientStream, Listener, ServerStream, connect};

/// Where clients look for the daemon by default.
#[cfg(unix)]
pub const DEFAULT_ENDPOINT: &str = "/run/vpnmgr/sock";
/// Where clients look for the daemon by default.
///
/// `\\.\pipe\` is the only namespace named pipes live in; the path is a name,
/// not a filesystem location, so nothing needs creating around it.
#[cfg(windows)]
pub const DEFAULT_ENDPOINT: &str = r"\\.\pipe\vpnmgr";

/// Human-readable description of who may talk to the daemon, for diagnostics.
#[cfg(unix)]
pub const ACCESS_DESCRIPTION: &str = "members of the vpnmgr group";
#[cfg(windows)]
pub const ACCESS_DESCRIPTION: &str = "administrators and interactive users";

#[cfg(unix)]
mod unix {
    use super::*;
    use tokio::net::{UnixListener, UnixStream};

    pub type ServerStream = UnixStream;
    pub type ClientStream = UnixStream;

    pub struct Listener {
        inner: UnixListener,
    }

    impl Listener {
        pub fn bind(path: &Path) -> io::Result<Self> {
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            // A socket left behind by a crash would block binding.
            if path.exists() {
                std::fs::remove_file(path)?;
            }
            let inner = UnixListener::bind(path)?;
            Ok(Self { inner })
        }

        pub async fn accept(&mut self) -> io::Result<ServerStream> {
            let (stream, _) = self.inner.accept().await?;
            Ok(stream)
        }
    }

    pub async fn connect(path: &Path) -> io::Result<ClientStream> {
        UnixStream::connect(path).await
    }
}

#[cfg(windows)]
mod windows {
    use super::*;
    use std::ffi::c_void;
    use tokio::net::windows::named_pipe::{
        ClientOptions, NamedPipeClient, NamedPipeServer, ServerOptions,
    };

    pub type ServerStream = NamedPipeServer;
    pub type ClientStream = NamedPipeClient;

    /// Who may open the pipe, in SDDL.
    ///
    /// * `D:P` — an explicit DACL, inheritance disabled.
    /// * `(A;;GA;;;SY)` — LocalSystem, full. The daemon itself.
    /// * `(A;;GA;;;BA)` — BUILTIN\Administrators, full.
    /// * `(A;;GRGW;;;IU)` — INTERACTIVE, read and write. This is the Windows
    ///   equivalent of the `vpnmgr` group: someone logged in at this machine
    ///   can run the CLI and the tray without elevation, which is the whole
    ///   reason the daemon holds the privilege instead of the client.
    ///
    /// Deliberately *not* granted: `AU` (Authenticated Users), which would
    /// include remote and service accounts, and `WD` (Everyone).
    const SDDL: &str = "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;IU)";

    pub struct Listener {
        name: String,
        /// The instance waiting for the next client. A named pipe server
        /// handles one connection per instance, so accepting means handing this
        /// one over and creating its replacement.
        next: NamedPipeServer,
    }

    impl Listener {
        pub fn bind(path: &Path) -> io::Result<Self> {
            let name = path.to_string_lossy().into_owned();
            let next = create(&name, true)?;
            Ok(Self { name, next })
        }

        pub async fn accept(&mut self) -> io::Result<ServerStream> {
            self.next.connect().await?;
            let replacement = create(&self.name, false)?;
            Ok(std::mem::replace(&mut self.next, replacement))
        }
    }

    /// Create one pipe instance carrying the DACL above.
    fn create(name: &str, first: bool) -> io::Result<NamedPipeServer> {
        let mut sd = SecurityDescriptor::from_sddl(SDDL)?;
        let mut attrs = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: sd.as_ptr(),
            bInheritHandle: 0,
        };

        // SAFETY: `attrs` outlives the call, and its descriptor pointer is
        // valid for that duration because `sd` is still owned here.
        unsafe {
            ServerOptions::new()
                .first_pipe_instance(first)
                .reject_remote_clients(true)
                .create_with_security_attributes_raw(
                    name,
                    &mut attrs as *mut SECURITY_ATTRIBUTES as *mut c_void,
                )
        }
    }

    pub async fn connect(path: &Path) -> io::Result<ClientStream> {
        ClientOptions::new().open(path.as_os_str())
    }

    // Field names match the Win32 header so they can be checked against the
    // documentation without translation.
    #[repr(C)]
    #[allow(non_snake_case)]
    struct SECURITY_ATTRIBUTES {
        nLength: u32,
        lpSecurityDescriptor: *mut c_void,
        bInheritHandle: i32,
    }

    // The SDDL conversion lives in advapi32, which is not linked by default;
    // LocalFree is in kernel32, which is.
    #[link(name = "advapi32")]
    unsafe extern "system" {
        fn ConvertStringSecurityDescriptorToSecurityDescriptorW(
            string_security_descriptor: *const u16,
            string_sd_revision: u32,
            security_descriptor: *mut *mut c_void,
            security_descriptor_size: *mut u32,
        ) -> i32;
    }

    unsafe extern "system" {
        fn LocalFree(mem: *mut c_void) -> *mut c_void;
    }

    /// A security descriptor built from SDDL, freed on drop.
    struct SecurityDescriptor(*mut c_void);

    impl SecurityDescriptor {
        fn from_sddl(sddl: &str) -> io::Result<Self> {
            let wide: Vec<u16> = sddl.encode_utf16().chain(std::iter::once(0)).collect();
            let mut psd: *mut c_void = std::ptr::null_mut();
            // SAFETY: `wide` is NUL-terminated and lives across the call; the
            // descriptor it allocates is owned by us and released in Drop.
            let ok = unsafe {
                ConvertStringSecurityDescriptorToSecurityDescriptorW(
                    wide.as_ptr(),
                    1, // SDDL_REVISION_1
                    &mut psd,
                    std::ptr::null_mut(),
                )
            };
            if ok == 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(Self(psd))
        }

        fn as_ptr(&mut self) -> *mut c_void {
            self.0
        }
    }

    impl Drop for SecurityDescriptor {
        fn drop(&mut self) {
            if !self.0.is_null() {
                // SAFETY: allocated by the conversion above and not freed yet.
                unsafe { LocalFree(self.0) };
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        /// A malformed descriptor must fail loudly. Silently falling back to a
        /// default DACL would either lock every client out or, worse, open the
        /// daemon up.
        #[test]
        fn invalid_sddl_is_an_error() {
            assert!(SecurityDescriptor::from_sddl("not a descriptor").is_err());
        }

        #[test]
        fn the_shipped_descriptor_parses() {
            assert!(SecurityDescriptor::from_sddl(SDDL).is_ok());
        }
    }
}
