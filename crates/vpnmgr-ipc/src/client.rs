//! Client side of the daemon protocol.

use std::path::{Path, PathBuf};

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;

use crate::{Error, Request, Response, Result};

/// A connection to `vpnmgrd`.
pub struct Client {
    stream: BufReader<UnixStream>,
    path: PathBuf,
}

impl Client {
    pub async fn connect(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref().to_owned();
        let stream = UnixStream::connect(&path).await.map_err(|source| {
            // Permission denied is by far the most common failure and has a
            // specific fix, so it gets its own message.
            if source.kind() == std::io::ErrorKind::PermissionDenied {
                Error::PermissionDenied { path: path.clone() }
            } else {
                Error::Connect {
                    path: path.clone(),
                    source,
                }
            }
        })?;
        Ok(Self {
            stream: BufReader::new(stream),
            path,
        })
    }

    /// Send one request and await its reply.
    pub async fn send(&mut self, request: &Request) -> Result<Response> {
        let mut line = serde_json::to_string(request)?;
        line.push('\n');
        self.stream.get_mut().write_all(line.as_bytes()).await?;
        self.stream.get_mut().flush().await?;

        let mut reply = String::new();
        let n = self.stream.read_line(&mut reply).await?;
        if n == 0 {
            return Err(Error::Closed);
        }
        Ok(serde_json::from_str(reply.trim_end())?)
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

/// Connect, send one request, and return the reply.
pub async fn request(path: impl AsRef<Path>, request: &Request) -> Result<Response> {
    Client::connect(path).await?.send(request).await
}
