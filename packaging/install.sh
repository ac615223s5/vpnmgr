#!/usr/bin/env bash
# Install or update vpnmgr.
#
#     sudo ./packaging/install.sh <path-to-airvpn.conf>   # first install
#     sudo ./packaging/install.sh                         # update in place
#
# Works from three places, and figures out which on its own:
#   - a git checkout, where it builds from source
#   - an unpacked release tarball, where the binaries are already next to it
#   - /usr/local/bin, once installed, where `vpnmgr-update` fetches a release
#     and re-runs this from the unpacked copy
#
# Installs the binaries, extracts the key material into root-owned 0600 files,
# writes /etc/vpnmgr/config.toml, and enables the daemon. On an update the
# config and keys are left exactly as they are.
set -euo pipefail

CONF="${1:-}"
PREFIX="${PREFIX:-/usr/local}"
CONFDIR="${CONFDIR:-/etc/vpnmgr}"
GROUP="vpnmgr"

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# In a checkout this script lives in packaging/ and the binaries are built into
# target/release. In a release tarball it sits at the root with bin/ and
# packaging/ beside it. Everything below is resolved from these two, so neither
# layout depends on the caller's working directory.
if [[ "$(basename "$HERE")" == "packaging" ]]; then
    ROOT="$(dirname "$HERE")"
    DATA="$HERE"
    BINDIR="${BINDIR:-$ROOT/target/release}"
    SOURCE_TREE=1
else
    ROOT="$HERE"
    DATA="$HERE/packaging"
    BINDIR="${BINDIR:-$HERE/bin}"
    SOURCE_TREE=0
fi

if [[ $EUID -ne 0 ]]; then
    echo "must be run as root" >&2
    exit 1
fi

# An update is any run where the daemon is already configured. The .conf is
# only needed to extract key material, and on an update that has already
# happened -- demanding it again would mean keeping the file around forever.
UPDATE=0
if [[ -f "$CONFDIR/config.toml" && -f "$CONFDIR/wg.key" ]]; then
    UPDATE=1
fi

if [[ $UPDATE -eq 0 && ( -z "$CONF" || ! -f "$CONF" ) ]]; then
    echo "usage: sudo $0 <path-to-airvpn.conf>" >&2
    echo "download one from AirVPN's Config Generator (WireGuard, port 1637)" >&2
    exit 1
fi

if [[ $UPDATE -eq 1 ]]; then
    echo "==> updating an existing install (config and keys kept)"
fi

if [[ ! -x "$BINDIR/vpnmgrd" ]]; then
    if [[ $SOURCE_TREE -eq 0 ]]; then
        echo "no binaries in $BINDIR; this does not look like a release tarball" >&2
        exit 1
    fi
    echo "==> building"
    # rustup installs cargo into the *user's* ~/.cargo/bin, which is not on
    # root's PATH, so a plain `cargo build` here fails under sudo. Build as the
    # invoking user when we can.
    if command -v cargo >/dev/null 2>&1; then
        (cd "$ROOT" && cargo build --release)
    elif [[ -n "${SUDO_USER:-}" ]] && sudo -u "$SUDO_USER" bash -lc 'command -v cargo' >/dev/null 2>&1; then
        echo "    cargo is not on root's PATH; building as $SUDO_USER"
        sudo -u "$SUDO_USER" bash -lc "cd '$ROOT' && cargo build --release"
    else
        echo "cargo not found, and $BINDIR has no prebuilt binaries." >&2
        echo "Build them first, as your normal user:" >&2
        echo "    cargo build --release" >&2
        exit 1
    fi
fi

echo "==> installing binaries into $PREFIX/bin"
# The daemon is running during an update, and writing over a busy executable
# fails with ETXTBSY. install(1) replaces by rename, which the running process
# survives -- it keeps the old inode until it restarts below.
install -m 0755 "$BINDIR/vpnmgrd" "$PREFIX/bin/vpnmgrd"
install -m 0755 "$BINDIR/vpnmgr" "$PREFIX/bin/vpnmgr"
install -m 0755 "$BINDIR/vpnmgr-tray" "$PREFIX/bin/vpnmgr-tray"

# Ship the updater itself, so future updates are one command with no checkout.
if [[ -f "$DATA/vpnmgr-update.sh" ]]; then
    echo "==> installing the updater as $PREFIX/bin/vpnmgr-update"
    install -m 0755 "$DATA/vpnmgr-update.sh" "$PREFIX/bin/vpnmgr-update"
fi

echo "==> installing the applications-menu entry"
install -d -m 0755 /usr/share/applications
install -m 0644 "$DATA/vpnmgr.desktop" /usr/share/applications/vpnmgr.desktop
# Refresh the menu cache so the entry shows up without a re-login.
update-desktop-database /usr/share/applications 2>/dev/null || true

echo "==> installing the tray autostart entry"
install -d -m 0755 /etc/xdg/autostart
install -m 0644 "$DATA/vpnmgr-tray.desktop" /etc/xdg/autostart/vpnmgr-tray.desktop

echo "==> creating group $GROUP"
groupadd -f "$GROUP"

if [[ $UPDATE -eq 0 ]]; then
    echo "==> extracting key material into $CONFDIR"
    install -d -m 0750 "$CONFDIR"

    # Pull the secrets out of the .conf without ever putting them on a command
    # line, where they would be visible in ps output.
    extract() {
        sed -n "s/^[[:space:]]*$1[[:space:]]*=[[:space:]]*\([A-Za-z0-9+/=]\+\).*/\1/Ip" "$CONF" | head -1
    }

    PRIVATE_KEY="$(extract PrivateKey)"
    PRESHARED_KEY="$(extract PresharedKey)"

    if [[ -z "$PRIVATE_KEY" ]]; then
        echo "no PrivateKey found in $CONF" >&2
        exit 1
    fi

    umask 077
    printf '%s' "$PRIVATE_KEY" > "$CONFDIR/wg.key"
    chmod 0600 "$CONFDIR/wg.key"
    if [[ -n "$PRESHARED_KEY" ]]; then
        printf '%s' "$PRESHARED_KEY" > "$CONFDIR/wg.psk"
        chmod 0600 "$CONFDIR/wg.psk"
    fi

    echo "==> writing $CONFDIR/config.toml"
    "$PREFIX/bin/vpnmgr" import "$CONF" --dir "$CONFDIR" \
        | sed -n '/^\[provider/,$p' > "$CONFDIR/config.toml"
    chmod 0640 "$CONFDIR/config.toml"
fi

echo "==> installing systemd unit"
install -m 0644 "$DATA/vpnmgrd.service" /etc/systemd/system/vpnmgrd.service
systemctl daemon-reload

if [[ $UPDATE -eq 1 ]]; then
    # restart, not reload: new binaries only take effect on exec. The tunnel
    # comes down with the daemon and is not automatically re-established, which
    # is the safe direction -- reconnecting silently under a new build would be
    # worse than a connection the user re-makes deliberately.
    WAS_CONNECTED=0
    if "$PREFIX/bin/vpnmgr" status 2>/dev/null | head -1 | grep -q '^connected'; then
        WAS_CONNECTED=1
    fi
    echo "==> restarting vpnmgrd"
    systemctl restart vpnmgrd
else
    systemctl enable --now vpnmgrd
fi

VERSION="$("$PREFIX/bin/vpnmgr" --version 2>/dev/null || echo "vpnmgr ?")"

echo
if [[ $UPDATE -eq 1 ]]; then
    echo "Updated to $VERSION."
    if [[ "${WAS_CONNECTED:-0}" -eq 1 ]]; then
        echo
        echo "The tunnel came down with the daemon. Reconnect when you want it:"
        echo "    vpnmgr connect"
    fi
    echo
    echo "The tray is still running the previous build; quit and relaunch it"
    echo "from the applications menu to pick this one up."
    exit 0
fi

echo "Installed $VERSION. Add yourself to the '$GROUP' group, then log out and back in:"
echo "    sudo usermod -aG $GROUP \$USER"
echo
echo "The log out matters: group membership is fixed at login, so until then"
echo "every client -- including the tray -- will be refused by the socket."
echo
echo "Then try:"
echo "    vpnmgr status"
echo "    vpnmgr test --country ca"
echo "    vpnmgr connect"
echo
echo "The tray starts automatically at next login, and is in your applications"
echo "menu as \"VPN Manager\". Launching it while it is already running just"
echo "points you back at the existing tray icon rather than adding a second."
echo
echo "Later, to update:"
echo "    sudo vpnmgr-update"
