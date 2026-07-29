#!/usr/bin/env bash
# Install vpnmgr. Run as root from the repository root:
#     sudo ./packaging/install.sh <path-to-airvpn.conf>
#
# Installs the binaries, extracts the key material into root-owned 0600 files,
# writes /etc/vpnmgr/config.toml, and enables the daemon.
set -euo pipefail

CONF="${1:-}"
PREFIX="${PREFIX:-/usr/local}"
CONFDIR="${CONFDIR:-/etc/vpnmgr}"
GROUP="vpnmgr"

if [[ $EUID -ne 0 ]]; then
    echo "must be run as root" >&2
    exit 1
fi
if [[ -z "$CONF" || ! -f "$CONF" ]]; then
    echo "usage: sudo $0 <path-to-airvpn.conf>" >&2
    echo "download one from AirVPN's Config Generator (WireGuard, port 1637)" >&2
    exit 1
fi

echo "==> building"
cargo build --release

echo "==> installing binaries into $PREFIX/bin"
install -m 0755 target/release/vpnmgrd "$PREFIX/bin/vpnmgrd"
install -m 0755 target/release/vpnmgr "$PREFIX/bin/vpnmgr"

echo "==> creating group $GROUP"
groupadd -f "$GROUP"

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
if [[ -f "$CONFDIR/config.toml" ]]; then
    echo "    (existing config.toml kept; remove it to regenerate)"
else
    "$PREFIX/bin/vpnmgr" import "$CONF" --dir "$CONFDIR" \
        | sed -n '/^\[provider/,$p' > "$CONFDIR/config.toml"
    chmod 0640 "$CONFDIR/config.toml"
fi

echo "==> installing systemd unit"
install -m 0644 packaging/vpnmgrd.service /etc/systemd/system/vpnmgrd.service
systemctl daemon-reload
systemctl enable --now vpnmgrd

echo
echo "Done. Add yourself to the '$GROUP' group, then log out and back in:"
echo "    sudo usermod -aG $GROUP \$USER"
echo
echo "Then try:"
echo "    vpnmgr status"
echo "    vpnmgr test --country ca"
echo "    vpnmgr connect"
