#!/usr/bin/env bash
# Install or update vpnmgr from a GitHub release.
#
#     curl -fsSL https://raw.githubusercontent.com/ac615223s5/vpnmgr/master/packaging/vpnmgr-update.sh \
#       | sudo bash -s -- --conf ~/AirVPN.conf      # first install
#     sudo vpnmgr-update                            # update, once installed
#
# Options:
#   --conf PATH     AirVPN .conf, required only for a first install
#   --version TAG   install a specific release instead of the latest
#   --check         report what is available and exit without changing anything
#   --force         reinstall even when the installed version already matches
#
# Downloads the release tarball, checks it against the published SHA256, and
# runs the install.sh inside it. Nothing is installed from an archive whose
# checksum did not match.
set -euo pipefail

REPO="${VPNMGR_REPO:-ac615223s5/vpnmgr}"
PREFIX="${PREFIX:-/usr/local}"
API="https://api.github.com/repos/$REPO"

CONF=""
WANT_VERSION=""
CHECK_ONLY=0
FORCE=0

while [[ $# -gt 0 ]]; do
    case "$1" in
        --conf)    CONF="${2:-}"; shift 2 ;;
        --version) WANT_VERSION="${2:-}"; shift 2 ;;
        --check)   CHECK_ONLY=1; shift ;;
        --force)   FORCE=1; shift ;;
        -h|--help) sed -n '2,17p' "$0" | sed 's/^# \?//'; exit 0 ;;
        *) echo "unknown option: $1" >&2; exit 2 ;;
    esac
done

need() {
    command -v "$1" >/dev/null 2>&1 || { echo "$1 is required but not installed" >&2; exit 1; }
}
need curl
need tar
need sha256sum

installed_version() {
    if command -v vpnmgr >/dev/null 2>&1; then
        # "vpnmgr 0.1.0" -> "v0.1.0", to compare against the release tag.
        local v
        v="$(vpnmgr --version 2>/dev/null | awk '{print $2}')"
        [[ -n "$v" ]] && printf 'v%s' "$v"
    fi
}

# The tag of the newest release. Parsed out of the API response with sed rather
# than jq, which is not installed by default anywhere this is likely to run.
latest_version() {
    curl -fsSL "$API/releases/latest" \
        | sed -n 's/.*"tag_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' \
        | head -1
}

CURRENT="$(installed_version || true)"
if [[ -n "$WANT_VERSION" ]]; then
    TARGET="$WANT_VERSION"
else
    TARGET="$(latest_version || true)"
    if [[ -z "$TARGET" ]]; then
        echo "could not determine the latest release of $REPO" >&2
        echo "check the network, or pass --version vX.Y.Z" >&2
        exit 1
    fi
fi

echo "installed: ${CURRENT:-none}"
echo "available: $TARGET"

if [[ $CHECK_ONLY -eq 1 ]]; then
    if [[ "$CURRENT" == "$TARGET" ]]; then
        echo "up to date"
    else
        echo "run 'sudo vpnmgr-update' to install $TARGET"
    fi
    exit 0
fi

if [[ "$CURRENT" == "$TARGET" && $FORCE -eq 0 ]]; then
    echo "already up to date; --force to reinstall anyway"
    exit 0
fi

# Only the install itself needs root. Checking a version does not, and asking
# for a password to answer a question is a good way to train people to type it
# without reading.
if [[ $EUID -ne 0 ]]; then
    echo "installing needs root: re-run with sudo" >&2
    exit 1
fi

ARCH="$(uname -m)"
case "$ARCH" in
    x86_64)  TRIPLE="x86_64-unknown-linux-gnu" ;;
    aarch64) TRIPLE="aarch64-unknown-linux-gnu" ;;
    *) echo "no release build for $ARCH; build from source instead" >&2; exit 1 ;;
esac

STEM="vpnmgr-${TARGET}-${TRIPLE}"
BASE="https://github.com/$REPO/releases/download/$TARGET"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

echo "==> downloading $STEM.tar.gz"
if ! curl -fsSL --retry 3 -o "$TMP/$STEM.tar.gz" "$BASE/$STEM.tar.gz"; then
    echo "no such asset: $BASE/$STEM.tar.gz" >&2
    echo "the release may not publish a build for $TRIPLE" >&2
    exit 1
fi
curl -fsSL --retry 3 -o "$TMP/$STEM.tar.gz.sha256" "$BASE/$STEM.tar.gz.sha256"

echo "==> verifying the checksum"
# Compare digests directly rather than trusting the filename inside the
# checksum file to line up with what was downloaded.
want="$(awk '{print $1}' "$TMP/$STEM.tar.gz.sha256")"
got="$(sha256sum "$TMP/$STEM.tar.gz" | awk '{print $1}')"
if [[ -z "$want" || "$want" != "$got" ]]; then
    echo "checksum mismatch -- refusing to install" >&2
    echo "  expected: ${want:-<empty>}" >&2
    echo "  actual  : $got" >&2
    exit 1
fi
echo "    $got"

tar -xzf "$TMP/$STEM.tar.gz" -C "$TMP"
DIR="$TMP/$STEM"
if [[ ! -x "$DIR/install.sh" ]]; then
    echo "the archive has no install.sh at $DIR; refusing to guess" >&2
    exit 1
fi

# Hand off. install.sh decides for itself whether this is a first install or an
# update, so the .conf is passed through only when one was given.
if [[ -n "$CONF" ]]; then
    exec "$DIR/install.sh" "$CONF"
else
    exec "$DIR/install.sh"
fi
