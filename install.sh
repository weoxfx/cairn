#!/bin/sh
set -eu

repo="weoxfx/cairn"
version="${CAIRN_VERSION:-}"
install_dir="${CAIRN_INSTALL_DIR:-${HOME:?HOME is not set}/.local/bin}"

need() {
    command -v "$1" >/dev/null 2>&1 || {
        printf 'error: %s is required\n' "$1" >&2
        exit 1
    }
}

need curl
need tar
need uname
need install

case "$(uname -s):$(uname -m)" in
    Linux:x86_64|Linux:amd64)
        target="x86_64-unknown-linux-musl"
        ;;
    Darwin:arm64|Darwin:aarch64)
        target="aarch64-apple-darwin"
        ;;
    Darwin:x86_64|Darwin:amd64)
        target="x86_64-apple-darwin"
        ;;
    *)
        printf 'No prebuilt binary for %s/%s. Build from source instead:\n' \
            "$(uname -s)" "$(uname -m)" >&2
        printf '  https://github.com/%s#build-from-source\n' "$repo" >&2
        exit 1
        ;;
esac

if [ -z "$version" ]; then
    latest="$(curl -fsSL --proto '=https' -o /dev/null -w '%{url_effective}' \
        "https://github.com/$repo/releases/latest")"
    version="${latest##*/}"
fi

case "$version" in
    v*)
        ;;
    latest|"")
        printf 'error: could not determine the latest Cairn release\n' >&2
        exit 1
        ;;
    *)
        version="v$version"
        ;;
esac

archive="cairn-${version}-${target}.tar.gz"
base="https://github.com/$repo/releases/download/$version"
tmp="$(mktemp -d "${TMPDIR:-/tmp}/cairn-install.XXXXXX")"
trap 'rm -rf "$tmp"' 0

printf 'Downloading %s\n' "$archive"
curl -fsSL --proto '=https' --tlsv1.2 "$base/$archive" -o "$tmp/$archive"
curl -fsSL --proto '=https' --tlsv1.2 "$base/$archive.sha256" -o "$tmp/$archive.sha256"

if command -v sha256sum >/dev/null 2>&1; then
    (cd "$tmp" && sha256sum -c "$archive.sha256")
else
    (cd "$tmp" && shasum -a 256 -c "$archive.sha256")
fi

tar -xzf "$tmp/$archive" -C "$tmp"
source="$tmp/cairn-${version}-${target}/cairn"
if [ ! -f "$source" ]; then
    printf 'error: archive did not contain the expected binary\n' >&2
    exit 1
fi

mkdir -p "$install_dir"
install -m 755 "$source" "$install_dir/cairn"
printf 'Installed cairn to %s\n' "$install_dir/cairn"

case ":$PATH:" in
    *":$install_dir:"*)
        printf 'Run: cairn\n'
        ;;
    *)
        printf 'To run it now:\n  export PATH="%s:$PATH"\n' "$install_dir"
        printf 'To keep it, add that line to ~/.profile (Linux) or ~/.zshrc (macOS), then open a new terminal.\n'
        ;;
esac
