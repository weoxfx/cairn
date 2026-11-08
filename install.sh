#!/bin/sh
set -eu

repo="weoxfx/cairn"
version="${CAIRN_VERSION:-}"
install_dir="${CAIRN_INSTALL_DIR:-}"
source_ref="${CAIRN_SOURCE_REF:-master}"
from_source="${CAIRN_FROM_SOURCE:-0}"

usage() {
    cat <<EOF
Install Cairn.

Usage:
  install.sh [--from-source]

Options:
  --from-source  Build from source instead of downloading a release.

Environment:
  CAIRN_VERSION      Release tag to install, for example v0.2.0.
  CAIRN_INSTALL_DIR  Directory for the binary (default: ~/.local/bin).
  CAIRN_SOURCE_REF   Source branch/tag for --from-source (default: master).
  CAIRN_FROM_SOURCE  Set to 1 for a source build.
EOF
}

case "${1:-}" in
    --from-source)
        from_source=1
        ;;
    --help|-h)
        usage
        exit 0
        ;;
    "")
        ;;
    *)
        printf 'error: unknown option: %s\n\n' "$1" >&2
        usage >&2
        exit 1
        ;;
esac

need() {
    command -v "$1" >/dev/null 2>&1 || {
        printf 'error: %s is required\n' "$1" >&2
        exit 1
    }
}

need curl
need tar
need uname
need mktemp

os="$(uname -s)"
arch="$(uname -m)"
termux=0
case "${PREFIX:-}" in
    *com.termux*) termux=1 ;;
esac

if [ -z "$install_dir" ]; then
    if [ "$termux" -eq 1 ]; then
        install_dir="${PREFIX:?PREFIX is not set}/bin"
    else
        install_dir="${HOME:?HOME is not set}/.local/bin"
    fi
fi

target=""
case "$os:$arch" in
    Linux:x86_64|Linux:amd64)
        target="x86_64-unknown-linux-musl"
        ;;
    Darwin:arm64|Darwin:aarch64)
        target="aarch64-apple-darwin"
        ;;
    Darwin:x86_64|Darwin:amd64)
        target="x86_64-apple-darwin"
        ;;
esac

install_binary() {
    mkdir -p "$install_dir"
    if command -v install >/dev/null 2>&1; then
        install -m 755 "$1" "$install_dir/cairn"
    else
        cp "$1" "$install_dir/cairn"
        chmod 755 "$install_dir/cairn"
    fi
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
}

missing_build_tools() {
    if [ "$termux" -eq 1 ]; then
        printf 'Cairn has no prebuilt Android/Termux binary. Install Rust, then run this again:\n' >&2
        printf '  pkg install rust\n' >&2
        printf '  curl -fsSL https://raw.githubusercontent.com/%s/master/install.sh | sh -s -- --from-source\n' "$repo" >&2
    else
        printf 'Cairn has no prebuilt binary for %s/%s, and no published release was found.\n' "$os" "$arch" >&2
        printf 'Install Rust and the platform build tools, then run this again:\n' >&2
        printf '  https://rustup.rs\n' >&2
        printf '  curl -fsSL https://raw.githubusercontent.com/%s/master/install.sh | sh -s -- --from-source\n' "$repo" >&2
    fi
    exit 1
}

source_build() {
    need cargo

    archive="cairn-${source_ref}.tar.gz"
    src_root="$tmp/src"
    mkdir -p "$src_root"
    printf 'No release is available for this platform; building from source (%s)\n' "$source_ref"
    curl -fsSL --proto '=https' --tlsv1.2 \
        "https://github.com/$repo/archive/$source_ref.tar.gz" \
        -o "$tmp/$archive"
    tar -xzf "$tmp/$archive" -C "$src_root"

    source_dir=""
    for cargo_toml in "$src_root"/*/Cargo.toml; do
        [ -f "$cargo_toml" ] || continue
        source_dir="${cargo_toml%/Cargo.toml}"
        break
    done
    if [ -z "$source_dir" ]; then
        printf 'error: source archive did not contain Cargo.toml\n' >&2
        exit 1
    fi

    (cd "$source_dir" && cargo build --locked --release)
    built="$source_dir/target/release/cairn"
    if [ ! -f "$built" ]; then
        printf 'error: source build did not produce the cairn binary\n' >&2
        exit 1
    fi
    install_binary "$built"
}

tmp="$(mktemp -d "${TMPDIR:-/tmp}/cairn-install.XXXXXX")"
trap 'rm -rf "$tmp"' 0

if [ "$from_source" = 1 ]; then
    source_build
    exit 0
fi

if [ -z "$version" ]; then
    latest="$(curl -fsSL --proto '=https' -o /dev/null -w '%{url_effective}' \
        "https://github.com/$repo/releases/latest" 2>/dev/null || true)"
    case "$latest" in
        */releases/tag/*)
            version="${latest##*/}"
            ;;
        *)
            printf 'No published Cairn release found.\n' >&2
            if command -v cargo >/dev/null 2>&1; then
                source_build
                exit 0
            fi
            missing_build_tools
            ;;
    esac
else
    case "$version" in
        v*) ;;
        *) version="v$version" ;;
    esac
fi

if [ -z "$target" ]; then
    if command -v cargo >/dev/null 2>&1; then
        source_build
        exit 0
    fi
    missing_build_tools
fi

archive="cairn-${version}-${target}.tar.gz"
base="https://github.com/$repo/releases/download/$version"

printf 'Downloading %s\n' "$archive"
curl -fsSL --proto '=https' --tlsv1.2 "$base/$archive" -o "$tmp/$archive"
curl -fsSL --proto '=https' --tlsv1.2 "$base/$archive.sha256" -o "$tmp/$archive.sha256"

if command -v sha256sum >/dev/null 2>&1; then
    (cd "$tmp" && sha256sum -c "$archive.sha256")
elif command -v shasum >/dev/null 2>&1; then
    (cd "$tmp" && shasum -a 256 -c "$archive.sha256")
else
    printf 'error: sha256sum or shasum is required to verify the download\n' >&2
    exit 1
fi

tar -xzf "$tmp/$archive" -C "$tmp"
source="$tmp/cairn-${version}-${target}/cairn"
if [ ! -f "$source" ]; then
    printf 'error: archive did not contain the expected binary\n' >&2
    exit 1
fi

install_binary "$source"
