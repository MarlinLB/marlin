#!/bin/sh
#
# .github/actions/setup-toolchain/install.sh -- the data-plane build/style
# toolchain, one script so every distro job and the style job install the
# same versions. Runs as root inside a bare distro container (no sudo).
# SETUP_NFPM=true additionally installs the pinned nfpm release.
#
# Runnable outside CI too, e.g.:
#   docker run --rm -v "$PWD":/w -w /w ubuntu:24.04 \
#       .github/actions/setup-toolchain/install.sh
set -eu

BPFTOOL_VERSION=7.7.0
BPFTOOL_SHA256=09150596f09356b0ff632dd7f9856e0ea86bf96b269e9bc94278d9a9432a268c
NFPM_VERSION=2.47.0
NFPM_SHA256=0660ca602b2d2d2ae4781a06c692b3eeb9d437ffea05b831d76e41f4a3188783

: "${SETUP_NFPM:=false}"

arch=$(uname -m)
if [ "$arch" != "x86_64" ]; then
    echo "install.sh: only x86_64 is supported today (got $arch) -- arm64 is a documented extension point (docs/PHASES.md)" >&2
    exit 1
fi

if [ -r /etc/os-release ]; then
    # shellcheck disable=SC1091
    . /etc/os-release
else
    echo "install.sh: no /etc/os-release -- unsupported image" >&2
    exit 1
fi

# Ubuntu and Debian share package names for everything below; add a case
# branch here, not a second script, the day that stops holding (Debian 12 is
# meant to be one matrix row plus, at most, one branch here).
case "$ID" in
    ubuntu | debian)
        export DEBIAN_FRONTEND=noninteractive
        apt-get update -qq
        apt-get install -y -qq --no-install-recommends \
            ca-certificates curl git make \
            clang lld llvm binutils \
            clang-format clang-tidy \
            libbpf-dev libelf-dev zlib1g-dev \
            dpkg-dev
        ;;
    *)
        echo "install.sh: unsupported distro '$ID' -- add a case here" >&2
        exit 1
        ;;
esac

tmpdir=$(mktemp -d)
trap 'rm -rf "$tmpdir"' EXIT

# bpftool is a build-host requirement only, for `bpftool gen object`
# (docs/DEPLOYMENT.md §1.1) -- no distro package matches a container's
# kernel, and none needs to: gen object touches no running kernel state
# (data-plane/mk/toolchain.mk probe 5). A fixed upstream release is pinned
# instead, the same shape as nfpm below.
curl -fsSL -o "$tmpdir/bpftool.tar.gz" \
    "https://github.com/libbpf/bpftool/releases/download/v${BPFTOOL_VERSION}/bpftool-v${BPFTOOL_VERSION}-amd64.tar.gz"
echo "${BPFTOOL_SHA256}  $tmpdir/bpftool.tar.gz" | sha256sum -c -
tar -xzf "$tmpdir/bpftool.tar.gz" -C "$tmpdir"
install -m 0755 "$tmpdir/bpftool" /usr/local/sbin/bpftool

if [ "$SETUP_NFPM" = "true" ]; then
    curl -fsSL -o "$tmpdir/nfpm.tar.gz" \
        "https://github.com/goreleaser/nfpm/releases/download/v${NFPM_VERSION}/nfpm_${NFPM_VERSION}_Linux_x86_64.tar.gz"
    echo "${NFPM_SHA256}  $tmpdir/nfpm.tar.gz" | sha256sum -c -
    tar -xzf "$tmpdir/nfpm.tar.gz" -C "$tmpdir" nfpm
    install -m 0755 "$tmpdir/nfpm" /usr/local/bin/nfpm
fi
