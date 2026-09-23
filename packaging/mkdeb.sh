#!/bin/sh
#
# packaging/mkdeb.sh -- builds marlinlb-xdp, marlinlb-daemon and marlinlb from
# artefacts `make bpf marlind` already produced. Invoked by the root
# Makefile's `deb` target; every value nfpm needs (versions, distro suffix,
# shared-library dependencies) is computed here so packaging/nfpm/*.yaml
# holds no hand-maintained numbers.
#
# Overridable: NFPM (the nfpm binary), DEB_DISTRO (defaults to ID+VERSION_ID
# from /etc/os-release), DEB_REVISION (defaults to 1), DEB_ARCH (defaults to
# `dpkg --print-architecture`).
set -eu

cd "$(dirname "$0")/.."  # repo root; every path below is root-relative

: "${NFPM:=nfpm}"
: "${DEB_REVISION:=1}"
: "${DEB_ARCH:=$(dpkg --print-architecture 2>/dev/null || echo amd64)}"

if [ -z "${DEB_DISTRO:-}" ]; then
    if [ -r /etc/os-release ]; then
        # shellcheck disable=SC1091
        . /etc/os-release
        DEB_DISTRO="${ID}${VERSION_ID}"
    else
        echo "mkdeb.sh: cannot determine DEB_DISTRO -- no /etc/os-release; set DEB_DISTRO explicitly" >&2
        exit 1
    fi
fi

BPF_OBJ=data-plane/build/bpf/marlin.bpf.o
MARLIND_BIN=data-plane/build/marlind/marlind
COMPAT_H=data-plane/include/marlind/compat.h

[ -f "$BPF_OBJ" ] || { echo "mkdeb.sh: $BPF_OBJ missing -- run 'make bpf' first" >&2; exit 1; }
[ -x "$MARLIND_BIN" ] || { echo "mkdeb.sh: $MARLIND_BIN missing or not executable -- run 'make marlind' first" >&2; exit 1; }
command -v "$NFPM" >/dev/null 2>&1 || { echo "mkdeb.sh: \$NFPM ($NFPM) not found -- install nfpm: https://nfpm.goreleaser.com" >&2; exit 1; }
command -v dpkg-shlibdeps >/dev/null 2>&1 || { echo "mkdeb.sh: dpkg-shlibdeps not found -- install dpkg-dev" >&2; exit 1; }

BUILD_DIR=build/deb
rm -rf "$BUILD_DIR"
mkdir -p "$BUILD_DIR/copyright"

# --- version mapping: SemVer (docs/design/29-versions.md) -> Debian policy -
# The first '-' becomes '~', so a pre-release sorts before its release the
# same way SemVer orders it (SemVer §11.3, Debian policy §5.6.12); a trailing
# '+build' is dropped, since Debian's own '+'/'~' ordering does not match
# SemVer's "build metadata is ignored for ordering" rule and no VERSION file
# in this tree carries one today.
semver_to_deb() {
    printf '%s' "$1" | sed -e 's/-/~/' -e 's/+.*//'
}

BPF_SEMVER=$(cat data-plane/bpf/VERSION)
MARLIND_SEMVER=$(cat data-plane/marlind/VERSION)
META_SEMVER=$(cat packaging/VERSION)

REV_SUFFIX="-${DEB_REVISION}~${DEB_DISTRO}"
MARLINLB_XDP_VERSION="$(semver_to_deb "$BPF_SEMVER")${REV_SUFFIX}"
MARLINLB_DAEMON_VERSION="$(semver_to_deb "$MARLIND_SEMVER")${REV_SUFFIX}"
MARLINLB_META_VERSION="$(semver_to_deb "$META_SEMVER")${REV_SUFFIX}"

# marlind's own floor on marlin.bpf.o (data-plane/include/marlind/compat.h) is
# read, not re-decided here, so there is exactly one copy of the number --
# apt then refuses the same marlinlb-xdp/marlinlb-daemon pairs `--attach`
# would refuse with exit 5 (docs/DEPLOYMENT.md §1.2).
FLOOR_SEMVER=$(sed -n 's/^#define MARLIND_MIN_BPF_VERSION *"\(.*\)".*/\1/p' "$COMPAT_H")
[ -n "$FLOOR_SEMVER" ] || { echo "mkdeb.sh: could not read MARLIND_MIN_BPF_VERSION from $COMPAT_H" >&2; exit 1; }
MARLINLB_XDP_FLOOR_VERSION=$(semver_to_deb "$FLOOR_SEMVER")

export DEB_ARCH MARLINLB_XDP_VERSION MARLINLB_DAEMON_VERSION MARLINLB_META_VERSION MARLINLB_XDP_FLOOR_VERSION

# --- shared-library dependencies: computed, not hand-maintained ------------
# dpkg-shlibdeps insists on a debian/control next to the binary it inspects;
# this one is thrown away right after -- nothing here reads its content, it
# exists only so the tool has something to open.
SHLIBS_DIR="$BUILD_DIR/shlibs"
mkdir -p "$SHLIBS_DIR/debian"
cat > "$SHLIBS_DIR/debian/control" <<'EOF'
Source: marlinlb
Package: marlinlb-daemon
Architecture: any
EOF
cp "$MARLIND_BIN" "$SHLIBS_DIR/marlind"
SHLIBS_DEPENDS=$(cd "$SHLIBS_DIR" && dpkg-shlibdeps -O ./marlind | sed -n 's/^shlibs:Depends=//p')
[ -n "$SHLIBS_DEPENDS" ] || { echo "mkdeb.sh: dpkg-shlibdeps produced no shlibs:Depends for $MARLIND_BIN" >&2; exit 1; }
export SHLIBS_DEPENDS

# --- copyright files --------------------------------------------------------
# GPL-2.0-only OR BSD-2-Clause is data-plane/'s own dual license
# (data-plane/LICENSE, data-plane/LICENSE-BSD-2-Clause); marlinlb-daemon also
# links the vendored tomlc17 (MIT, vendor/README.md) into marlind.
cat data-plane/LICENSE data-plane/LICENSE-BSD-2-Clause > "$BUILD_DIR/copyright/marlinlb-xdp"
cat data-plane/LICENSE data-plane/LICENSE-BSD-2-Clause data-plane/vendor/tomlc17/LICENSE > "$BUILD_DIR/copyright/marlinlb-daemon"
cp LICENSE "$BUILD_DIR/copyright/marlinlb"

# --- build ------------------------------------------------------------------
# nfpm's own filename convention embeds the Debian version verbatim,
# '~' included; GitHub rewrites '~' to '.' in release asset filenames
# (though not in an artifact's own content), so the on-disk name here swaps
# it for '+' instead -- what ships inside each package is unaffected.
build_pkg() {
    pkg="$1"
    version="$2"
    file_version=$(printf '%s' "$version" | tr '~' '+')
    target="$BUILD_DIR/${pkg}_${file_version}_${DEB_DISTRO}_${DEB_ARCH}.deb"

    echo "packaging $pkg $version ($DEB_DISTRO/$DEB_ARCH)"
    "$NFPM" package --config "packaging/nfpm/${pkg}.yaml" --packager deb --target "$target"
}

build_pkg marlinlb-xdp "$MARLINLB_XDP_VERSION"
build_pkg marlinlb-daemon "$MARLINLB_DAEMON_VERSION"
build_pkg marlinlb "$MARLINLB_META_VERSION"

rm -rf "$SHLIBS_DIR"

echo
echo "built:"
ls -1 "$BUILD_DIR"/*.deb
