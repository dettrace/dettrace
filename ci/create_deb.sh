#!/bin/sh

# Creates a Debian package.

set -e

NAME=$1
VERSION=$2

PKGNAME=${NAME}_${VERSION}

cleanup() {
    # Delete the package staging directory
    rm -rf -- "${PKGNAME}"
}

cleanup

trap cleanup EXIT

mkdir -p -- "${PKGNAME}/usr/bin"
mkdir -p -- "${PKGNAME}/usr/share/${NAME}/bin"

cp -a bin/${NAME}-static "${PKGNAME}/usr/share/${NAME}/bin/${NAME}"
ln -sf "../share/${NAME}/bin/${NAME}" "${PKGNAME}/usr/bin/${NAME}"
cp -a root "${PKGNAME}/usr/share/${NAME}/root"
find "${PKGNAME}/usr/share/${NAME}/root" -type f -name .gitignore -exec rm '{}' \+
cp -a examples "${PKGNAME}/usr/share/${NAME}/"
mkdir -- "${PKGNAME}/DEBIAN"

cat > "${PKGNAME}/DEBIAN/control" << EOF
Package: ${NAME}
Version: ${VERSION}
Section: base
Priority: optional
Architecture: amd64
Depends:
Maintainer: Jason White
Description: ${NAME}
 Runs programs deterministically using ptrace.
EOF

fakeroot -- dpkg-deb --build "${PKGNAME}"
