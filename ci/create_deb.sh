#!/bin/sh

# Creates a Debian package.

set -e

NAME=$1
VERSION=$2

PKGNAME=${NAME}_${VERSION}

rm -rf -- "${PKGNAME}"

mkdir -p -- "${PKGNAME}/usr/bin"
mkdir -p -- "${PKGNAME}/usr/share/cloudseal/bin"

cp -a bin/dettrace-static "${PKGNAME}/usr/share/cloudseal/bin/cloudseal"
ln -sf "../share/cloudseal/bin/cloudseal" "${PKGNAME}/usr/bin/cloudseal"
cp -a root "${PKGNAME}/usr/share/cloudseal/root"
find "${PKGNAME}/usr/share/cloudseal/root" -type f -name .gitignore -exec rm '{}' \+
cp -a initramfs.cpio "${PKGNAME}/usr/share/cloudseal/"
cp -a package/examples "${PKGNAME}/usr/share/cloudseal/"
mkdir -- "${PKGNAME}/DEBIAN"

cat > "${PKGNAME}/DEBIAN/control" << EOF
Package: ${NAME}
Version: ${VERSION}
Section: base
Priority: optional
Architecture: amd64
Depends:
Maintainer: Jason White <jw@cloudseal.io>
Description: Cloudseal Alpha
 Runs programs deterministically using ptrace.
EOF

fakeroot -- dpkg-deb --build "${PKGNAME}"
