#!/bin/bash -ex

cd /home/
rm *.time || true

for package in xdelta;do # sl whiff xdelta3 xdg-utils xdiskusage; do
    cd $package/build/
    # for i in 1 2 3; do
        /usr/bin/time --append -o ../../$package.time \
        -f "build time, real %e, user %U, sys %S" \
        /dettrace/bin/dettrace --in-schroot --chroot / dpkg-buildpackage -uc -us -b
    # done
    cd ../../
done

cat *.time
