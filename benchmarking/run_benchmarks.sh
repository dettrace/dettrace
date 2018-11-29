#!/bin/bash -ex

## This script should only be called from the benchmarks directory!
if [ $(basename "$PWD") != "benchmarking" ]
then
    echo "Please call this script from within the benchmarking/ dir."
fi

# Build dettrace
make -C ../
# remove old files
rm *.time || true

for package in xdelta sl whiff xdelta3 xdg-utils xdiskusage; do
    for i in 1 2 3; do
        /usr/bin/time --append -o $package.time \
        -f "build time, real %e, user %U, sys %S" \
        ../bin/dettrace --chroot ./wheezy --working-dir ./wheezy/home/$package/build \
        dpkg-buildpackage -uc -us -b
    done
done

more *.time
