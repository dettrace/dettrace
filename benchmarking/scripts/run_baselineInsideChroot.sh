#!/bin/bash -ex

### This script should NOT be called directly by you! It is meant to be called inside
### the chroot set up by ./run_baseline.sh

# Mount!
mount proc /proc -t proc
mount devpts /dev/pts -t devpts
mount sysfs /sys -t sysfs

cd /home/

rm /home/*.time || true

for package in xdelta sl whiff xdelta3 xdg-utils xdiskusage; do
    for i in 1 2 3; do
        cd /home/$package/build/;
        LC_ALL=C /usr/bin/time --append -o /home/$package.time \
        -f "build time, real %e, user %U, sys %S" \
        dpkg-buildpackage -uc -us -b;
    done
done

cd /home/
more *.time

# Even if script fails before we unmount here, the mount namespace will make sure
# this is cleaned up
umount /proc
umount /dev/pts
umount /sys
