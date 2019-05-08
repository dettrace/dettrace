#!/bin/bash -ex

### This script should NOT be called directly by you! It is meant to be called inside
### the chroot set up by ./createChroot.sh

# Mount!
mount proc /proc -t proc
mount devpts /dev/pts -t devpts
mount sysfs /sys -t sysfs

cd /home/
# Add to sources.list
echo "deb-src http://archive.debian.org/debian-archive/debian wheezy main" >> /etc/apt/sources.list
apt-get update

apt-get install dpkg-dev time

# Fetch source and dependecies for our packages.
for package in xdelta sl whiff xdelta3 xdg-utils xdiskusage; do
    mkdir $package
    cd $package
    apt-get source $package
    apt-get -y build-dep $package
    dpkg-source -x *.dsc build
    cd ../
done

# Even if script fails before we unmount here, the mount namespace will make sure
# this is cleaned up
umount /proc
umount /dev/pts
umount /sys
