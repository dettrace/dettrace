#!/bin/bash -ex

# Mount!
mount proc /proc -t proc
mount devpts /dev/pts -t devpts
mount sysfs /sys -t sysfs

cd /home/
# Add to sources.list
echo "deb-src http://deb.debian.org/debian wheezy main" >> /etc/apt/sources.list
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

umount /proc
umount /dev/pts
