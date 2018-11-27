#!/bin/bash -ex

### This download and sets up the chroot we use for our benchmarking.
### This only has to be done once!
### This script must be run as sudo... I'm sorry.
### This will only work from a ubuntu/debian enviornment.
if [ -f "./wheezy" ]
then
	  echo "./wheezy chroot already exists! Exiting..."
fi

# Download chroot
debootstrap --variant=buildd wheezy ./wheezy http://deb.debian.org/debian/

# Install dettrace inside chroot...
mkdir -p ./wheezy/dettrace/

# Go inside chroot!
cp scripts/installInsideChroot.sh ./wheezy/
chroot ./wheezy /installInsideChroot.sh
