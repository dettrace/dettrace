#!/bin/bash
# This script must run as sudo!!
# Installs a new package inside chroot under /home/

# Move actual script to chroot.
cp ./scripts/install_package.sh ./wheezy/install_package.sh
chmod +x ./wheezy/install_package.sh

# Get package.
package=$1
current_dir=./wheezy/home/$package
echo "Instaling package " $current_dir

# Package already exists...
if [ ! -d $current_dir ]
then
    # Download package first.
    echo "Installing package"
    chroot ./wheezy /install_package.sh $package
fi

# Set permissions so user can write to any directory in their chroot.
chgrp -R $(logname 2>/dev/null || echo $SUDO_USER) $current_dir
chown -R $(logname 2>/dev/null || echo $SUDO_USER) $current_dir
