
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
