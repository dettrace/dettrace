# This should only be ran inside of the wheezy chroot!
mount proc /proc -t proc
mount devpts /dev/pts -t devpts
mount sysfs /sys -t sysfs

cd /home/
package=$1

mkdir $package
cd $package
apt-get source $package
apt-get -y build-dep $package
dpkg-source -x *.dsc build
cd ../
