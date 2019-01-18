# This should only be ran inside of the wheezy chroot!
cd /home/
package=$1

mkdir $package
cd $package
apt-get source $package
apt-get -y build-dep $package
dpkg-source -x *.dsc build
cd ../
