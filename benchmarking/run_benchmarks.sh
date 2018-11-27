#!/bin/bash -ex

# Build dettrace
make -C ../ static

# Move dettrace into our chroot!
rsync -a ../root/ wheezy/dettrace/root
rsync -a ../lib/ wheezy/dettrace/lib
rsync -a ../bin/ wheezy/dettrace/bin

# Go inside chroot!
cp ./scripts/runBenchmarksInsideChroot.sh ./wheezy/
chroot ./wheezy /runBenchmarksInsideChroot.sh
