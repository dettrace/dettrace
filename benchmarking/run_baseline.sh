#!/bin/bash -ex

## This script should only be called from the benchmarks directory!
if [ $(basename "$PWD") != "benchmarking" ]
then
    echo "Please call this script from within the benchmarking/ dir."
fi

# Copy script over to chroot.
cp scripts/run_baselineInsideChroot.sh ./wheezy/

unshare -m chroot ./wheezy /run_baselineInsideChroot.sh
