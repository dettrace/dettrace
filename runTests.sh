#!/bin/bash
# Note: Run this script from *this* directory.

set -xe

cd `dirname $0`

# Turn off ASLR
make 
setarch `uname -m` -R ./src/dettrace ./test/unitTests/systemCallTests
