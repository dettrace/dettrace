#!/bin/bash
# Note: Run this script from *this* directory.

# Turn off ASLR
make &&
setarch `uname -m` -R ./src/dettrace ./test/unitTests/systemCallTests
