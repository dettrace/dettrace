#!/bin/bash
# Note: Run this script from *this* directory.

set -xe

cd `dirname $0`
echo "Running unit tests."
# Turn off ASLR
make
setarch `uname -m` -R ./src/dettrace ./test/unitTests/systemCallTests

echo "Running sample programs."
# Returns 1 on success, 0 on failure.
python3 ./test/samplePrograms/compareOutputs.py
echo "ALL TEST PASSED!"
