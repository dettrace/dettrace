#!/bin/bash

while true
do
    echo "First Try..."
    ./bin/dettrace --debug 4 test/samplePrograms/twoPthreadsNoJoin.bin
    rc=$?;
    if [[ $rc != 0 ]]; then more temp.txt; exit $rc; fi
done

