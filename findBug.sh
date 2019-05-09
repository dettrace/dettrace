#!/bin/bash

while true
do
    echo "First Try..."
    ./bin/dettrace --timeoutSeconds 10 --debug 4 test/samplePrograms/twoPthreadsNoJoin.bin 2> temp.txt > /dev/null
    rc=$?;
    if [[ $rc != 0 ]]; then more temp.txt; exit $rc; fi
done

