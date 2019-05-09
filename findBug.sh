#!/bin/bash

while true
do
    echo "First Try..."
    python3 ./test/samplePrograms/timeout.py 5s ./bin/dettrace --debug 4 test/samplePrograms/twoPthreadsNoJoin.bin 2> temp.txt > /dev/null
    rc=$?;
    if [[ $rc != 0 ]]; then more temp.txt; exit $rc; fi
done

