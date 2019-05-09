#!/bin/bash

while true
do
    ./bin/dettrace --debug 4 test/samplePrograms/twoPthreadsNoJoin.bin 2> temp.txt > /dev/null
    rc=$?;
    if [[ $rc != 0 ]]; then more temp.txt; exit $rc; fi
done

