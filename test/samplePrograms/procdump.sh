#!/bin/bash

# set -eEuo pipefail

for f in `ls /proc`; do
    echo -n "$f: ";
    if [ -f "/proc/$f" ];
    then
	cat "/proc/$f" | md5sum
    else
	echo "not a file"
    fi
done
