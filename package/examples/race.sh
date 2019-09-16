#!/bin/bash

function prnt {
    for ((i=0; i<500; i++)); do
	echo -n $1;
    done;
    echo;
}

prnt a &
prnt b
wait
echo

