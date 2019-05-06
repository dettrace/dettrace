#!/bin/bash
# A little script for confirming rdrand is an expected failure:
echo "Testing rdrand.bin"
set -u

TMP1=`mktemp`
TMP2=`mktemp`
TMP3=`mktemp`

./rdrand.bin &> $TMP1
code1=$?
# Hacky way to get the Illegal instruction:
bash -c './rdrand.bin 2>&1' &> $TMP2
# ./rdrand.bin &> $TMP
code2=$?
set +x
echo "Return codes from rdrand runs 1&2: $code1 $code2"

if grep -q 'Illegal instruction' $TMP2 ;
then echo "OK: rdrand not supported on this arch.";
elif diff $TMP1 $TMP2 ;
then echo "OK: rdrand worked, but produced different values."
else echo "Error: rdrand produced same answer!?"
     exit 1
fi

../../bin/dettrace ./rdrand.bin 2> $TMP3
code3=$?
if [ $code3 == "0" ];
then echo "ERROR unexpected pass: dettrace ran rdrand and shouldn't!"
     echo "Output: "
     cat $TMP3
     exit 1
else echo "Expected failure: dettrace not expected to work for rdrand."     
fi
rm $TMP1 $TMP2 $TMP3
