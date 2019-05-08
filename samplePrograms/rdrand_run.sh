#!/bin/bash
# A little script for confirming rdrand is an expected failure:
echo "Testing rdrand.bin"
set -u

TMP1=`mktemp`
TMP2=`mktemp`
TMP3=`mktemp`
TMP4=`mktemp`

./rdrand.bin &> $TMP1
code1=$?
# Hacky way to get the Illegal instruction:
bash -c './rdrand.bin 2>&1' &> $TMP2
# ./rdrand.bin &> $TMP
code2=$?
set +x
echo "Return codes from native rdrand runs: $code1 $code2"

if grep -q 'Illegal instruction' $TMP2 ;
then echo "OK: rdrand not supported on this arch.";
else echo "OK: rdrand worked natively on this arch."
fi

../../bin/dettrace ./rdrand.bin &> $TMP3
code3=$?
../../bin/dettrace ./rdrand.bin &> $TMP4
code4=$?

if [ $code3 != "0" ] || [ $code4 != "0" ] ;
then
    echo "Expected failure: dettrace not expected to work for rdrand."
    echo "Return codes: $code3 $code4"
   
elif diff $TMP3 $TMP4 ;
then echo "ERROR unexpected pass: dettrace made rdrand reproducible!?"
     if ! grep -q "RDRAND value" $TMP3 ;
     then echo "It looks like the program died in the middle with a silent failure."
     fi
     exit 1
else
    echo "Expected failure: dettrace let rdrand through and produced nonreprodocible outputs."
fi
rm $TMP1 $TMP2 $TMP3 $TMP4
