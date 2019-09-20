#!/bin/bash

set -e

GCC=gcc
GXX=g++
CLANG=clang-6.0
CLANGXX=clang++-6.0
MAKE=make

export TZ=UTC

TMPDIR=/tmp/test-compilation

function cleanup {
  rm  -rf ${TMPDIR}
}
trap cleanup EXIT

mkdir -p ${TMPDIR}

function success {
  printf "%-72s    OK\n" "$1"
}

echo "int main() { return 0; } " | ${GCC} -xc -pipe -c -o ${TMPDIR}/${GCC}-c-success.o - && success "compile test with ${GCC}.."
echo "int main() { return 0; } " | ${CLANG} -xc -pipe -c -o ${TMPDIR}/clang-c-success.o - && success "compile test with ${CLANG}.."
echo "int main() { return 0; } " | ${GXX} -xc++ -pipe -c -o ${TMPDIR}/${GXX}-c-success.o - && success "compile test with ${GXX}.."
echo "int main() { return 0; } " | ${CLANGXX} -xc++ -pipe -c -o ${TMPDIR}/${CLANGXX}-c-success.o - && success "compile test with ${CLANGXX}.."

cat > ${TMPDIR}/helloworld.c <<EOF
#include <stdio.h>
int main(int argc, char* argv[]) {
  printf("hello world!\n");
  return 0;
}
EOF

echo -ne "compile & run helloworld.c with ${GCC}..\t"
${GCC} ${TMPDIR}/helloworld.c -o ${TMPDIR}/helloworld_c -O2 && ${TMPDIR}/helloworld_c
rm -f ${TMPDIR}/helloworld_c

echo -ne "compile & run helloworld.c with ${CLANG}..\t"
${CLANG} ${TMPDIR}/helloworld.c -o ${TMPDIR}/helloworld_c -O2 && ${TMPDIR}/helloworld_c
rm -f ${TMPDIR}/helloworld_c

rm -f ${TMPDIR}/helloworld.c

cat > ${TMPDIR}/helloworld.cc <<EOF
#include <iostream>
int main(int argc, char* argv[]) {
  std::cout << "hello world!\n";
  return 0;
}
EOF

echo -ne "compile & run helloworld.cc with ${GXX}..\t"
${GXX} ${TMPDIR}/helloworld.cc -o ${TMPDIR}/helloworld_cc -O2 && ${TMPDIR}/helloworld_cc
rm -f ${TMPDIR}/helloworld_cc

echo -ne "compile & run helloworld.cc with ${CLANGXX}..\t"
${CLANGXX} ${TMPDIR}/helloworld.cc -o ${TMPDIR}/helloworld_cc -O2 && ${TMPDIR}/helloworld_cc
rm -f ${TMPDIR}/helloworld_cc

rm -f ${TMPDIR}/helloworld.cc

# create helloworld.c
cat > ${TMPDIR}/helloworld.c <<EOF
#include <stdio.h>
int main(int argc, char* argv[]) {
  printf("hello world!\n");
  return 0;
}
EOF

echo -ne "run make to build/run simple programs.."
${MAKE} CC=${GCC} ${TMPDIR}/helloworld > /dev/null && ${TMPDIR}/helloworld

rm -f ${TMPDIR}/helloworld
rm -f ${TMPDIR}/helloworld.c

cat > ${TMPDIR}/datetime.c <<EOF
#include <stdio.h>
int main(int argc, char* argv[]) {
  printf("date: %s, time: %s\n", __DATE__, __TIME__);
  return 0;
}
EOF

echo -ne "date/time macro should be determistic.."
${GCC} ${TMPDIR}/datetime.c -o ${TMPDIR}/datetime-0 -O2 && ${TMPDIR}/datetime-0 > ${TMPDIR}/datetime-0.out
cat ${TMPDIR}/datetime-0.out
sleep 2
${GCC} ${TMPDIR}/datetime.c -o ${TMPDIR}/datetime-1 -O2 && ${TMPDIR}/datetime-1 > ${TMPDIR}/datetime-1.out
echo -ne "date/time should not change after rebuilds.."
diff ${TMPDIR}/datetime-0.out ${TMPDIR}/datetime-1.out && echo OK

rm -f ${TMPDIR}/datetime.c ${TMPDIR}/datetime-{0,1} ${TMPDIR}/datetime-{0,1}.out

cat > ${TMPDIR}/helloworld.py <<EOF
#!/usr/bin/env python
from __future__ import print_function
import sys
if __name__ == "__main__":
    input = sys.argv[0]
    lines = 0
    with open(input, 'r') as infile:
        for line in infile:
            lines = 1 + lines
    print(lines)
EOF
chmod +x ${TMPDIR}/helloworld.py && ${TMPDIR}/helloworld.py > /dev/null && success "running simple python program.."
rm -f ${TMPDIR}/helloworld.py ${TMPDIR}/helloworld.pyc

cat > ${TMPDIR}/helloworld.pl <<EOF
#!/usr/bin/env perl
#
# The traditional first program.

# Strict and warnings are recommended.
use strict;
use warnings;

# Print a message.
print "Hello, World!\n";
EOF

chmod +x ${TMPDIR}/helloworld.pl && ${TMPDIR}/helloworld.pl > /dev/null && success "running simple perl program.."
rm -f ${TMPDIR}/helloworld.pl
