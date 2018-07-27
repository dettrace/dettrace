#!/bin/bash

set -e

GCC=gcc
GXX=g++
CLANG=clang-6.0
CLANGXX=clang++-6.0

TMPDIR=/tmp/test-compilation

function cleanup {
  rm  -r ${TMPDIR}
}
trap cleanup EXIT

mkdir ${TMPDIR}

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

