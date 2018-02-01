
# Determinism enforcement based on ptrace.

## Overview
Using `ptrace` we are able to run programs deterministically. All system calls are caught
and determinized by our tracer.

## Installation
Working on any recent Linux system you should be able to `make` from this directory.

We use C++17 features not yet implemented in older compilers. It should work with GCC
6.0 or higher. See [GCC feature list](https://gcc.gnu.org/projects/cxx-status.html).

## Usage
Use the `dettrace` executable to run a program deterministically:
```shell
./dettrace <your_executable> <your_flags>
```

For example `ls`:
```shell
./dettrace ls -ahl
```

## Debugging
We support the debugging flag `--debug N` for N from [1, 5]. Where 5 is the most verbose
output.

## Unimplemented System Calls
We use a whitelist to determinizing system calls. Therefore any system call not implemented
will throw a runtime exception.