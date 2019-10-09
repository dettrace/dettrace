
# DetTrace: Dynamic Determinism Enforcement Based on Ptrace.

[![Build Status](https://dev.azure.com/upenn-acg/detTrace/_apis/build/status/upenn-acg.detTrace?branchName=master)](https://dev.azure.com/upenn-acg/detTrace/_build/latest?definitionId=1&branchName=master)

## Overview
Using `ptrace` we are able to run programs deterministically. All nondeterministic system
calls are caught and determinized by DetTrace.

## Building

### Project Dependencies
Currently, this project requires the following dependencies:

```
clang # Building C++ code base
libssl-dev # Hashing of bytes from read system call.
libseccomp-dev # Helper library for finer-grained system call filtering.
libarchive-dev # TBD
```

This project relies on the [libseccomp library](https://github.com/seccomp/libseccomp). Please install. For hassle free, we recommend installing from your system's standard repository of packages.

Working on any recent Linux system you should be able to `make` from this directory.

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
output. Notice debugging output is deterministic for levels 1-4, not 5.

## Unimplemented System Calls
We use a whitelist to determinize system calls. Therefore any system call not implemented
will throw a runtime exception.

## Testing

`make test` invokes the test runner.  Right now [2018.07.13] we are
running our tests through Docker (`make test-docker`).

## Contribution Guidelines

As more people work concurrently on DetTrace, and the project becomes more complicated,
please follow the following guidelines for contributing to DetTrace.

1) Every commit from now on should represent a working, testable, version of DetTrace,
    please squash commits as needed to have every commit represent a logical, working
    state of DetTrace.
2) Please create and add an integration test for any change made made to DetTrace if
    possible. This will avoid future regressions, and ensure your change works.
3) Pushing to master has been disabled for all of us!
    Submit a pull request with your changes. We should
    all do a better job and hold each other accountable for reviews and quick pull
    request merges to keep things moving along.
4) Rebase changes to the latest commit in master (head) before submitting a pull request.
5) Use rebase instead of merge when updating your branch with the latest DetTrace changes.
6) Keep pull request commit numbers short when possible. It is hard/impossible to follow
    pull requests consisting of hundreds of commits!
