# Sample Programs to run deterministically

## Reason
Our unit test framework catch, does not allow for process forking. So we must run several
of our tests outside the test framework. We do it here by diff-ing the output of the
program under dettrace vs. the known determinsitic output.

## Adding more sample programs to test against.

let `yourSampleProgram` the name of your sample program.

1) Add the source file to this directory, with the name _yourSampleProgram.c_
2) Add yourSampleProgram to theMakefile in this directory. See ./Makefile for reference.
3) Add the reference output file to compare against as ExpectedOutputs/yourSampleProgram.output.