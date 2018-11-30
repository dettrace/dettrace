## Benchmarking

This folder is designed to allow for quick benchmarking of debian reproducible build packages with respect to a dettrace implementation.

## Installation
Install the needed wheezy chroot using `./creatChroot` script. You will need to run this script using `sudo`. This only needs to be done once, it may take a while to set up.
Do not call the `./scripts/installInsideChroot.sh` this script is meant to be run from inside the chroot, it is called by `./createChroot`

## Running benchmarks
Use the `run_benchmarks.sh`, it will recompile dettrace and runt it on 6 benchmarks: `sl`, `whiff`, `xdelta`, `xdelta3`, `xdg-utils`, `xdiskusage`.

The benchmarks will generate $package.time file showing 3 runtimes per benchmark. Example:

```bash
omarsa@acghaswellcat16 /h/o/d/benchmarking> more *.time
::::::::::::::
sl.time
::::::::::::::
build time, real 9.99, user 6.04, sys 4.26
build time, real 9.88, user 6.28, sys 3.98
build time, real 9.98, user 6.11, sys 4.12
::::::::::::::
whiff.time
::::::::::::::
build time, real 7.23, user 4.10, sys 3.21
build time, real 7.18, user 4.24, sys 3.16
build time, real 7.35, user 4.19, sys 3.21
::::::::::::::
xdelta.time
::::::::::::::
build time, real 45.50, user 24.66, sys 20.68
build time, real 46.25, user 24.69, sys 20.71
build time, real 44.72, user 24.59, sys 20.49
::::::::::::::
xdelta3.time
::::::::::::::
build time, real 17.74, user 14.04, sys 3.66
build time, real 17.25, user 13.57, sys 3.69
build time, real 16.91, user 13.41, sys 3.57
::::::::::::::
xdg-utils.time
::::::::::::::
build time, real 24.03, user 14.63, sys 9.06
build time, real 23.68, user 14.77, sys 8.73
build time, real 23.81, user 14.97, sys 8.63
::::::::::::::
xdiskusage.time
::::::::::::::
Command terminated by signal 6
build time, real 1.47, user 0.09, sys 0.29

```
