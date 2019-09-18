# Cloudseal Alpha - Dynamic determinism enforcement

## Overview

Cloudseal uses a combination of lightweight containerization and system call interception to identify and compensate for potentially random behavior that may occur during the execution of a given program or command. In this way, Cloudseal can be used to launch arbitrary programs and run them in a way that is deterministic and reproducible.

Future Cloudseal releases will include additional features, particularly record-replay features.  This alpha package provides only the core deterministic container concept, and it is useful primarily for deterministic builds and software tests.

## Installation

The Cloudseal package installs to a single directory anywhere within your file system.  Cloudseal is a statically-linked executable that should work on any Linux distribution with kernel version 4.8 or greater. Below are three different ways to get files onto your system.

### Install with a script

You can install globally to `/usr/cloudseal` with:

```shell
curl -sSLf https://cloudseal.io/getit | sudo bash
```

This uses a default installation root of `/usr`, with Cloudseal files unpacked in `/usr/cloudseal`. The script will also create a symbolic link: `/usr/bin/cloudseal`.

A non-root user can install to a custom directory:

```shell
curl -sSLf https://cloudseal.io/getit | bash -s custom_dir
```

### Install from a binary tarball

You can grab the latest binary tarball at the [Cloudseal downloads page](https://cloudseal.io/download).  To install the software manually, simply unpack the tarball anywhere you like and make sure the contained `./bin/cloudseal` binary is on your path.

### Install via a `.deb` package

In addition to tarballs, the [downloads page](https://cloudseal.io/download) provides an installation package in the Debian `.deb` file format.  Download it and then install with:

```shell
sudo apt install ./cloudseal-alpha_xyz.deb
```

## Basic Usage

Typical usage of the Cloudseal tool consists of simply placing `cloudseal` at the beginning of the command that is to be executed. For example, running the script `my-example.sh` would be achieved by the following command:
```shell
cloudseal ./my-example.sh
```

Similarly, we could run `cloudseal ls -l`, which runs the usual `/bin/ls`, revealing that the process run under Cloudseal can by default access the full host file system. More detailed control over the starting conditions of the deterministic computation is enabled with additional command line flags. To see these flags and how to use them, please refer to the command line help info:

```shell
cloudseal --help
```

## Examples
The Cloudseal installation will generate a directory of example scripts located at `<installDir>/cloudseal/examples`
which highlight some of the ways that Cloudseal can be used to enforce determinism.

To run these scripts, first go to the examples directory:
```shell
cd /usr/share/cloudseal/examples
```

Next, run one of the examples a few times to see that it is, by default,
nondeterministic. For example, running `./rand.py` should output a new
series of random numbers on each execution:

```shell
$ ./rand.py
57 55 68 49 11 68 88 43 2 97
$ ./rand.py
17 12 63 1 92 76 75 68 13 81
```

Finally, run the same script again, but this time, use `cloudseal` to
enforce determinism:

```shell
$ cloudseal ./rand.py
55 8 80 78 8 35 14 60 71 78
$ cloudseal ./rand.py
55 8 80 78 8 35 14 60 71 78
```

Notice the key difference here: every execution returns the same
results!  It doesn't matter what language the program is written in or
exactly *how* it gets its randomness (e.g., `getrandom` system call,
or `/dev/random`).  Because all sources of randomness are determinized, the end result is determinstic.  However, if we want to seed our container with a different stream of random numbers, we can simply change its initial state by changing the seed:

```
$ cloudseal --prng-seed=100  ./examples/rand.py
66 21 41 90 94 9 97 97 8 64
$ cloudseal --prng-seed=200  ./examples/rand.py
12 93 91 75 36 20 5 51 61 37
```

### More Examples

In addition to `rand.py`, you can also try the following example scripts:

- `race.sh`: Creates two simultaneously-running processes, one printing `a`
and the other printing `b`. Normally, this generates an output string of
randomly interleaved `a`s and `b`s, but calling this script with `cloudseal`
results in a consistent, reproducible output string.

- `date.sh`: Retrieves the current date and time via the `date` command.
Normally, the output of this command would change on subsequent calls as
time elapses. However, running with `cloudseal` ensures that the same
date output is received on every call.  The `--epoch` flag can control the date visible in the program.

- `devrand.sh`: Generates random numbers similar to `rand.py`, but uses
`/dev/random` as the source of its data. 

Take a look at the contents of these example scripts to see what is being tested.

As you start running arbitrary commands in `cloudseal`, it is recommended to start with your software builds or unit tests.
