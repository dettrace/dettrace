# Cloudseal Alpha - Dynamic determinism enforcement

## Overview

Cloudseal uses a combination of lightweight containerization and system call interception to identify and compensate for potentially random behavior that may occur during the execution of a given program or command. In this way, Cloudseal can be used to launch arbitrary programs and run them in a way that is deterministic and reproducible.

Future Cloudseal releases will include additional features, particularly record-replay features.  This alpha package provides only the core deterministic container concept, and it is useful primarily for deterministic builds and software tests.

## Installation

The Cloudseal package installs to a single directory anywhere within your file system.  Cloudseal is a statically-linked executable that should work on any Linux distribution, with kernel version 4.8 or greater. Below are three different ways to get files onto your system.

### With a script one-liner

You can install globally to `/usr/cloudseal` with:

```shell
curl -sSLf https://cloudseal.io/getit | sudo bash
```

This uses a default installation root of `/usr`, with Cloudseal files unpacked in `/usr/cloudseal`. The script will also create a symbolic link: `/usr/bin/cloudseal`.

A non-root user can install to a custom directory:

```shell
curl -sSLf https://cloudseal.io/getit | bash -s custom_dir
```

### From a binary tarball

You can grab the latest binary tarball at the [Cloudseal downloads page](https://cloudseal.io/download).  To install this manually, simply unpack it anywhere you like and make sure the contained `./bin/cloudseal` binary is on your path.

### Via a `.deb` package

The [downloads page](https://cloudseal.io/download) also provides an installation package in the Debian `.deb` file format.  Then install with:

```shell
sudo apt install ./cloudseal-alpha_xyz.deb
```

## Basic Usage

Typical usage of the Cloudseal tool consists of simply placing `cloudseal` at the beginning of the command that is to be executed. For example, running the script `my-example.sh` would be achieved by the following command:
```shell
cloudseal ./my-example.sh
```

Similarly, we could run `cloudseal ls -l`, revealing that the process run under Cloudseal can still by default access the full file system, including `/bin/ls`. More detailed control over the starting conditions of the deterministic computation is enabled with additional command line flags. To see these flags and how to use them, please refer to the command line help info:

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

Next, run one of the examples a few times. For example,
running `./rand.py` should output a new series of random numbers on each execution:

```shell
$ ./rand.py
57 55 68 49 11 68 88 43 2 97
$ ./rand.py
17 12 63 1 92 76 75 68 13 81
$ ./rand.py
98 44 97 98 35 40 40 10 36 19
```

Finally, run the same script a few more times, but this time, use `cloudseal` to
enforce determinism:

```shell
$ cloudseal ./rand.py
55 8 80 78 8 35 14 60 71 78
$ cloudseal ./rand.py
55 8 80 78 8 35 14 60 71 78
$ cloudseal ./rand.py
55 8 80 78 8 35 14 60 71 78
```

Notice the key difference here: every execution returns the same results!

In addition to `rand.py`, you can also try the following example scripts:

- `race.sh`: Creates two simultaneously-running processes, one printing `a`
and the other printing `b`. Normally, this generates an output string of
randomly interleaved `a`s and `b`s, but calling this script with `cloudseal`
results in a consistent, reproducible output string.

- `date.sh`: Retrieves the current date and time via the `date` command.
Normally, the output of this command would change on subsequent calls as
time elapses. However, running with `cloudseal` ensures that the same
date output is received on every call.

- `devrand.sh`: Generates random numbers similar to `rand.py`, but uses
`/dev/random` as the source of its data. **Note:** Reading from `/dev/random`
will block until sufficient entropy is available to generate the random output,
so this example can take a while to run.

It is highly reccommended to take a look at the contents of these example
scripts to see what is being tested.

It is also worthwhile to experiment with running arbitrary commands in
`cloudseal`. One such experiment could be reading directly from `/dev/urandom`:

```shell
$ head -c 16 /dev/urandom | hexdump
0000000 9808 6ead 7593 4497 6435 a7d9 876d 8720
0000010
$ head -c 16 /dev/urandom | hexdump
0000000 31b6 8790 f480 8c05 62c5 653f fdbd 27ba
0000010
$ head -c 16 /dev/urandom | hexdump
0000000 e8aa f3e1 95be 0780 4cce 2a15 edf9 d6c9
0000010
```

Again, we see random data being generated. Next, run the same command with
`cloudseal`:
```shell
$ cloudseal head -c 16 /dev/urandom | hexdump
0000000 3211 d873 5fc1 a37b d83b cf8d ea15 69c2
0000010
$ cloudseal head -c 16 /dev/urandom | hexdump
0000000 3211 d873 5fc1 a37b d83b cf8d ea15 69c2
0000010
$ cloudseal head -c 16 /dev/urandom | hexdump
0000000 3211 d873 5fc1 a37b d83b cf8d ea15 69c2
0000010
```

As expected, the command is now running deterministically and generates
the same output on each execution.
