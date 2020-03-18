
# DetTrace: A Reproducible Container Abstraction

[![Build Status](https://dev.azure.com/upenn-acg/detTrace/_apis/build/status/dettrace.dettrace?branchName=master)](https://dev.azure.com/upenn-acg/detTrace/_build/latest?definitionId=1&branchName=master)

Here, we give an overview of the command line interface for Dettrace as well as common Dettrace workflows. We describe the steps necessary to build Dettrace, software dependencies, hardware requirements, and compiler toolchains. Furthermore, we show various example use-cases for Dettrace and using chroot environments.

## Quick Start

To quickly run something deterministically, use Docker.  Clone this repository and build:

```bash
docker build -t dettrace .
docker run -it --rm --privileged dettrace
```

Or pull and run from DockerHub:

```bash
docker run -it --rm --privileged dettrace/dettrace
```

Once inside the container (in privileged mode with CAP_SYS_ADMIN), you can run under dettrace:

```bash
> dettrace  --epoch="1980-01-01,00:00:00" date
Tue Jan  1 00:00:00 UTC 1980
```

In this simple example, by controlling the container config, we
controlled the virtual time exposed through system calls inside the
reproducible container.


## Description

The latest version of Dettrace can be found on GitHub at https://github.com/dettrace/dettrace.

### Hardware dependencies
The Dettrace prototype currently only works for x86-64 Intel CPUs. While not strictly necessary, portability guarantees are strongest when the CPU supports intercepting certain nondeterministic CPU instructions, e.g., CPUID.

### Software dependencies
Dettrace works well with kernel versions 4.8 through 5.3 (only minor modifications should be necessary to allow Dettrace to work in newer kernel versions). Kernel version < 4.8 use a slower
ptrace implementation (more details in publication) making overall execution of Dettrace slower. Kernel version >= 4.12 are required for OS support for CPUID interception. Currently Dettrace has a few dependencies:
- libssl: Hashing implementation for bytes from read system call (Useful for debugging nondeterministic bytes read from pipe).
- libseccomp: Helper library for finer-grained system call filtering using seccomp-bpf.
- libarchive: Unpackaging archive files used by Dettrace.
- libelfin: ELF/DWARF parser.
- libfuse: test-only dependence, used for filesystem tests.


These dependencies are fairly common and should be easy to install from your Linux distro's package manager. For Apt these are libarchive-dev, libssl-dev, and libseccomp-dev, libelfin-dev, and libfuse-dev.

Dettrace relies on various Linux namespaces for isolation and determinism. Some systems disable user namespaces by default. If you encounter a `clone failed: operation not permitted` error, please enable user namespace access (the exact method may depend on your distro and OS version). Furthermore, Linux does not allow user namespaces for processes whose root is not `/` (the chroot system call was executed at some point).

### Data sets

While Dettrace is designed to enforce reproducibility for arbitrary computation, the prototype implementation is tailored to work with Debian packages and chroot environments. The Debian Apt Package Repository and chroot images available through debootstrap may be of interest. Our prototype was used to build the now old Debian Wheezy packages; recent Debian version may execute system calls not currently implemented in Dettrace.

## Installation

Dettrace uses a standard Makefile for compilation. Assuming you have the all the software dependencies (above), and a C++ compiler supporting C++14, running `make` in the root directory of the repository will generate the Dettrace binary under `bin/`. Dettrace may also be statically linked using `make static` assuming all the correct dependencies are present as statically linkable objects. Dettrace may be installed anywhere on the system by moving the `bin/` directory along with the `root/` directory. This directory structure must be maintained as the Dettrace binary always expects `root/` to be located at the directory `../root` relative to the location of the Dettrace binary (see reasoning below).

The word `chroot` is unfortunately overloaded, referring to both the Linux system call which changes the location of the root directory for a process, and for the concept of a directory tree which "looks like" a Linux filesystem, containing all the binaries, libraries, and special files (e.g. `/proc`, `/dev/`) necessary for a Linux system to function.

The Debian command `debootstrap` is an easy way to get such a chroot environment. For more information see: https://wiki.debian.org/chroot. If you're using a different Linux distribution, you should consult the documentation to find the appropriate way to install a chroot. You can install debootstrap from the Apt repository. `sudo apt install debootstrap`.

One can install a Stretch Debian chroot by running the commands:

```bash
> mkdir stretch
> sudo debootstrap stretch stretch/ http://deb.debian.org/debian
```

Unfortunately, this requires root permissions. Once you have downloaded the chroot, you should have a `stretch/` directory which we can `ls`:
```bash
> ls stretch
bin/   dev/  home/  lib64/  mnt/  proc/  run/
boot/  etc/  lib/   media/  opt/  root/  sbin/
```

As you can see, this looks just like a Linux filesystem tree. Dettrace accepts any such chroot to be used as the starting image. As Dettrace will be using the files in `stretch/`
we need to ensure the permissions are correct (more information can be found at https://wiki.debian.org/chroot):
```bash
> sudo chgrp -R $USER stretch/
> sudo chown -R $USER stretch/
```

You are now ready to use Dettrace and the chroot (see below).

## Experiment workflow

Dettrace is a command line tool which makes it easy to make computation reproducible. You can simply prepend the command you are interested in determinizing with `./path/to/dettrace`, but if you want to execute a command containing hyphenated flags, be sure to separate it with ` -- `.
For example:

```bash
> ./bin/dettrace -- ls -ahl
-rw-r--r-- 1 root ... Jan 1 1970 initramfs.cpio
drwxr-xr-x 1 root ... Jan 1 1970 root
-rw-r--r-- 1 root ... Jan 1 1970 shell.nix
drwxr-xr-x 1 root ... Jan 1 1970 src
...
```
Note the modification dates of all files are now deterministic! Dettrace will determinize the specified program along with any subprocesses that are spawned. Furthermore, Dettrace containerizes the program to guarantee a reproducible starting filesystem.  For example `/tmp` must always start empty, and if we generate a temp file it must be deterministic:

```bash
> ./bin/dettrace -- ls /tmp
> ./bin/dettrace -- bash -c 'mktemp; ls /tmp'
/tmp/tmp.GF2eacAJCh
tmp.GF2eacAJCh
```

Similarly we may create a file and then `stat` the file with Dettrace:
```bash
> touch foo.txt
> ./bin/dettrace stat foo.txt
  File: foo.txt
  Size: 0	 Blocks: 1  IO Block: 512 ...
Device: 1h/1d	Inode: 8   Links: 1
Access: (0644/-rw-r--r--)  Uid: ...
Access: 1970-01-01 00:00:00.000000000 +0000
Modify: 1970-01-01 00:00:00.000000000 +0000
Change: 1970-01-01 00:00:00.000000000 +0000
 Birth: -
```
Notice the file's metadata is now deterministic!

The current release of dettrace does not build its a custom chroot environment for executing each command.  Rather, you can control the base filesystem image using existing container technology like Docker.  Running dettrace inside a Docker container will expose the `/` file system including CWD.

## Evaluation and expected result

Any program running under Dettrace is expected to produce deterministic output. So running the `date` command multiple times will produce the same result.

```bash
> ./bin/dettrace date
Sun Aug  8 22:00:00 UTC 1993
> ./bin/dettrace date
Sun Aug  8 22:00:00 UTC 1993
```

Dettrace comes with dozens of sample nondeterministic programs meant to stress test different sources of nondeterminism found in programs. These programs are designed to be nondeterministic, and have an expected, deterministic, output when running under Dettrace. You may test your installation by running `make test` to run all our sample programs and integration tests. If docker is installed you may run `make test-docker` to run the same tests under a Docker environment instead. Docker is the preferred way to run the tests as it handles hard-to-reproduce sources of irreproducibility seen in the wild.

Let's do a reproducible build! For simplicity we will use Dettrace itself as the program to build reproducibly. From the root directory of the Dettrace repository:
```bash
./bin/dettrace -- make -C src/
```

This will build Dettrace deterministically under Dettrace. You can use a program like `hashdeep` to hash the binary outputs of programs and ensure the results are deterministic
across builds.

## Experiment customization

Dettrace has several command line options which may be useful. See `./bin/dettrace --help` for list of all options.

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
