# binaries that are simple to build (1 source file, same name as binary)
SIMPLE_ROOTS=simpleFork inverseFork nestedFork vfork clock_gettime getpid uname pipe getRandom waitOnChild fchownat forkAndPipe helloWorld 2writers1reader fuse-single-read fuse-single-write open openat creat  sigsegv sigill sigabrt kill alarm-handler alarm-nohandler alarm-ignore selectWithoutTimeout selectWithTimeout getdents getdents64 pollWithoutTimeout pollWithPositiveTimeout pollWithNegativeTimeout rdtsc rdtscp nanosleep nanosleep-par alarm-resethand readDevRandom readDevRandomMultiple readDevUrandom exec-mkstemp complex_mkdirat_dirfd mkdir mkdirat_fdcwd mknod mknod_fullpath open_already_exists openat_already_exists simpleCreat simple_mkdirat_dirfd symlink symlinkat vdso-funcs multithreaded multipleThreads processAndThread processThreadProcess processThreadThread pthreadJoin pthreadNoJoin ptpThreadJoin ptpThreadNoJoin twoPthreadsJoin twoPthreadsNoJoin tenThreadJoin tenThreadNoJoin exitgroup exitgroupMainProcess condvar-parent-wait condvar-thread-wait sigsuspend sigtimedwait-no-timeout sigtimedwait-timeout-0s sigtimedwait-timeout-1s timerfd1 cpuid_fault # confdir3 execveMainThread execveThreads open_tmpfile deadlockingPipe

ifndef DETTRACE_NO_CPUID_INTERCEPTION
SIMPLE_ROOTS := $(SIMPLE_ROOTS) cpuid
endif

SIMPLE_BINARIES= $(addsuffix .bin,$(SIMPLE_ROOTS))

# binaries with parameterized builds
PARAM_ROOTS= pipe-pWcR pipe-cWpR pipe-pcWpR pipe-pWpcR pipe-cWpcR pipe-pcWpcR setitimer-real setitimer-virtual setitimer-prof getitimer-real getitimer-virtual getitimer-prof # mq
PARAM_BINARIES= $(addsuffix .bin,$(PARAM_ROOTS))

# built-in Linux utilities, nothing to build
LINUX_UTILITIES=sshkeygen grep sed more less ls sh cat # relativeTimeStamps1 relativeTimeStamps2 tars to fix one day.

SHELL_SCRIPTS= bash1.sh test-compilation.sh

# tests of random number generator insns, need special build flags
BROADWELL_ROOTS= rdinsn
BROADWELL_BINARIES= $(addsuffix .bin,$(BROADWELL_ROOTS))

RT_ROOTS= timer_create_default timer_create_sigvtalrm timer_gettime
RT_BINARIES= $(addsuffix .bin,$(RT_ROOTS))

ifdef DETTRACE_NO_CPUID_INTERCEPTION
CXX_ROOTS=
else
CXX_ROOTS=random_device
endif
CXX_BINARIES= $(addsuffix .bin,$(CXX_ROOTS))

DETTRACE=../../bin/dettrace --
DIFF_CMD=diff

CC ?= clang

build: $(SIMPLE_BINARIES) $(PARAM_BINARIES) $(BROADWELL_BINARIES) $(RT_BINARIES) $(CXX_BINARIES)

run: test
test: test-binaries test-scripts
test-binaries: $(patsubst %.bin, %.ok, $(SIMPLE_BINARIES)) $(patsubst %.bin, %.ok, $(PARAM_BINARIES)) $(patsubst %, %.ok, $(LINUX_UTILITIES)) $(patsubst %.bin, %.ok, $(BROADWELL_BINARIES)) $(patsubst %.bin, %.ok, $(RT_BINARIES)) $(patsubst %.bin, %.ok, $(CXX_BINARIES))
test-scripts: $(patsubst %.sh, %.ok, $(SHELL_SCRIPTS))

# compile each sample program binary
$(SIMPLE_BINARIES): %.bin: %.c
	@$(CC) $< -Wall -Werror -g -o $@ -pthread -std=gnu99

# HW RNG tests need >=broadwell codegen
$(BROADWELL_BINARIES): %.bin: %.c
	@$(CC) $< -Wall -Werror -g -o $@ -pthread -std=gnu99 -march=broadwell

# timer_create tests need to link with -lrt
$(RT_BINARIES): %.bin: %.c
	@$(CC) $< -Wall -Werror -g -o $@ -std=gnu99 -lrt

$(CXX_BINARIES): %.bin: %.cpp
	@$(CXX) $< -Wall -Werror -g -o $@ -std=gnu++11

rdinsn.ok: rdinsn.bin
	@echo "   Testing rdrand..."
	@$(DETTRACE) ./rdinsn.bin rdrand > ActualOutputs/rdrand.output
	@echo "   Testing rdseed..."
	@$(DETTRACE) ./rdinsn.bin rdseed > ActualOutputs/rdseed.output

cpuid_fault.ok: cpuid_fault.bin
	@echo "   Testing cpuid_fault works on host..."
	@./cpuid_fault.bin > ActualOutputs/cpuid_fault.output
	@$(DIFF_CMD) ActualOutputs/cpuid_fault.output ExpectedOutputs/cpuid_fault.output

# NB: disable special cpu insn test for now
# cpuid.ok: cpuid
# 	@echo "   **IGNORING** $^ test..."

setup:
	@mkdir -p ActualOutputs
	fusermount -q -u $(FUSE_FILE) || true # tear down FUSE filesystem if one is somehow still running

# a "phony" target to run the program, capture its output and compare against expected output
# this is used for programs that don't take any arguments or need fancy setup/teardown
%.ok: %.bin setup
	@echo "   Testing $(basename $<)..."
	@python3 timeout.py 5s $(DETTRACE) ./$< > ActualOutputs/$(basename $<).output
	@python3 timeout.py 5s $(DETTRACE) ./$< > ActualOutputs/$(basename $<).output2
# Require exactly the same output for consecutive runs on the same machine:
	@$(DIFF_CMD) ActualOutputs/$(basename $<).output ActualOutputs/$(basename $<).output2 || \
          (echo "ERROR: NONDETERMINISM detected between runs 1 and 2."; exit 1)
# Allow some lee-way for currently non-PORTABLE output.
# Note this will not allow EMPTY ExpectedOutputs:
	@grep -v NONPORTABLE ActualOutputs/$(basename $<).output   > ActualOutputs/$(basename $<).output.stripped
	@grep -v NONPORTABLE ExpectedOutputs/$(basename $<).output > ExpectedOutputs/$(basename $<).output.stripped
	@$(DIFF_CMD) ActualOutputs/$(basename $<).output.stripped ExpectedOutputs/$(basename $<).output.stripped || \
          (echo "ERROR: ACTUAL output (above) did not match EXPECTED (below)."; exit 1)
	@if grep -q NONPORTABLE ExpectedOutputs/$(basename $<).output; then \
	  grep NONPORTABLE ActualOutputs/$(basename $<).output   > ActualOutputs/$(basename $<).output.nonport || true; \
	  grep NONPORTABLE ExpectedOutputs/$(basename $<).output > ExpectedOutputs/$(basename $<).output.nonport || true; \
	  $(DIFF_CMD) ActualOutputs/$(basename $<).output.nonport ExpectedOutputs/$(basename $<).output.nonport || echo "WARNING: differences in NONPORTABLE sections of output."; fi

# SHELL_SCRIPTS tests:
%.ok: %.sh setup
	@echo "   Testing script $(basename $<)..."
#       Redirect both stdout and stderr (danger?):
	@$(DETTRACE) ./$< > ActualOutputs/$(basename $<).output 2>&1
	@$(DIFF_CMD) ActualOutputs/$(basename $<).output ExpectedOutputs/$(basename $<).output

# Linux utilities, which in general need to be run with apropriate flags and/or setup/teardown

# Verify calling tar twice after updating the timestamps returns the same results.
#tars.ok:
#	@echo "   Testing $@..."
#Compile one directory up to having "tar2" tar "tar1".
# @$(DETTRACE) bash -c "make clean && make && tar -cf ../myTar.tar ."
# @$(DETTRACE) bash -c "make clean && make && tar -cf ../myTar2.tar ."
# @diff ../myTar.tar ../myTar2.tar
# @rm ../myTar.tar ../myTar2.tar

# Verify relative timestamps are the same under dettrace and not.
relativeTimeStamps1.ok:
	@echo "   Testing $@..."
	@bash -c "diff <(ls -t .) <(python3 timeout.py 5s $(DETTRACE) ls -t .)"


# Verify creating a new file puts that file first in the list.
relativeTimeStamps2.ok:
	@echo "   Testing $@..."
	@bash -c 'diff <(python3 timeout.py 5s $(DETTRACE) bash -c "touch temp.txt && ls -t . | head -n 1") <(touch temp.txt && ls -t . | head -n 1)'

getdents.ok: getdents.bin
	@echo "   Testing $(basename $<)..."
	@python3 timeout.py 5s $(DETTRACE) ./$< > ActualOutputs/$(basename $<).output.1
	@python3 timeout.py 5s $(DETTRACE) ./$< > ActualOutputs/$(basename $<).output.2
	@diff ActualOutputs/$(basename $<).output.1 ActualOutputs/$(basename $<).output.2

getdents64.ok: getdents64.bin
	@echo "   Testing $(basename $<)..."
	@python3 timeout.py 5s $(DETTRACE) ./$< > ActualOutputs/$(basename $<).output.1
	@python3 timeout.py 5s $(DETTRACE) ./$< > ActualOutputs/$(basename $<).output.2
	@diff ActualOutputs/$(basename $<).output.1 ActualOutputs/$(basename $<).output.2

sshkeygen.ok:
	@echo "   Testing ssh-keygen..."
	@rm -f thisKey thisKey.pub
	@python3 timeout.py 5s $(DETTRACE) ssh-keygen -f thisKey -N \"\" > ActualOutputs/sshkeygen.output
	@$(DIFF_CMD) ActualOutputs/sshkeygen.output ExpectedOutputs/sshkeygen.output

grep.ok:
	@echo "   Testing grep..."
# Erases original grepTestFile
	@echo "abcd" > grepTestFile
	@echo "bcde" >> grepTestFile
	@echo "helloworld" >> grepTestFile
	@echo "abcdefghi" >> grepTestFile
	@echo "acegik" >> grepTestFile
	@grep "bcd" grepTestFile > ExpectedOutputs/grep.output
	@python3 timeout.py 5s $(DETTRACE) grep "bcd" grepTestFile > ActualOutputs/grep.output
	@$(DIFF_CMD) ActualOutputs/grep.output ExpectedOutputs/grep.output

sed.ok:
	@echo "   Testing sed..."
	@rm -rf ActualOutputs/sed.output
	@python3 timeout.py 5s $(DETTRACE) echo "hello" > ActualOutputs/sed.output
	@python3 timeout.py 5s $(DETTRACE) echo "world" >> ActualOutputs/sed.output
	@python3 timeout.py 5s $(DETTRACE) 'sed -i "1 a big" ActualOutputs/sed.output'
	@python3 timeout.py 5s $(DETTRACE) 'sed -i "s/world/sun/" ActualOutputs/sed.output'
	@python3 timeout.py 5s $(DETTRACE) 'sed -i "2 d" ActualOutputs/sed.output'
	@python3 timeout.py 5s $(DETTRACE) 'sed -i "2 a moon" ActualOutputs/sed.output'
	@python3 timeout.py 5s $(DETTRACE) 'sed -i "/moon/ i hello" ActualOutputs/sed.output'
	@$(DIFF_CMD) ActualOutputs/sed.output ExpectedOutputs/sed.output

more.ok:
	@echo "   Testing more..."
	@rm -rf moreTestFile
	@python3 timeout.py 5s $(DETTRACE) echo "line 0" >> moreTestFile
	@python3 timeout.py 5s $(DETTRACE) echo "line 1" >> moreTestFile
	@python3 timeout.py 5s $(DETTRACE) echo "line 2" >> moreTestFile
	@python3 timeout.py 5s $(DETTRACE) echo "line 3" >> moreTestFile
	@python3 timeout.py 5s $(DETTRACE) echo "line 4" >> moreTestFile
	@python3 timeout.py 5s $(DETTRACE) echo "line 5" >> moreTestFile
	@python3 timeout.py 5s $(DETTRACE) echo "line 6" >> moreTestFile
	@python3 timeout.py 5s $(DETTRACE) echo "line 7" >> moreTestFile
	@python3 timeout.py 5s $(DETTRACE) echo "line 8" >> moreTestFile
	@python3 timeout.py 5s $(DETTRACE) echo "line 9" >> moreTestFile
	@python3 timeout.py 5s $(DETTRACE) more moreTestFile > ActualOutputs/more.output
	@python3 timeout.py 5s $(DETTRACE) more moreTestFile > ExpectedOutputs/more.output
	@$(DIFF_CMD) ActualOutputs/more.output ExpectedOutputs/more.output

less.ok:
	@echo "   Testing less..."
	@rm -rf lessTestFile
	@python3 timeout.py 5s $(DETTRACE) echo "line 0" >> lessTestFile
	@python3 timeout.py 5s $(DETTRACE) echo "line 1" >> lessTestFile
	@python3 timeout.py 5s $(DETTRACE) echo "line 2" >> lessTestFile
	@python3 timeout.py 5s $(DETTRACE) echo "line 3" >> lessTestFile
	@python3 timeout.py 5s $(DETTRACE) echo "line 4" >> lessTestFile
	@python3 timeout.py 5s $(DETTRACE) echo "line 5" >> lessTestFile
	@python3 timeout.py 5s $(DETTRACE) echo "line 6" >> lessTestFile
	@python3 timeout.py 5s $(DETTRACE) echo "line 7" >> lessTestFile
	@python3 timeout.py 5s $(DETTRACE) echo "line 8" >> lessTestFile
	@python3 timeout.py 5s $(DETTRACE) echo "line 9" >> lessTestFile
	@python3 timeout.py 5s $(DETTRACE) less lessTestFile > ActualOutputs/less.output
	@$(DIFF_CMD) ActualOutputs/less.output ExpectedOutputs/less.output

ls.ok:
	@echo "   Testing ls..."
	@rm -rf lsTestDirectory
	@python3 timeout.py 5s $(DETTRACE) mkdir lsTestDirectory
	@python3 timeout.py 5s $(DETTRACE) mkdir lsTestDirectory/foo
	@python3 timeout.py 5s $(DETTRACE) touch lsTestDirectory/hello
	@python3 timeout.py 5s $(DETTRACE) mkdir lsTestDirectory/foo/bar
	@python3 timeout.py 5s $(DETTRACE) touch lsTestDirectory/foo/world
	@python3 timeout.py 5s $(DETTRACE) ls -R lsTestDirectory > ActualOutputs/ls.output
	@$(DIFF_CMD) ActualOutputs/ls.output ExpectedOutputs/ls.output

sh.ok:
	@echo "   Testing sh..."
	@rm -rf shTestFile
	@echo ps \-p '$$$$' \| tail \-1 \| mawk \'\{ print '$$'4 \}\' > shTestFile
	@python3 timeout.py 5s $(DETTRACE) sh shTestFile > ActualOutputs/sh.output
	@$(DIFF_CMD) ActualOutputs/sh.output ExpectedOutputs/sh.output

cat.ok:
	@echo "   Testing cat..."
	@rm -rf catTestFile
	@echo "First" >> catTestFile
	@echo "" >> catTestFile
	@echo "Second" >> catTestFile
	@echo "Third" >> catTestFile
	@echo "" >> catTestFile
	@echo "Fourth" >> catTestFile
	@echo "Fifth" >> catTestFile
	@echo "Sixth" >> catTestFile
	@python3 timeout.py 5s $(DETTRACE) cat -ne catTestFile > ActualOutputs/cat.output
	@$(DIFF_CMD) ActualOutputs/cat.output ExpectedOutputs/cat.output

# Other DetTrace tests, with non-trivial invocation or cleanup

deadlockingPipe.ok: deadlockingPipe.bin
	@echo "   Testing $(basename $<)..."
#	ignore expected error when DetTrace detects the deadlock
	@($(DETTRACE) ./$< || true) 2> ActualOutputs/$(basename $<).output
	@$(DIFF_CMD) ActualOutputs/$(basename $<).output ExpectedOutputs/$(basename $<).output

# FUSE tests for read/write retrying

# 1-file "filesystem" using FUSE (https://github.com/libfuse/libfuse) that only reads/writes 1 byte at a time
partialfs: partialfs.c
	@$(CC) $< -Wall -g -D_FILE_OFFSET_BITS=64 -lfuse -pthread -o $@

FUSE_FILE=file.fuse
fuse-%.ok: fuse-%.bin partialfs
	@echo "   Testing fuse variant: $(basename $<)..."
	@truncate --size=0 $(FUSE_FILE)
	@./partialfs -o direct_io $(FUSE_FILE) # launch FUSE filesystem
	@python3 timeout.py 5s $(DETTRACE) ./$< $(FUSE_FILE) > ActualOutputs/$(basename $<).output
	@fusermount -q -u $(FUSE_FILE) # tear down FUSE filesystem
	@$(DIFF_CMD) ActualOutputs/$(basename $<).output ExpectedOutputs/$(basename $<).output

alarm-nohandler.ok: alarm-nohandler.bin
	@echo "   Testing $(basename $<)..."
	@($(DETTRACE) ./$< || if [ $$? -ne 142 ]; then echo "unexpected exit code"; fi ) > ActualOutputs/$(basename $<).output
	@$(DIFF_CMD) ActualOutputs/$(basename $<).output ExpectedOutputs/$(basename $<).output

alarm-resethand.ok: alarm-resethand.bin
	@echo "   Testing $(basename $<)..."
	@($(DETTRACE) ./$< || if [ $$? -ne 142 ]; then echo "unexpected exit code"; fi ) > ActualOutputs/$(basename $<).output
	@$(DIFF_CMD) ActualOutputs/$(basename $<).output ExpectedOutputs/$(basename $<).output

# Parameterized pipe tests. Each of these tests has a parent and a child process
# connected via a pipe, and either/both may read/write from the pipe. Syntax:
# pWcR means parent writes, child reads
# pcWpR means parent+child both write, parent reads
# and so on...

pipe-pWcR.bin: pipe-rw.c
	$(CC) $^ -Wall -g -DPARENT_WRITE=true -DCHILD_READ=true -o $@
pipe-cWpR.bin: pipe-rw.c
	$(CC) $^ -Wall -g -DCHILD_WRITE=true -DPARENT_READ=true -o $@
pipe-pcWpR.bin: pipe-rw.c
	$(CC) $^ -Wall -g -DPARENT_WRITE=true -DCHILD_WRITE=true -DPARENT_READ=true -o $@
pipe-pWpcR.bin: pipe-rw.c
	$(CC) $^ -Wall -g -DPARENT_WRITE=true -DPARENT_READ=true -DCHILD_READ=true -o $@
pipe-cWpcR.bin: pipe-rw.c
	$(CC) $^ -Wall -g -DCHILD_WRITE=true -DPARENT_READ=true -DCHILD_READ=true -o $@
pipe-pcWpcR.bin: pipe-rw.c
	$(CC) $^ -Wall -g -DPARENT_WRITE=true -DCHILD_WRITE=true -DPARENT_READ=true -DCHILD_READ=true -o $@

mq.bin: mq.c
	$(CC) $^ -o $@ -Wall -g -O2 -lrt

# parameterized getitimer/setitimer tests

getitimer-real.bin: getitimer.c
	clang $^ -Wall -g -DWHICH_ITIMER=ITIMER_REAL -o $@
getitimer-virtual.bin: getitimer.c
	clang $^ -Wall -g -DWHICH_ITIMER=ITIMER_VIRTUAL -o $@
getitimer-prof.bin: getitimer.c
	clang $^ -Wall -g -DWHICH_ITIMER=ITIMER_PROF -o $@
setitimer-real.bin: setitimer.c
	clang $^ -Wall -g -DWHICH_ITIMER=ITIMER_REAL -DSIGNAL_TO_HANDLE=SIGALRM -o $@
setitimer-virtual.bin: setitimer.c
	clang $^ -Wall -g -DWHICH_ITIMER=ITIMER_VIRTUAL -DSIGNAL_TO_HANDLE=SIGVTALRM -o $@
setitimer-prof.bin: setitimer.c
	clang $^ -Wall -g -DWHICH_ITIMER=ITIMER_PROF -DSIGNAL_TO_HANDLE=SIGPROF -o $@

alarm-ignore.ok: alarm-ignore.bin
	@echo "   Testing $(basename $<)..."
#	HACK: check that we time out as expected (247 == -9 means received SIGKILL due to timeout)
	@python3 timeout.py 2s $(DETTRACE) ./$< || [ $$? -eq 247 ]

kill.ok: kill.bin
	@for s in $$(seq 1 64); do echo "   Testing $(basename $<) $$s..." && (python3 timeout.py 5s $(DETTRACE) ./$< $$s 2> ActualOutputs/$(basename $<)-$$s.output || true) && $(DIFF_CMD) ActualOutputs/$(basename $<)-$$s.output ExpectedOutputs/$(basename $<).output ; done

# NB: we allow SIGABRT to be sent via tgkill, to support abort() calls
tgkill.ok: tgkill.bin
	@for s in 1 2 3 4 5 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30 31 32 33 34 35 36 37 38 39 40 41 42 43 44 45 46 47 48 49 50 51 52 53 54 55 56 57 58 59 60 61 62 63 64; do echo "   Testing $(basename $<) $$s..." && (python3 timeout.py 5s $(DETTRACE) ./$< $$s 2> ActualOutputs/$(basename $<)-$$s.output || true) && $(DIFF_CMD) ActualOutputs/$(basename $<)-$$s.output ExpectedOutputs/$(basename $<).output ; done
#	@for s in 1 2; do echo "   Testing $(basename $<) $$s..." && (python3 timeout.py 5s $(DETTRACE) ./$< $$s 2> ActualOutputs/$(basename $<)-$$s.output || true) && $(DIFF_CMD) ActualOutputs/$(basename $<)-$$s.output ExpectedOutputs/$(basename $<).output ; done

exec-mkstemp.ok: exec-mkstemp.bin
	@echo "   Testing $(basename $<)..."
	@$(DETTRACE) ./exec-mkstemp.bin test > ActualOutputs/$(basename $<).output && $(DIFF_CMD) ActualOutputs/$(basename $<).output ExpectedOutputs/$(basename $<).output

shuf.ok:
	@echo "   Testing shuf..."
	@$(DETTRACE) shuf Makefile --output .shuf.1.Makefile
	@$(DETTRACE) shuf Makefile --output .shuf.2.Makefile
	@diff .shuf.1.Makefile .shuf.2.Makefile
	@rm -f .shuf.[12].Makefile

# Not a DetTrace test case per se. A small ptrace implementation that validates
# that structs have the same size from the tracee and from ptrace, i.e., that
# going through libc does not change struct layout.
check-struct-layout.bin: check-struct-layout.c
	clang -Wall $^ -o $@ -lrt

.PHONY: build setup run clean test
clean:
	$(RM) $(FUSE_FILE)
	$(RM) *.bin partialfs ActualOutputs/*
