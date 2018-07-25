# binaries that are simple to build (1 source file, same name as binary)
SIMPLE_ROOTS=simpleFork inverseFork nestedFork vfork clock_gettime getpid uname pipe getRandom waitOnChild fchownat forkAndPipe deadlockingPipe helloWorld 2writers1reader fuse-single-read fuse-single-write open openat creat  sigsegv sigill sigabrt kill tgkill selectWithoutTimeout selectWithTimeout getdents getdents64 pollWithoutTimeout pollWithPositiveTimeout pollWithNegativeTimeout rdtsc rdtscp nanosleep
# cpuid simpleThreads multipleThreads
SIMPLE_BINARIES= $(addsuffix .bin,$(SIMPLE_ROOTS))

# binaries for pipe tests, they use a parameterized build
PIPE_ROOTS= pipe-pWcR pipe-cWpR pipe-pcWpR pipe-pWpcR pipe-cWpcR pipe-pcWpcR
PIPE_BINARIES= $(addsuffix .bin,$(PIPE_ROOTS))

# built-in Linux utilities, nothing to build
LINUX_UTILITIES=sshkeygen grep sed more less ls sh cat # relativeTimeStamps1 relativeTimeStamps2 tars to fix one day.

# tests of random number generator insns, need special build flags
BROADWELL_ROOTS= rdrand rdseed
BROADWELL_BINARIES= $(addsuffix .bin,$(BROADWELL_ROOTS))

DETTRACE=../../bin/dettrace
DIFF_CMD=diff

build: $(SIMPLE_BINARIES) $(PIPE_BINARIES) $(BROADWELL_BINARIES)

CC=clang

test: run
run: $(patsubst %.bin, %.ok, $(SIMPLE_BINARIES)) $(patsubst %.bin, %.ok, $(PIPE_BINARIES)) $(patsubst %, %.ok, $(LINUX_UTILITIES)) $(patsubst %.bin, %.ok, $(BROADWELL_BINARIES))

# compile each sample program binary
$(SIMPLE_BINARIES): %.bin: %.c
	$(CC) $< -Wall -g -o $@ -pthread -std=gnu99

# HW RNG tests need >=broadwell codegen
$(BROADWELL_BINARIES): %.bin: %.c
	$(CC) $< -Wall -g -o $@ -pthread -std=gnu99 -march=broadwell

# NB: disable special cpu insn tests for now
rdrand.ok: rdrand.bin
	@echo "   **IGNORING** $^ test..."
rdseed.ok: rdseed.bin
	@echo "   **IGNORING** $^ test..."
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

getdents.ok: getdents
	@echo "   Testing $<..."
	@python3 timeout.py 5s $(DETTRACE) ./$< > ActualOutputs/$<.output.1
	@python3 timeout.py 5s $(DETTRACE) ./$< > ActualOutputs/$<.output.2
	@diff ActualOutputs/$<.output.1 ActualOutputs/$<.output.2

getdents64.ok: getdents64
	@echo "   Testing $<..."
	@python3 timeout.py 5s $(DETTRACE) ./$< > ActualOutputs/$<.output.1
	@python3 timeout.py 5s $(DETTRACE) ./$< > ActualOutputs/$<.output.2
	@diff ActualOutputs/$<.output.1 ActualOutputs/$<.output.2

sshkeygen.ok:
	@echo "   Testing ssh-keygen..."
	@rm -f thisKey thisKey.pub
	@python3 timeout.py 5s $(DETTRACE) 'ssh-keygen -f thisKey -N ""' > ActualOutputs/sshkeygen.output
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

deadlockingPipe.ok: deadlockingPipe
	@echo "   Testing $<..."
#	ignore expected error when DetTrace detects the deadlock
	@($(DETTRACE) ./$< || true) 2> ActualOutputs/$<.output
	@$(DIFF_CMD) ActualOutputs/$<.output ExpectedOutputs/$<.output

# FUSE tests for read/write retrying

# 1-file "filesystem" using FUSE (https://github.com/libfuse/libfuse) that only reads/writes 1 byte at a time
partialfs: partialfs.c
	@$(CC) $< -Wall -g -D_FILE_OFFSET_BITS=64 -lfuse -pthread -o $@

FUSE_FILE=file.fuse
fuse-%.ok: fuse-%.bin partialfs
	@echo "   Testing fuse variant: $(basename $<)..."
	@truncate --size=0 $(FUSE_FILE)
	@./partialfs -o direct_io $(FUSE_FILE) # launch FUSE filesystem
	@python3 timeout.py 5s $(DETTRACE) --no-container ./$< $(FUSE_FILE) > ActualOutputs/$(basename $<).output
	@fusermount -q -u $(FUSE_FILE) # tear down FUSE filesystem
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

kill.ok: kill.bin
	@for s in $$(seq 1 64); do echo "   Testing $(basename $<) $$s..." && (python3 timeout.py 5s $(DETTRACE) ./$< $$s 2> ActualOutputs/$(basename $<)-$$s.output || true) && $(DIFF_CMD) ActualOutputs/$(basename $<)-$$s.output ExpectedOutputs/$(basename $<).output ; done

# NB: we allow SIGABRT to be sent via tgkill, to support abort() calls
tgkill.ok: tgkill.bin
	@for s in 1 2 3 4 5 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30 31 32 33 34 35 36 37 38 39 40 41 42 43 44 45 46 47 48 49 50 51 52 53 54 55 56 57 58 59 60 61 62 63 64; do echo "   Testing $(basename $<) $$s..." && (python3 timeout.py 5s $(DETTRACE) ./$< $$s 2> ActualOutputs/$(basename $<)-$$s.output || true) && $(DIFF_CMD) ActualOutputs/$(basename $<)-$$s.output ExpectedOutputs/$(basename $<).output ; done

.PHONY: build setup run clean test
clean:
	$(RM) $(FUSE_FILE)
	$(RM) *.bin partialfs 
