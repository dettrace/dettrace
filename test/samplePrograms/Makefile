# binaries that are simple to build (1 source file, same name as binary)
SIMPLE_BUILD_BINARIES=simpleFork inverseFork nestedFork vfork clock_gettime getpid callSshKeygen uname pipe getRandom waitOnChild fchownat forkAndPipe deadlockingPipe helloWorld 2writers1reader fuse-single-read fuse-single-write
PIPE_BINARIES=pipe-pWcR pipe-cWpR pipe-pcWpR pipe-pWpcR pipe-cWpcR pipe-pcWpcR
LINUX_UTILITIES=sshkeygen

DIFF_CMD=diff --brief

build: $(SIMPLE_BUILD_BINARIES) $(PIPE_BINARIES)


run: $(patsubst %, %.ok, $(SIMPLE_BUILD_BINARIES)) $(patsubst %, %.ok, $(PIPE_BINARIES)) $(patsubst %, %.ok, $(LINUX_UTILITIES))

# compile each sample program binary
$(SIMPLE_BUILD_BINARIES): %: %.c
	gcc $< -Wall -g -o $@

setup:
	@mkdir -p ActualOutputs
	fusermount -q -u $(FUSE_FILE) || true # tear down FUSE filesystem if one is somehow still running

# a "phony" target to run the program, capture its output and compare against expected output
# this is used for programs that don't take any arguments or need fancy setup/teardown
%.ok: % setup
	@echo "   Testing $<..."
	@python3 timeout.py 5s ../../bin/dettrace ./$< > ActualOutputs/$<.output
	@$(DIFF_CMD) ActualOutputs/$<.output ExpectedOutputs/$<.output

# Linux utilities, which in general need to be run with apropriate flags and/or setup/teardown

sshkeygen.ok:
	@echo "   Testing ssh-keygen..."
	@rm -f thisKey thisKey.pub
	@../../bin/dettrace ssh-keygen -f thisKey -N "" > ActualOutputs/sshkeygen.output
	@$(DIFF_CMD) ActualOutputs/sshkeygen.output ExpectedOutputs/sshkeygen.output


# Other DetTrace tests, with non-trivial invocation or cleanup

deadlockingPipe.ok: deadlockingPipe
	@echo "   Testing $<..."
#	ignore expected error when DetTrace detects the deadlock
	@(../../bin/dettrace ./$< || true) 2> ActualOutputs/$<.output
	@$(DIFF_CMD) ActualOutputs/$<.output ExpectedOutputs/$<.output

# FUSE tests for read/write retrying

# 1-file "filesystem" using FUSE (https://github.com/libfuse/libfuse) that only reads/writes 1 byte at a time
partialfs: partialfs.c
	@gcc $< -Wall -g -D_FILE_OFFSET_BITS=64 -lfuse -pthread -o $@

FUSE_FILE=file.fuse
fuse-%.ok: fuse-% partialfs
	@echo "   Testing $<..."
	@truncate --size=0 $(FUSE_FILE)
	@./partialfs -o direct_io $(FUSE_FILE) # launch FUSE filesystem
	@../../bin/dettrace --nocontainer ./$< $(FUSE_FILE) > ActualOutputs/$<.output
	@fusermount -q -u $(FUSE_FILE) # tear down FUSE filesystem
	@$(DIFF_CMD) ActualOutputs/$<.output ExpectedOutputs/$<.output

# Parameterized pipe tests. Each of these tests has a parent and a child process
# connected via a pipe, and either/both may read/write from the pipe. Syntax:
# pWcR means parent writes, child reads
# pcWpR means parent+child both write, parent reads
# and so on...

pipe-pWcR: pipe-rw.c
	gcc $^ -Wall -g -DPARENT_WRITE=true -DCHILD_READ=true -o $@
pipe-cWpR: pipe-rw.c
	gcc $^ -Wall -g -DCHILD_WRITE=true -DPARENT_READ=true -o $@
pipe-pcWpR: pipe-rw.c
	gcc $^ -Wall -g -DPARENT_WRITE=true -DCHILD_WRITE=true -DPARENT_READ=true -o $@
pipe-pWpcR: pipe-rw.c
	gcc $^ -Wall -g -DPARENT_WRITE=true -DPARENT_READ=true -DCHILD_READ=true -o $@
pipe-cWpcR: pipe-rw.c
	gcc $^ -Wall -g -DCHILD_WRITE=true -DPARENT_READ=true -DCHILD_READ=true -o $@
pipe-pcWpcR: pipe-rw.c
	gcc $^ -Wall -g -DPARENT_WRITE=true -DCHILD_WRITE=true -DPARENT_READ=true -DCHILD_READ=true -o $@

.PHONY: build setup run clean
clean:
	$(RM) $(SIMPLE_BUILD_BINARIES) partialfs $(PIPE_BINARIES)
