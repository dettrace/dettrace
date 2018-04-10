# binaries that are simple to build (1 source file, same name as binary)
SIMPLE_BUILD_BINARIES=simpleFork inverseFork nestedFork vfork clock_gettime getpid uname alarm pipe pipe-multiwrite getRandom callSshKeygen waitOnChild fchownat forkAndPipe deadlockingPipe helloWorld 2writers1reader fuse-single-read fuse-single-write


build: $(SIMPLE_BUILD_BINARIES)


run: $(patsubst %, %.ok, $(SIMPLE_BUILD_BINARIES))

# compile each sample program binary
$(SIMPLE_BUILD_BINARIES): %: %.c
	gcc $< -Wall -g -o $@

setup:
	@mkdir -p ActualOutputs
# tear down FUSE filesystem if one is still running
#	-killall --quiet partialfs

# a "phony" target to run the program, capture its output and compare against expected output
%.ok: % setup
	@echo "   Testing $<..."
	@../../bin/dettrace ./$< > ActualOutputs/$<.output
	@diff --brief ActualOutputs/$<.output ExpectedOutputs/$<.output

# FUSE tests for read/write retrying

# 1-file "filesystem" using FUSE (https://github.com/libfuse/libfuse) that only reads/writes 1 byte at a time
partialfs: partialfs.c
	gcc $< -Wall -g -D_FILE_OFFSET_BITS=64 -lfuse -pthread -o $@

FUSE_FILE=file.fuse
fuse-%.ok: fuse-% partialfs
	@echo "   Testing $<..."
	@truncate --size=0 $(FUSE_FILE)
	@./partialfs -o direct_io $(FUSE_FILE) # launch FUSE filesystem
	@../../bin/dettrace --nocontainer ./$< $(FUSE_FILE) > ActualOutputs/$<.output
	@killall partialfs # tear down FUSE filesystem
	@diff --brief ActualOutputs/$<.output ExpectedOutputs/$<.output

.PHONY: build setup run clean
clean:
	$(RM) $(SIMPLE_BUILD_BINARIES) partialfs
