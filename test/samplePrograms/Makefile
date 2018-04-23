# binaries that are simple to build (1 source file, same name as binary)
SIMPLE_BUILD_BINARIES=simpleFork inverseFork nestedFork vfork clock_gettime getpid callSshKeygen uname pipe getRandom waitOnChild fchownat forkAndPipe deadlockingPipe helloWorld 2writers1reader fuse-single-read fuse-single-write
PIPE_BINARIES=pipe-pWcR pipe-cWpR pipe-pcWpR pipe-pWpcR pipe-cWpcR pipe-pcWpcR
LINUX_UTILITIES=sshkeygen grep sed more less ls sh cat

DIFF_CMD=diff

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

grep.ok:
	@echo "   Testing grep..."
	@rm -rf "greptestfile"
	@echo "abcd" >> grepTestFile
	@echo "bcde" >> grepTestFile
	@echo "helloworld" >> grepTestFile
	@echo "abcdefghi" >> grepTestFile
	@echo "acegik" >> grepTestFile
	@../../bin/dettrace grep "bcd" grepTestFile > ActualOutputs/grep.output
	@$(DIFF_CMD) ActualOutputs/grep.output ExpectedOutputs/grep.output

sed.ok:
	@echo "   Testing sed..."
	@rm -rf ActualOutputs/sed.output
	@../../bin/dettrace echo "hello" > ActualOutputs/sed.output
	@../../bin/dettrace echo "world" >> ActualOutputs/sed.output
	@../../bin/dettrace sed -i "1 a big" ActualOutputs/sed.output
	@../../bin/dettrace sed -i "s/world/sun/" ActualOutputs/sed.output
	@../../bin/dettrace sed -i "2 d" ActualOutputs/sed.output
	@../../bin/dettrace sed -i "2 a moon" ActualOutputs/sed.output
	@../../bin/dettrace sed -i "/moon/ i hello" ActualOutputs/sed.output
	@$(DIFF_CMD) ActualOutputs/sed.output ExpectedOutputs/sed.output

more.ok:
	@echo "   Testing more..."
	@rm -rf moreTestFile
	@../../bin/dettrace echo "line 0" >> moreTestFile
	@../../bin/dettrace echo "line 1" >> moreTestFile
	@../../bin/dettrace echo "line 2" >> moreTestFile
	@../../bin/dettrace echo "line 3" >> moreTestFile
	@../../bin/dettrace echo "line 4" >> moreTestFile
	@../../bin/dettrace echo "line 5" >> moreTestFile
	@../../bin/dettrace echo "line 6" >> moreTestFile
	@../../bin/dettrace echo "line 7" >> moreTestFile
	@../../bin/dettrace echo "line 8" >> moreTestFile
	@../../bin/dettrace echo "line 9" >> moreTestFile
	@../../bin/dettrace more moreTestFile > ActualOutputs/more.output
	@$(DIFF_CMD) ActualOutputs/more.output ExpectedOutputs/more.output

less.ok:
	@echo "   Testing less..."
	@rm -rf lessTestFile
	@../../bin/dettrace echo "line 0" >> lessTestFile
	@../../bin/dettrace echo "line 1" >> lessTestFile
	@../../bin/dettrace echo "line 2" >> lessTestFile
	@../../bin/dettrace echo "line 3" >> lessTestFile
	@../../bin/dettrace echo "line 4" >> lessTestFile
	@../../bin/dettrace echo "line 5" >> lessTestFile
	@../../bin/dettrace echo "line 6" >> lessTestFile
	@../../bin/dettrace echo "line 7" >> lessTestFile
	@../../bin/dettrace echo "line 8" >> lessTestFile
	@../../bin/dettrace echo "line 9" >> lessTestFile
	@../../bin/dettrace less lessTestFile > ActualOutputs/less.output
	@$(DIFF_CMD) ActualOutputs/less.output ExpectedOutputs/less.output

ls.ok:
	@echo "   Testing ls..."
	@rm -rf lsTestDirectory
	@../../bin/dettrace mkdir lsTestDirectory
	@../../bin/dettrace mkdir lsTestDirectory/foo
	@../../bin/dettrace touch lsTestDirectory/hello
	@../../bin/dettrace mkdir lsTestDirectory/foo/bar
	@../../bin/dettrace touch lsTestDirectory/foo/world
	@../../bin/dettrace ls -R lsTestDirectory > ActualOutputs/ls.output
	@$(DIFF_CMD) ActualOutputs/ls.output ExpectedOutputs/ls.output

sh.ok:
	@echo "   Testing sh..."
	@rm -rf shTestFile
	@echo ps \-p '$$$$' \| tail \-1 \| mawk \'\{ print '$$'4 \}\' > shTestFile
	@../../bin/dettrace sh shTestFile > ActualOutputs/sh.output
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
	@../../bin/dettrace cat -ne catTestFile > ActualOutputs/cat.output
	@$(DIFF_CMD) ActualOutputs/cat.output ExpectedOutputs/cat.output

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
