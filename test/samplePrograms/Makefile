AUTO_BUILD_BINARIES=simpleFork inverseFork nestedFork vfork clock_gettime getpid uname alarm pipe pipe-multiwrite getRandom callSshKeygen

MANUAL_BUILD_BINARIES=


build: $(AUTO_BUILD_BINARIES) $(MANUAL_BUILD_BINARIES)

run: $(patsubst %, %.ok, $(AUTO_BUILD_BINARIES))

# compile each sample program binary
$(AUTO_BUILD_BINARIES): %: %.c
	gcc $< -Wall -g -o $@

# a "phony" target to run the program, capture its output and compare against expected output
%.ok: %
	@echo Testing $<...
	@mkdir -p ActualOutputs
	@../../bin/dettrace ./$< > ActualOutputs/$<.output
	@diff --brief ActualOutputs/$<.output ExpectedOutputs/$<.output

.PHONY: build run clean
clean:
	$(RM) $(AUTO_BUILD_BINARIES) $(MANUAL_BUILD_BINARIES)
