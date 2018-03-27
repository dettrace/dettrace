OBJECTS=simpleFork inverseFork nestedFork vfork clock_gettime getpid uname alarm pipe pipe-multiwrite getRandom callSshKeygen waitOnChild fchownat forkAndPipe


all: $(OBJECTS)

$(OBJECTS):%:%.c
	gcc $< -Wall -g -o $@

.PHONY: clean test
clean:
	$(RM) $(OBJECTS)
