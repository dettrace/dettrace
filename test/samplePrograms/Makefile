OBJECTS=simpleFork inverseFork nestedFork vfork clock_gettime getpid uname alarm pipe pipe-multiwrite getRandom callSshKeygen


all: $(OBJECTS)

test:
	./inverseFork
	./nestedFork
	./simpleFork
	./vfork
	./alarm
	./pipe
	./pipe-multiwrite
	./getRandom
	./callSshKeygen

$(OBJECTS):%:%.c
	gcc $< -Wall -g -o $@

.PHONY: clean test
clean:
	$(RM) $(OBJECTS)
