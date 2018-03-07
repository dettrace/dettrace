OBJECTS=simpleFork inverseFork nestedFork vfork clock_gettime getpid uname alarm pipe pipe-multiwrite

all: $(OBJECTS)

test:
	./inverseFork
	./nestedFork
	./simpleFork
	./vfork
	./alarm
	./pipe
	./pipe-multiwrite

$(OBJECTS):%:%.c
	gcc $< -Wall -g -o $@

.PHONY: clean test
clean:
	$(RM) $(OBJECTS)
