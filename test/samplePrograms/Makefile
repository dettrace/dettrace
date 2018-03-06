OBJECTS=simpleFork inverseFork nestedFork vfork clock_gettime getpid uname alarm

all: $(OBJECTS)

test:
	./inverseFork
	./nestedFork
	./simpleFork
	./vfork
	./alarm

$(OBJECTS):%:%.c
	gcc $< -Wall -g -o $@

.PHONY: clean test
clean:
	$(RM) $(OBJECTS)
