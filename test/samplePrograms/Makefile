OBJECTS=simpleFork inverseFork nestedFork vfork clock_gettime getpid uname

all: $(OBJECTS)

test:
	./inverseFork
	./nestedFork
	./simpleFork
	./vfork

$(OBJECTS):%:%.c
	g++ $< -g -o $@

.PHONY: clean test
clean:
	$(RM) $(OBJECTS)
