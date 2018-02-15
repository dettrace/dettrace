OBJECTS=simpleFork inverseFork nestedFork vfork clock_gettime helloWorld getpid uname

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
