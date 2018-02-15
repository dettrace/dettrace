OBJECTS=simpleFork inverseFork nestedFork vfork clock_gettime helloWorld getpid uname

all: $(OBJECTS)

$(OBJECTS):%:%.c
	g++ $< -g -o $@

.PHONY: clean
clean:
	$(RM) $(OBJECTS)
