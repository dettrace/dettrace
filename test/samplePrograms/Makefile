OBJECTS=simpleFork inverseFork nestedFork vfork clock_gettime helloWorld getpid

all: $(OBJECTS)

$(OBJECTS):%:%.c
	g++ $< -o $@

.PHONY: clean
clean:
	$(RM) $(OBJECTS)
