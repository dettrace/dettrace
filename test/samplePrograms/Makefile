OBJECTS=simpleFork inverseFork nestedFork vfork

all: $(OBJECTS)

test:
	./inverseFork
	./nestedFork
	./simpleFork
	./vfork

$(OBJECTS):%:%.c
	g++ $< -o $@

.PHONY: clean test
clean:
	$(RM) $(OBJECTS)
