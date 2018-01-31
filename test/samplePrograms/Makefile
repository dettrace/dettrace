OBJECTS=simpleFork inverseFork nestedFork vfork

all: $(OBJECTS)

$(OBJECTS):%:%.c
	g++ $< -o $@

.PHONY: clean
clean:
	$(RM) $(OBJECTS)
