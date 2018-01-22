OBJECTS=simpleFork inverseFork nestedFork

all: $(OBJECTS)

$(OBJECTS):%:%.c
	g++ $< -o $@

.PHONY: clean
clean:
	$(RM) $(OBJECTS)
