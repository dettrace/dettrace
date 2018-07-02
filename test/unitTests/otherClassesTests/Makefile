CXX = g++
DEBUG =  -O0 -g
CXXFLAGS = $(DEBUG) -std=c++14 -Wall $(INCLUDE)

src = $(wildcard *.cpp)
obj = $(src:.cpp=.o)
dep = $(obj:.o=.d)

build: otherClassesTests

otherClassesTests: $(obj)
	$(CXX) $^ -o $@

run: otherClassesTests
	./otherClassesTests | tee .other-classes-test-output
	@grep --quiet "All tests passed" .other-classes-test-output

-include $(dep)

# rule to generate a dep file by using the C preprocessor
# (see man cpp for details on the -MM and -MT options)
%.d: %.cpp
	@$(CXX) $(CXXFLAGS) $< -MM -MT $(@:.d=.o) >$@

.PHONY: clean build
clean:
	$(RM) $(obj)
	$(RM) $(dep)
	$(RM) otherClassesTests
# Credits to the awesome makefile guide:
# http://nuclear.mutantstargoat.com/articles/make/
