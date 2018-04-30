CXX = g++
DEBUG =  -O0 -g
CXXFLAGS = $(DEBUG) -std=c++14 -Wall $(INCLUDE)

src = $(wildcard *.cpp)
obj = $(src:.cpp=.o)
dep = $(obj:.o=.d)

build: systemCallTests

systemCallTests: $(obj)
	$(CXX) $^ -o $@

run: systemCallTests
	../../bin/dettrace ./systemCallTests -r console | tee .unit-test-output
	@grep --quiet "All tests passed" .unit-test-output

-include $(dep)

# rule to generate a dep file by using the C preprocessor
# (see man cpp for details on the -MM and -MT options)
%.d: %.cpp
	@cpp $(CXXFLAGS) $< -MM -MT $(@:.d=.o) >$@

.PHONY: clean build
clean:
	$(RM) $(obj)
	$(RM) $(dep)
	$(RM) systemCallTests
# Credits to the awesome makefile guide:
# http://nuclear.mutantstargoat.com/articles/make/
