CXX = g++
# Using features from the C++17 Standard: pair and pattern matching with auto.
DEBUG =  -O0 -g
CXXFLAGS = $(DEBUG) -std=c++1z -Wall $(INCLUDE)

src = $(wildcard *.cpp)
obj = $(src:.cpp=.o)
dep = $(obj:.o=.d)

all: systemCallTests

systemCallTests: $(obj)
	$(CXX) $^ -o $@

run:
	../../dettrace/dettrace ./systemCallTests

-include $(dep)

# rule to generate a dep file by using the C preprocessor
# (see man cpp for details on the -MM and -MT options)
%.d: %.cpp
	@cpp $(CXXFLAGS) $< -MM -MT $(@:.d=.o) >$@

.PHONY: clean
clean:
	$(RM) $(obj)
	$(RM) $(dep)
	$(RM) systemCallTests
# Credits to the awesome makefile guide:
# http://nuclear.mutantstargoat.com/articles/make/
