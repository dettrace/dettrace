CXXFLAGS = -g -Wall -O0 -std=c++14
CXX =g++
src = $(wildcard *.cpp)
obj = $(src:.cpp=.o)
dep = $(obj:.o=.d)  # one dependency file for each source

detTrace: $(obj)
	$(CXX) $(CXXFLAGS) $^ -o $@

-include $(dep)   # include all dep files in the makefile

# rule to generate a dep file by using the C preprocessor
# (see man cpp for details on the -MM and -MT options)
%.d: %.cpp
	@cpp $(CXXFLAGS) $< -MM -MT $(@:.d=.o) >$@

.PHONY: clean
clean:
	@rm $(obj) detTrace
	@rm -f $(dep)

# Credits to the awesome makefile guide:
# http://nuclear.mutantstargoat.com/articles/make/
