CXX = g++
# Using features from the C++17 Standard: pair and pattern matching with auto.
DEBUG =  -O0 -g
CXXFLAGS = $(DEBUG) -std=c++1z -Wall $(INCLUDE)
LIBS = -pthread -lseccomp

# Libdet only.
LIBDETFLAGS= -g -Wall -Wextra -Wconversion -fPIC -shared -Wl,--no-as-needed -std=c++1z
LIBDETLIBS=-ldl -lm

INCLUDE = -I ../include/

src = $(wildcard *.cpp)
obj = $(src:.cpp=.o)
dep = $(obj:.o=.d)

all: dettrace libdet.so

dettrace: $(obj) $(libs)
	$(CXX) $(CXXFLAGS) $^ -o $@ $(LIBS)

-include $(dep)

# rule to generate a dep file by using the C preprocessor
# (see man cpp for details on the -MM and -MT options)
%.d: %.cpp
	@cpp $(CXXFLAGS) $< -MM -MT $(@:.d=.o) >$@


libdet.so: libdet.cpp
	$(CXX) $(LIBDETFLAGS) -o libdet.so libdet.cpp $(LIBDETLIBS)

.PHONY: clean
clean:
	$(RM) $(obj)
	$(RM) $(dep)
	$(RM) dettrace libdet.so
# Credits to the awesome makefile guide:
# http://nuclear.mutantstargoat.com/articles/make/
