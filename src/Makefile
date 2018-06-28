CXX = clang++
CC= clang

DEBUG =  -O0 -g
CXXFLAGS = $(DEBUG) -std=c++14 -Wall $(INCLUDE)
CFLAGS = $(DEBUG) -Wall -Wshadow $(INCLUDE)
LIBS = -pthread -lseccomp -L ../lib/lib64

# Libdet only.
LIBDETFLAGS= -g -Wall -Wextra -Wconversion -fPIC -shared -Wl,--no-as-needed -std=c99
LIBDETLIBS=-ldl -lm

INCLUDE = -I ../include/ -I ../lib/include

src = $(wildcard *.cpp)
obj = $(src:.cpp=.o)
dep = $(obj:.o=.d)

all: dettrace libdet.so
all-static: dettrace-static libdet.so

dettrace: $(obj) $(libs)
	$(CXX) $(CXXFLAGS) $^ -o $@ $(LIBS)

dettrace-static: $(obj) $(libs)
	$(CXX) $(CXXFLAGS) -static $^ -o $@ $(LIBS)

-include $(dep)

# rule to generate a dep file by using the C preprocessor
# (see man cpp for details on the -MM and -MT options)
%.d: %.cpp
	@$(CXX) $(CXXFLAGS) $< -MM -MT $(@:.d=.o) >$@


libdet.so: libdet.c
	$(CC) $(LIBDETFLAGS) -o libdet.so libdet.c $(LIBDETLIBS)

.PHONY: clean
clean:
	$(RM) $(obj)
	$(RM) $(dep)
	$(RM) dettrace libdet.so
# Credits to the awesome makefile guide:
# http://nuclear.mutantstargoat.com/articles/make/
