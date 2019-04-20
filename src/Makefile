CXX = clang++
CC= clang

DEFINES=-D_GNU_SOURCE=1 -D_POSIX_C_SOURCE=20181101 -D__USE_XOPEN=1

CXXFLAGS =-g -O0 -std=c++14 -Wall $(INCLUDE) $(DEFINES)
CFLAGS =-g -O0 -Wall -Wshadow $(INCLUDE) $(DEFINES)
LIBS = -pthread -lseccomp -L ../lib/lib64

LIBCRYPTO=$(shell pkg-config --libs libcrypto)
LIBCRYPTO_STATIC=$(shell pkg-config --static --libs libcrypto)

LIBARCHIVE=$(shell pkg-config --libs libarchive)
LIBARCHIVE_STATIC=$(shell pkg-config --static --libs libarchive)

LIBELFIN=$(shell pkg-config --libs libelf++)
LIBELFIN_STATIC=$(shell pkg-config --static --libs libelf++)

# Libdet only.
LIBDETFLAGS= -g -O2 -Wall -Wextra -Wconversion -fPIC -shared -Wl,--no-as-needed -std=c99
LIBDETLIBS=-ldl -lm

LIBELFIN_CFLAGS = $(shell pkg-config --cflags libelf++)
INCLUDE = -I ../include/ -I ../lib/include $(LIBELFIN_CFLAGS)

src = $(wildcard *.cpp)
obj = $(src:.cpp=.o)
dep = $(obj:.o=.d)

all: dettrace
all-static: dettrace-static

dettrace: $(obj) $(libs)
	$(CXX) $(CXXFLAGS) $^ -o $@ $(LIBS) $(LIBARCHIVE) $(LIBELFIN) $(LIBCRYPTO)

dettrace-static: $(obj) $(libs)
	$(CXX) $(CXXFLAGS) -static $^ -o $@ $(LIBS) $(LIBARCHIVE_STATIC) $(LIBELFIN_STATIC) $(LIBCRYPTO_STATIC)

-include $(dep)

# rule to generate a dep file by using the C preprocessor
# (see man cpp for details on the -MM and -MT options)
%.d: %.cpp
	@g++ $(CXXFLAGS) $< -MM -MT $(@:.d=.o) >$@


.PHONY: clean
clean:
	$(RM) $(obj)
	$(RM) $(dep)
	$(RM) dettrace
# Credits to the awesome makefile guide:
# http://nuclear.mutantstargoat.com/articles/make/
