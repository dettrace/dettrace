NAME=cloudseal
CXX = clang++
CC= clang

DEFINES=-D_GNU_SOURCE=1 -D_POSIX_C_SOURCE=20181101 -D__USE_XOPEN=1

CXXFLAGS =-g -O3 -std=c++14 -Wall $(INCLUDE) $(DEFINES)
CFLAGS =-g -O3 -Wall -Wshadow $(INCLUDE) $(DEFINES)
LIBS = -pthread -lseccomp -lfingerprinter_tool -L ../lib/lib64 -L../../target/x86_64-unknown-linux-gnu/debug

INITRAMFS=$(shell ls "../initramfs.cpio")

LIBCRYPTO=$(shell pkg-config --libs libcrypto)
LIBCRYPTO_STATIC=$(shell pkg-config --static --libs libcrypto)

LIBARCHIVE=$(shell pkg-config --libs libarchive)
LIBARCHIVE_STATIC=$(shell pkg-config --static --libs libarchive)

# Libdet only.
LIBDETFLAGS= -g -O2 -Wall -Wextra -Wconversion -fPIC -shared -Wl,--no-as-needed -std=c99
LIBDETLIBS=-ldl -lm

INCLUDE = -I ../include/ -I ../lib/include

src = $(wildcard *.cpp)
obj = $(src:.cpp=.o)
dep = $(obj:.o=.d)

obj += initramfs.o

all: ${NAME}
all-static: ${NAME}-static

initramfs.o: initramfs.S $(INITRAMFS)
	$(CC) $< $(CFLAGS) -c -o $@ -D__INITRAMFS__='"$(INITRAMFS)"'

${NAME}: $(obj) $(libs)
	$(CXX) $(CXXFLAGS) $^ -o $@ $(LIBS) $(LIBARCHIVE) $(LIBCRYPTO)

${NAME}-static: $(obj) $(libs)
	$(CXX) $(CXXFLAGS) -static $^ -o $@ $(LIBS) $(LIBARCHIVE_STATIC) $(LIBCRYPTO_STATIC)

-include $(dep)

# rule to generate a dep file by using the C preprocessor
# (see man cpp for details on the -MM and -MT options)
%.d: %.cpp
	@g++ $(CXXFLAGS) $< -MM -MT $(@:.d=.o) >$@


.PHONY: all all-static clean
clean:
	$(RM) $(obj)
	$(RM) $(dep)
	$(RM) initramfs.o
	$(RM) ${NAME}
# Credits to the awesome makefile guide:
# http://nuclear.mutantstargoat.com/articles/make/
