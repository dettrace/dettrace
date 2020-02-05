
all: trap_cpuid

CC= clang -std=gnu99 -march=broadwell

trap_cpuid: trap_cpuid.c
	$(CC) $^ -o $@

from_forum:
	nasm -Wall -f elf64 -o utils.o utils.asm
	$(CC) -Wall -c -o cpuid.o cpuid.c
	$(CC) -Wall -g -o cpuid cpuid.o utils.o

clean:
	$(RM) trap_cpuid

.PHONY: all
