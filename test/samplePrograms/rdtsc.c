#include <stdio.h>
#include <x86intrin.h>

int main()
{
    unsigned long long int i;

    i = __rdtsc();
    printf("RDTSC: %llu ticks\n", i);
    i = __rdtsc();
    printf("RDTSC: %llu ticks\n", i);
}
