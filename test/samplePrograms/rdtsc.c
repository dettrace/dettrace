#include <stdio.h>
#include <x86intrin.h>

int main()
{
    unsigned long long int i;
    
    i = __rdtsc();
    printf("%llu ticks\n", i);
}
