#include <stdio.h>
#include <x86intrin.h>

int main()
{
    unsigned long long int i;
    unsigned int ui;


    i = __rdtscp(&ui);
    printf("RDTSCP: %llu ticks\n", i);
    printf("TSC_AUX was %x\n", ui);

    i = __rdtscp(&ui);
    printf("RDTSCP: %llu ticks\n", i);
    printf("TSC_AUX was %x\n", ui);
}
