#include <stdio.h>
#include <stdint.h>
#include <x86intrin.h>

#define MAX_ATTEMPTS 10

int rdrand(long long unsigned int* result) {
    int success;
    int attempts = MAX_ATTEMPTS;
    while (!(success = _rdrand64_step(result)) && --attempts != 0) {
    }
    return success;
}

int main()
{
    long long unsigned int result;

    if(rdrand(&result)) {
      printf("RDRAND value: %llu\n", result);
    } else {
      printf("RDRAND Failure. Insufficient Entropy.");
    }


}
