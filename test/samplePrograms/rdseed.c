#include <stdio.h>
#include <stdint.h>
#include <x86intrin.h>

#define MAX_ATTEMPTS 10

int rdseed(long long unsigned int* result) {
    int success;
    int attempts = MAX_ATTEMPTS;
    while (!(success = _rdseed64_step(result)) && --attempts != 0) {
    }
    return success;
}

int main()
{
    long long unsigned int result;

    if(rdseed(&result)) {
      printf("RDSEED value: %llu\n", result);
    } else {
      printf("RDSEED Failure. Insufficient Entropy.");
    }


}
