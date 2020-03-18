#include <stdint.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <x86intrin.h>
#include <assert.h>
#include <string.h>

#define MAX_ATTEMPTS 10

static void sigillHandler(int sig, siginfo_t *si, void *ctxt) {
  assert(4 == sig);
  printf("Received SIGILL (%d), rdrand/rdseed insn not supported.\n", sig);
}

int rdseed(unsigned long long* result) {
    int success;
    int attempts = MAX_ATTEMPTS;
    while (!(success = _rdseed64_step(result)) && --attempts != 0) {
    }
    return success;
}

int rdrand(unsigned long long* result) {
    int success = 0;
    int attempts = MAX_ATTEMPTS;
    while (!(success = _rdrand64_step(result)) && --attempts != 0) {
    }
    return success;
}

void printUsage(const char* argv0) {
    printf("Usage: %s (rdrand|rdseed)\n", argv0);
}

int main(int argc, char** argv) {

  if (argc != 2) {
    printUsage(argv[0]);
    return 1;
  }
  
  // setup SIGILL handler in case rdrand isn't supported
  struct sigaction sa;
  sa.sa_flags = SA_SIGINFO;
  sigemptyset(&sa.sa_mask);
  sa.sa_sigaction = sigillHandler;
  if (sigaction(SIGILL, &sa, NULL) == -1) {
    printf("ERROR: sigaction() returned -1\n");
    return 1;
  }

  // int (*rdinsn)(unsigned long long*);
  if (0 == strcmp("rdrand",argv[1])) {
    // rdinsn = rdrand;
  } else if (0 == strcmp("rdseed",argv[1])) {
    // UNFINISHED!
    // rdinsn = rdseed;
  } else {
    printUsage(argv[0]);
    return 1;
  }
  
  unsigned long long result0 = -1, result1 = -1;
  printf("%s test starting.\n", argv[1]);
  
  if(rdrand(&result0)) {
    printf("%s first value: %llu\n", argv[1], result0);
  } else {
    printf("Failure: Insufficient Entropy.");
    return 1;
  }

  if(rdrand(&result1)) {
    printf("%s second value: %llu\n", argv[1], result1);
  } else {
    printf("Failure: Insufficient Entropy.");
    return 1;
  }

  if (result0 == result1) {
    printf("ERROR: %s is reproducible?!?!?\n", argv[1]);
    return 1;
  } else {
    printf("Expected failure: %s not reproducible\n", argv[1]);
  }

  return 0;
}
