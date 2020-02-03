#include <stdlib.h>
#include <stdbool.h>
#include <signal.h>
#include <stdio.h>
#include <unistd.h>
#include <assert.h>
#include <inttypes.h>

int main() {
  sigset_t sigset;
  sigemptyset( &sigset );
  struct sigaction sa;
  sa.sa_mask = sigset;
  sa.sa_handler = SIG_IGN; // ignore alarm
  int rv = sigaction(SIGALRM, &sa, NULL);
  
  assert( 0 == rv );
  
  alarm( 1/*second*/ );

  while (true) {}

  return 0;
}
