#include <stdlib.h>
#include <stdbool.h>
#include <signal.h>
#include <stdio.h>
#include <unistd.h>
#include <assert.h>
#include <inttypes.h>

void alarmListener(int signum) {
  printf("alarmListener() invoked\n");
}

int main() {
  sigset_t sigset;
  sigemptyset( &sigset );
  struct sigaction sa;
  sa.sa_mask = sigset;
  sa.sa_flags = SA_RESETHAND; // go back to SIG_DFL after alarmListener runs once
  sa.sa_handler = alarmListener;
  printf("&sa: %p\n", &sa);
  int rv = sigaction(SIGALRM, &sa, NULL);
  
  assert( 0 == rv );
  
  alarm( 1/*second*/ );

  return 0;
}
