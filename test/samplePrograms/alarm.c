#include <stdlib.h>
#include <stdbool.h>
#include <sys/types.h>
#include <signal.h>
#include <stdio.h>
#include <unistd.h>
#include <assert.h>

typedef void (*sighandler_t)(int);

int counter = 0;

void handle_alarm( int sig ) {
  printf("counter=%d\n", counter);
  exit(0);
}

int main() {
  sighandler_t r = signal( SIGALRM, handle_alarm );
  assert( SIG_ERR != r );
  alarm( 1/*second*/ );

  while (true) {
    counter++;
  }

  return 0;
}
