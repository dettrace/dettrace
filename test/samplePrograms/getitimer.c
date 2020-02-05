#include <sys/time.h>
#include <stdio.h>
#include <assert.h>

#ifndef WHICH_ITIMER
#error WHICH_ITIMER must be #defined on the command-line.
#endif

int main(int argc, char** argv) {

  struct itimerval itv;
  int rv = getitimer( WHICH_ITIMER, &itv );
  assert( 0 == rv );

  printf( "it_interval.tv_sec=%lu it_interval.tv_usec=%lu\n",
          itv.it_interval.tv_sec, itv.it_interval.tv_usec );
  printf( "it_value.tv_sec=%lu it_value.tv_usec=%lu\n",
          itv.it_value.tv_sec, itv.it_value.tv_usec );

  return 0;
}
