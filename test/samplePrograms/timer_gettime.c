

#include <stdlib.h>
#include <signal.h>
#include <stdio.h>
#include <stdbool.h>
#include <time.h>
#include <assert.h>

int main() {

  // no notification
  struct sigevent se;
  se.sigev_notify = SIGEV_NONE;
  
  timer_t timerid;  
  int rv = timer_create(CLOCK_THREAD_CPUTIME_ID, &se, &timerid);
  printf("timer_create returned %d\n", rv);
  assert( 0 == rv );

  printf("NONPORTABLE created timerid %p\n", timerid);
  
  struct itimerspec ts;
  rv = timer_gettime(timerid, &ts);
  assert( 0 == rv );

  printf( "it_interval.tv_sec=%lu it_interval.tv_nsec=%lu\n",
          ts.it_interval.tv_sec, ts.it_interval.tv_nsec );
  printf( "it_value.tv_sec=%lu it_value.tv_nsec=%lu\n",
          ts.it_value.tv_sec, ts.it_value.tv_nsec );

  return 0;
}
