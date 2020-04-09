#include <stdio.h>
#include <stdlib.h>
#include <sys/timerfd.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include "util/assert.h"

#define IVAL_SECS 0
#define IVAL_NANOS 100000000UL
int is_relative = 1; // TODO: test both modes
int clockid = CLOCK_MONOTONIC;

int main(int argc, char* argv[]) {
  // RRN: I'm having an unusual problem here where relative clocks
  // (realtime or monotonic) deadlock on read on some machines.
  // int fd = timerfd_create(clockid, TFD_CLOEXEC);

  int fd = timerfd_create(clockid, 0);
  assert(fd >= 0);

  printf("timerfd_create fd: %d\n", fd);
  struct itimerspec it;

  it.it_interval.tv_sec = IVAL_SECS;
  it.it_interval.tv_nsec = IVAL_NANOS;

  if (is_relative) {
    it.it_value.tv_sec = IVAL_SECS;
    it.it_value.tv_nsec = IVAL_NANOS;
    assert(timerfd_settime(fd, 0, &it, NULL) != -1);
    printf("timerfd_set completed (relative timer)\n");
  } else {
    struct timespec now;
    // Grab the current time to set the first timer event after it:
    assert(clock_gettime(clockid, &now) == 0);
    it.it_value.tv_sec = now.tv_sec + IVAL_SECS;
    it.it_value.tv_nsec = now.tv_nsec + IVAL_NANOS;
    assert(timerfd_settime(fd, TFD_TIMER_ABSTIME, &it, NULL) != -1);
    printf("timerfd_set completed (absolute timer)\n");
  }

  for (int i = 0; i < 10; i++) {
    unsigned long expired = 0;
    // Returns an 8-byte integer with the number of timer expirations:
    ssize_t n = read(fd, &expired, sizeof(unsigned long));
    if (n != sizeof(unsigned long)) {
      fprintf(
          stderr, "read timerfd returned: %ld, expected: %ld\n", n,
          sizeof(unsigned long));
      exit(1);
    }
    printf("[%d] read expired count: %ld\n", i, expired);
  }

  assert(timerfd_gettime(fd, &it) == 0);

  assert(it.it_interval.tv_sec == IVAL_SECS);
  assert(it.it_interval.tv_nsec == IVAL_NANOS);
  assert(it.it_value.tv_sec == IVAL_SECS);
  assert(it.it_value.tv_nsec > 0);

  // Disable by setting to zero:
  it.it_value.tv_sec = 0;
  it.it_value.tv_nsec = 0;

  struct itimerspec it_old;
  assert(timerfd_settime(fd, 0, &it, &it_old) == 0);

  assert(timerfd_gettime(fd, &it) == 0);
  assert(it.it_interval.tv_sec == IVAL_SECS);
  assert(it.it_interval.tv_nsec == IVAL_NANOS);
  assert(it.it_value.tv_sec == 0);
  assert(it.it_value.tv_nsec == 0);

  close(fd);

  return 0;
}
