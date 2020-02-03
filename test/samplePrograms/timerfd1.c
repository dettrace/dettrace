#include <sys/types.h>
#include <sys/timerfd.h>
#include <time.h>
#include <unistd.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>

#define TIME_100MS 100000000UL

int main(int argc, char* argv[])
{
  int fd = timerfd_create(CLOCK_MONOTONIC, TFD_CLOEXEC);
  assert(fd >= 0);

  printf("timerfd_create fd: %d\n", fd);

  struct itimerspec it, it_old;

  it.it_interval.tv_sec = 0;
  it.it_interval.tv_nsec = TIME_100MS;
  it.it_value.tv_sec = 0;
  it.it_value.tv_nsec = TIME_100MS;

  assert(timerfd_settime(fd, 0, &it, &it_old) == 0);

  for (int i = 0; i < 10; i++) {
    unsigned long expired = 0;
    ssize_t n = read(fd, &expired, sizeof(unsigned long));
    if (n != sizeof(unsigned long)) {
      fprintf(stderr, "read timerfd returned: %ld, expected: %ld\n",
	      n, sizeof(unsigned long));
      exit(1);
    }
    printf("[%d] read expired count: %ld\n", i, expired);
  }

  assert(timerfd_gettime(fd, &it) == 0);

  assert(it.it_interval.tv_sec == 0);
  assert(it.it_interval.tv_nsec == TIME_100MS);
  assert(it.it_value.tv_sec == 0);
  assert(it.it_value.tv_nsec > 0);

  it.it_value.tv_sec = 0;
  it.it_value.tv_nsec = 0;

  assert(timerfd_settime(fd, 0, &it, &it_old) == 0);

  assert(timerfd_gettime(fd, &it) == 0);
  assert(it.it_interval.tv_sec == 0);
  assert(it.it_interval.tv_nsec == TIME_100MS);
  assert(it.it_value.tv_sec == 0);
  assert(it.it_value.tv_nsec == 0);

  close(fd);

  return 0;
}

