#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <sys/types.h>
#include <sys/time.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <time.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <sched.h>

#include "util/assert.h"

#define ARRAY_SIZE(arr) ( sizeof(arr) / sizeof((arr)[0]) )

#define MK_CLKID(id) { id, #id, }

static struct clock_idmap {
  clockid_t id;
  const char* name;
} clock_ids[] = {
  MK_CLKID(CLOCK_REALTIME),
  MK_CLKID(CLOCK_MONOTONIC),
  MK_CLKID(CLOCK_PROCESS_CPUTIME_ID),
  MK_CLKID(CLOCK_THREAD_CPUTIME_ID),
  MK_CLKID(CLOCK_MONOTONIC_RAW),
  MK_CLKID(CLOCK_REALTIME_COARSE),
  MK_CLKID(CLOCK_MONOTONIC_COARSE),
  MK_CLKID(CLOCK_BOOTTIME),
  MK_CLKID(CLOCK_REALTIME_ALARM),
  MK_CLKID(CLOCK_BOOTTIME_ALARM),
  MK_CLKID(CLOCK_TAI),
};

int main(int argc, char* argv[])
{
  struct timeval tv;
  struct timespec tp;
  time_t tm, tm0;

  assert(gettimeofday(&tv, NULL) == 0);
  printf("gettimeofday: tv_sec: %lu, tv_usec: %lu\n", tv.tv_sec, tv.tv_usec);

  printf("getcpu: cpu: %u\n", sched_getcpu());

  for (int i = 0; i < ARRAY_SIZE(clock_ids); i++) {
    assert(clock_gettime(clock_ids[i].id, &tp) == 0);
    printf("clock_gettime %s: tv_sec: %lu, tv_nsec: %lu\n", clock_ids[i].name, tp.tv_sec, tp.tv_nsec);
  }

  tm = time(NULL);
  printf("time(NULL): %lu\n", tm);

  tm = time(&tm0);
  printf("time(&s): returned: %lu, tloc: %lu\n", tm, tm0);

  return 0;
}
