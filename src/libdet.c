/**
 * We use LD_PRELOAD to provide a full user-space solution for VDSO functions on x86_64.
 * We need this as ptrace cannot intercept calls to systemcalls through VDSO.
 * Another solution is to turn off vdso throgh the kernel parameters on boot: vdso=0

 * Extern "C" needed to avoid name magling when linking.
 */
#define _GNU_SOURCE

#include <dirent.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <math.h> // ceil.
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/times.h>
#include <sys/timex.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

/**
 * Our logical time.

 * https://stackoverflow.com/questions/17126400/ \
 * how-are-global-variables-in-shared-libraries-linked
 * Global variables are not shared among different processes. Warning: global variables
 * should have unique names, or they might clash with libc functions!
 */

// TODO: One day, we should unify time.
// Start at this number to avoid seeing files "in the future", if we were to start at
// zero.
time_t libdet_clock = 744847200;

/**
 * The  functions  clock_gettime() retrieve the time of the specified clock clk_id.
 * The res and tp arguments are timespec structures, as specified in <time.h>:
 * struct timespec {
 *   time_t   tv_sec;         seconds
 *   long     tv_nsec;       nanoseconds
 * };

 * The clk_id argument is the identifier of the particular clock on  which  to  act. A
 * clock  may  be  system-wide and hence visible for all processes, or per-process if it
 * measures time only within a single process.
 */
int clock_gettime(clockid_t clk_id, struct timespec *tp){
  (void)clk_id; // ignore unused warning.
  /* fprintf(stderr, "CALLED: %s\n", "clock_gettime"); */
  if(tp == NULL){
    return -1;
  }else{
    tp->tv_nsec = libdet_clock;
    tp->tv_sec  = libdet_clock;
    libdet_clock++;
  }

  return 0;
}

// TODO?
// int getcpu(unsigned *cpu, unsigned *node, struct getcpu_cache *tcache){

// }

/**
 * The functions gettimeofday() and settimeofday() can get and set the time as well as a
 * timezone.  The tv argument is a struct timeval (as specified in <sys/time.h>):

 * struct timeval {
 *   time_t      tv_sec;     seconds
 *  suseconds_t tv_usec;     microseconds
 * };

 * and gives the number of seconds and microseconds since the Epoch (see time(2)). The
 * tz argument is a struct timezone:

 * struct timezone {
 *   int tz_minuteswest;     minutes west of Greenwich
 *   int tz_dsttime;         type of DST correction
 * };

 * If  either  tv  or  tz  is  NULL, the corresponding structure is not set or returned.
 * (However, compilation warnings will result if tv is NULL.)
 */
int gettimeofday(struct timeval *tv, struct timezone *tz){
  tv->tv_sec = libdet_clock;
  tv->tv_usec = libdet_clock;
  libdet_clock++;
  if(tz != NULL){
    // No minutes west of Greenwich and no daylight correction.
    tz->tz_minuteswest = 0;
    tz->tz_dsttime = 0;
  }

  return 0;
}

/**
 * Time returns the current time elapsed since January 1st 1970.
 * time_t is implemented as an arithmetic number. Needed for srand.
 * http://man7.org/linux/man-pages/man2/time.2.html
 */
time_t time(time_t* tloc){
  /* fprintf(stderr, "CALLED: %s\n", "time"); */

  if(tloc != NULL){
    *tloc = libdet_clock;
  }

  time_t retTime = libdet_clock;
  libdet_clock++;
  return retTime;
}

static uint32_t mkstempValue = 0;
// NB: these mk*stemp* implementations heavily rely on sequential execution to
// provide atomicity.

static int mymktemp(char* template, int suffixlen, int flags) {
  if (0 == mkstempValue) {
    mkstempValue = 1 + ((unsigned)getpid() * 2000); // statically allocate a slab of names to each process
  }

  char buf[7];
  snprintf(buf, 7, "%06x", mkstempValue);
  //fprintf(stderr, "[mymktemp] before: %s\n", template);
  memcpy(template + strlen(template) - suffixlen - 6, buf, 6);
  //fprintf(stderr, "[mymktemp] after: %s\n", template);
  int fd = open(template, O_CREAT | O_RDWR | O_EXCL | flags, S_IRUSR | S_IWUSR);
  mkstempValue += 1;
  return fd;
}

int mkstemp(char *template) {
  return mymktemp(template, 0, 0);
}

int mkostemp(char *template, int flags) {
  return mymktemp(template, 0, flags);
}

int mkstemps(char *template, int suffixlen) {
  return mymktemp(template, suffixlen, 0);
}

int mkostemps(char *template, int suffixlen, int flags) {
  return mymktemp(template, suffixlen, flags);
}

char* tempnam(const char* dir, const char* prefix) {
  if (0 == mkstempValue) {
    mkstempValue = 1 + ((unsigned)getpid() * 2000); // statically allocate a slab of names to each process
  }

  (void)dir;
  char buf[256];
  snprintf(buf, 256, "/tmp/%s%06x", prefix?prefix:"file", mkstempValue);
  mkstempValue += 1;
  return strdup(buf);
}
