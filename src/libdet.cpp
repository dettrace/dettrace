/**
 * We use LD_PRELOAD to provide a full user-space solution for VDSO functions on x86_64.
 * We need this as ptrace cannot intercept calls to systemcalls through VDSO.
 * Another solution is to turn off vdso throgh the kernel parameters on boot: vdso=0

 * Extern "C" needed to avoid name magling when linking.
 */
// #define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <stdarg.h>
#include <sys/timex.h>
#include <sys/times.h>
#include <sys/stat.h>
#include <errno.h>
#include <math.h> // ceil.
#include <dirent.h>

#include <stdint.h>


/**
 * Our logical time.

 * https://stackoverflow.com/questions/17126400/ \
 * how-are-global-variables-in-shared-libraries-linked
 * Global variables are not shared among different processes.
 */
uint32_t clock = 0;


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
extern "C"
int clock_gettime(clockid_t clk_id, struct timespec *tp){
  (void)clk_id; // ignore unused warning.
  // fprintf(stderr, "CALLED: %s\n", "clock_gettime");
  if(tp == NULL){
    return -1;
  }else{
    tp->tv_nsec = clock;
    tp->tv_sec  = clock;
    clock++;
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
extern "C"
int gettimeofday(struct timeval *tv, struct timezone *tz){
  if(tv != NULL) {
    tv->tv_sec = clock;
    tv->tv_usec = clock;
  }
  clock++;
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
extern "C"
time_t time(time_t *result){
  (void)result; // ignore unused warning.
  // fprintf(stderr, "CALLED: %s\n", "time");
  int retTime = clock;
  clock++;
  return retTime;
}
