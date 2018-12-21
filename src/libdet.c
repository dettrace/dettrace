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
