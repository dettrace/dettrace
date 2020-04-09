#ifndef DETTRACE_TESTS_UTIL_H
#define DETTRACE_TESTS_UTIL_H

#include <errno.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

void abort_if_failed(
    bool cond,
    int error,
    const char* file,
    int line,
    const char* func,
    const char* desc) {
  if (!cond) {
    fprintf(
        stderr, "%s: %s:%d: Assertion `%s' failed.\n", func, file, line, desc);
    if (errno > 0) {
      fprintf(stderr, "           os error (%d): %s\n", errno, strerror(errno));
    }
    raise(SIGABRT);
    abort();
  }
}

#ifdef __cplusplus
}
#endif

// The assert() from <assert.h> will get compiled out in release mode, so we
// define our own here.
#ifdef assert
#undef assert
#endif

#define assert(cond) \
  abort_if_failed(!!(cond), errno, __FILE__, __LINE__, __func__, #cond)

#endif // DETTRACE_TESTS_UTIL_H
