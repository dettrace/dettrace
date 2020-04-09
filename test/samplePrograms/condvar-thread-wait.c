/* build with `-O -pthread -D_GNU_SOURCE=1` */
#include <pthread.h>
#include <stdlib.h>
#include <unistd.h>

#include "util/assert.h"

static pthread_cond_t run_first = PTHREAD_COND_INITIALIZER;
static pthread_mutex_t cond_mutex = PTHREAD_MUTEX_INITIALIZER;

static void* second_thread(void* param) {
  int* done = (int*)param;

  assert(pthread_mutex_lock(&cond_mutex) == 0);
  while (!*done) {
    // Run in a loop to protect against spurious wake-ups. Calling
    // pthread_cond_wait after pthread_cond_signal will also deadlock.
    assert(pthread_cond_wait(&run_first, &cond_mutex) == 0);
  }
  assert(pthread_mutex_unlock(&cond_mutex) == 0);

  assert(write(STDOUT_FILENO, "second\n", 7) == 7);
  return NULL;
}

static void* first_thread(void* param) {
  int* done = (int*)param;

  assert(write(STDOUT_FILENO, "first\n", 6) == 6);

  // Update the variable
  assert(pthread_mutex_lock(&cond_mutex) == 0);
  *done = 1;
  assert(pthread_mutex_unlock(&cond_mutex) == 0);

  // Signal the other thread that we updated the variable
  assert(pthread_cond_signal(&run_first) == 0);
  return NULL;
}

int main(int argc, char* argv[]) {
  pthread_t first, second;

  int done = 0;

  assert(pthread_create(&first, NULL, first_thread, &done) == 0);
  assert(pthread_create(&second, NULL, second_thread, &done) == 0);
  assert(pthread_join(first, NULL) == 0);
  assert(pthread_join(second, NULL) == 0);
  return 0;
}
