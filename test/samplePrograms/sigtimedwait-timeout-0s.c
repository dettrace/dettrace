#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#include "util/assert.h"

static _Atomic int thread_should_exit;

static void thread_exit(int signum, siginfo_t* info, void* uctxt) {
  write(STDOUT_FILENO, "caught SIGTERM, preparing exit\n", 31);
  atomic_store(&thread_should_exit, 1);
}

static void* second_thread(void* param) {
  pthread_t thread_suspend = *(pthread_t*)param;

  write(STDOUT_FILENO, "2. sending SIGTERM\n", 19);
  pthread_kill(thread_suspend, SIGTERM);

  return NULL;
}

static void* first_thread(void* param) {
  sigset_t set;
  siginfo_t siginfo;
  struct timespec tp = {0, 0};

  sigemptyset(&set);
  sigaddset(&set, SIGTERM);

  write(STDOUT_FILENO, "1. sigtimedwait timeout one second\n", 35);
  sigtimedwait(&set, &siginfo, &tp);
  write(STDOUT_FILENO, "1. sigtimedwait finished\n", 25);

  return NULL;
}

int main(int argc, char* argv[]) {
  sigset_t set, oldset;
  pthread_t threads[2];

  sigemptyset(&set);

  sigaddset(&set, SIGTERM);
  sigprocmask(SIG_BLOCK, &set, &oldset);

  struct sigaction sa;
  memset(&sa, 0, sizeof(sa));
  sa.sa_sigaction = thread_exit;
  sa.sa_flags = SA_RESTART | SA_RESETHAND | SA_SIGINFO;

  assert(sigaction(SIGTERM, &sa, NULL) == 0);

  assert(pthread_create(&threads[0], NULL, first_thread, NULL) == 0);
  assert(pthread_create(&threads[1], NULL, second_thread, &threads[0]) == 0);

  pthread_join(threads[0], NULL);
  pthread_join(threads[1], NULL);

  return 0;
}
