#include <sys/types.h>
#include <unistd.h>
#include <signal.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <assert.h>

static _Atomic int thread_should_exit;
static pthread_cond_t run_first = PTHREAD_COND_INITIALIZER;
static pthread_mutex_t cond_mutex = PTHREAD_MUTEX_INITIALIZER;
static volatile pthread_t thread_suspend;

static void thread_exit(int signum, siginfo_t* info, void* uctxt) {
  write(STDOUT_FILENO, "caught SIGTERM, preparing exit\n", 31);
  atomic_store(&thread_should_exit, 1);
}

static void* second_thread(void* param) {
  assert(pthread_mutex_lock(&cond_mutex) == 0);
  assert(pthread_cond_wait(&run_first, &cond_mutex) == 0);
  assert(pthread_mutex_unlock(&cond_mutex) == 0);

  while(!thread_suspend);
  write(STDOUT_FILENO, "2. sending SIGTERM\n", 19);
  pthread_kill(thread_suspend, SIGTERM);
  
  return NULL;
}

static void* first_thread(void* param) {
  assert(pthread_mutex_lock(&cond_mutex) == 0);
  assert(pthread_cond_signal(&run_first) == 0);
  assert(pthread_mutex_unlock(&cond_mutex) == 0);

  sigset_t set;
  sigemptyset(&set);

  while(atomic_load(&thread_should_exit) == 0) {
    write(STDOUT_FILENO, "1. suspend\n", 11);
    sigsuspend(&set);
    write(STDOUT_FILENO, "1. suspend finished\n", 20);
  }

  return NULL;
}

int main(int argc, char* argv[])
{
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

  assert(pthread_create(&threads[1], NULL, second_thread, NULL) == 0);
  assert(pthread_create(&threads[0], NULL, first_thread, NULL) == 0);

  thread_suspend = threads[0];

  pthread_join(threads[0], NULL);
  pthread_join(threads[1], NULL);

  return 0;
}

