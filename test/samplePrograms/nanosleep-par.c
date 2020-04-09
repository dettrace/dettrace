#include <sys/types.h>
#include <sys/wait.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>
#include <stdatomic.h>

#include "util/assert.h"

static _Atomic unsigned long counter_loc;
static volatile _Atomic unsigned long* pcounter = &counter_loc;

#define DELAY_CYCLES 10000000

static void delay(void) {
  for (int i = 0; i < DELAY_CYCLES; i++)
    atomic_fetch_add(pcounter, 1);
}

static void run_parent_process(void)
{
  const struct timespec req = {0, 100000000};
  struct timespec rem = {0, 0};

  for (int i = 0; i < 10; i++) {
    printf("parent\n");
    assert(nanosleep(&req, &rem) == 0);
    delay();
  }
}

static void run_child_process(pid_t pid)
{
  const struct timespec req = {0, 100000000};
  struct timespec rem = {0, 0};

  for (int i = 0; i < 10; i++) {
    printf("child\n");
    assert(nanosleep(&req, &rem) == 0);
    delay();
  }
}

int main(int argc, char* argv[])
{
  pid_t pid = fork();

  if (pid == 0) { /* child */
    run_child_process(pid);
  } else if (pid > 0) { /* parent */
    int status;

    run_parent_process();
    waitpid(pid, &status, 0);
    printf("global counter: %lu\n", atomic_load(pcounter));
  } else {
    perror("fork():");
  }
  return 0;
}
