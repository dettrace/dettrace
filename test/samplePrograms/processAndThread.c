#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <sys/types.h>
#include <sched.h>
#include <errno.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <time.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>

#define STACK_SIZE (1024 * 1024)

const int bytesToRead = 100;
const int bytesToWrite = 100;
int pipefd[2];

// Process spawns thread with clone().
// Thread blocks trying to read from a pipe.
// Can the process still exit?
int thread_func(void *arg){
  //sleep(5);
  char buf[bytesToRead];
  printf("Thread - my tid is: %ld\n", syscall(SYS_gettid));
  printf("Thread - my ppid is: %d\n", getppid());

  printf("Thread wants to read from pipe.\n");
  int bytes = read(pipefd[0], buf, bytesToRead);
  if(bytes != bytesToRead){
    printf("Read less bytes than expected.\n");
  }
  printf("Thread read this many bytes: %d\n", bytes);
  fflush(NULL);
  return 0;
}

int main(void){
  int ret = pipe(pipefd);
  if(ret != 0){
    printf("Pipe errored.\n");
    exit(1);
  }


  printf("Process - my pid is: %d\n", getpid());
  printf("Process - my ppid is: %d\n", getppid());

  void* child_stack = malloc(STACK_SIZE);
  int thread_pid;
  printf("Creating new thread.\n");

  thread_pid = clone(thread_func, child_stack+STACK_SIZE, CLONE_VM|CLONE_FS|CLONE_FILES|CLONE_SIGHAND|CLONE_THREAD|CLONE_PARENT_SETTID| SIGCHLD, NULL);
  printf("Thread created! Thread pid: %d\n", thread_pid);

  char buffer[bytesToWrite];
  for (int i = 0; i < bytesToWrite; i++) {
    buffer[i] = 0;
  }
  int b = write(pipefd[1], buffer, bytesToWrite);
  printf("Process just wrote this many bytes: %d\n", b);
  printf("Just gonna exit now.\n");
  exit(EXIT_SUCCESS);
}
