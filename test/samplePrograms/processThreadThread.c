#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
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

// Process spawns thread which spawns thread.
// Can thread2 exit before thread one, the answer is yes.
#define STACK_SIZE (1024 * 1024)

const int bytesToRead = 100;
const int bytesToWrite = 100;
int pipefd[2];

int second_thread(void *arg){
  printf("Thread2 trying to read from pipe.\n");
  printf("my pid is: %d\n", getpid());
  char buf[bytesToRead];
  int bytes = read(pipefd[0], buf, bytesToRead);
  printf("Thread2 read this many bytes: %d\n", bytes);
  printf("Thread2 is done.\n");
  fflush(NULL);
  return 0;
}

int first_thread(void *arg){
  void* thread2_stack = malloc(STACK_SIZE);
  printf("Thread1 cloning thread2.\n");
  int thread_pid2;
  thread_pid2 = clone(second_thread, thread2_stack+STACK_SIZE, CLONE_VM|CLONE_FS|CLONE_FILES|CLONE_SIGHAND|CLONE_THREAD, NULL);
  printf("Thread1 cloned thread2, pid: %d\n", thread_pid2);

  char buffer[bytesToWrite];
  int b = write(pipefd[1], buffer, bytesToWrite);
  printf("Thread1 wrote this many bytes: %d\n", b);
  printf("Thread1 is done.\n");
  fflush(NULL);
  return 0;
}

int main(void){
  int ret = pipe(pipefd);
  if(ret != 0){
    printf("Pipe errored.\n");
    exit(1);
  }

  void* child_stack = malloc(STACK_SIZE);
  int thread_pid;
  printf("Process cloning thread1.\n");
  thread_pid = clone(first_thread, child_stack+STACK_SIZE, CLONE_VM|CLONE_FS|CLONE_FILES|CLONE_SIGHAND|CLONE_THREAD, NULL);
  printf("Process made thread1, pid: %d\n", thread_pid);
  printf("Process is exiting.\n");
  exit(EXIT_SUCCESS);
}
