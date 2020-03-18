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

#define STACK_SIZE (1024 * 1024)

const int bytesToRead = 100;
const int bytesToWrite = 100;
int pipefd[2];

int thread_func(void *arg){
  printf("Thread1 forking P2.\n");
  printf("Thread 1 pid: %d\n", getpid());
  printf("Thread 1 ppid: %d\n", getppid());
  pid_t p2 = fork();
  if (p2 == 0){
    // Child process tries to read from pipe.
    printf("Child process of thread trying to read from pipe.\n");
    printf("Child process pid: %d\n", getpid());
    printf("Child process' parent pid: %d\n", getppid());
    char buf[bytesToRead];
    int bytes = read(pipefd[0], buf, bytesToRead);
    printf("Child process read this many bytes: %d\n", bytes);
    printf("Child process done.\n");
    printf("Child process parent pid is now: %d\n", getppid());
    return 0;
  }
  
  // Thread writes to pipe.
  char buffer[bytesToWrite];
  int b = write(pipefd[1], buffer, bytesToWrite);
  printf("Thread1 wrote this many bytes: %d\n", b); 
  printf("Thread1 done, returning.\n");
  fflush(NULL);
  return 0;
}

int main(void){
  int ret = pipe(pipefd);
  if(ret != 0){
    printf("Pipe errored.\n");
    exit(1);
  }
  printf("Parent process pid: %d\n", getpid());
  printf("Parent process ppid: %d\n", getppid());
  void* child_stack = malloc(STACK_SIZE);
  int thread_pid;
  thread_pid = clone(thread_func, child_stack+STACK_SIZE, CLONE_VM|CLONE_FS|CLONE_FILES|CLONE_SIGHAND|CLONE_THREAD, NULL);
  printf("Process made thread1, pid: %d\n", thread_pid);
  printf("Process is exiting.\n");
  exit(EXIT_SUCCESS);
}
