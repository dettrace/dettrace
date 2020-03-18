#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <sys/types.h>
#include <unistd.h>

// Process spawns thread with pthread api.
// Thread blocks trying to read from a pipe.
// Can the process still exit?

const int bytesToRead = 100;
const int bytesToWrite = 100;
int pipefd[2];

void* thread_func(void *arg){
  printf("Thread - my pid is: %d\n", getpid());
  printf("Thread - my ppid is: %d\n", getppid());
  printf("Thread wants to read from pipe.\n");
  
  char buf[bytesToRead];
  int bytes = read(pipefd[0], buf, bytesToRead);
  printf("Thread read this many bytes. %d\n", bytes);
  fflush(NULL);
  pthread_exit(NULL);
}

int main(void){
  printf("Process - my pid is: %d\n", getpid());
  printf("Process - my ppid is: %d\n", getppid());
  int ret = pipe(pipefd);
  if(ret != 0){
    printf("Pipe errored.\n");
    exit(1);
  }

  pthread_t thread1;
  int p = pthread_create(&thread1, NULL, thread_func, NULL);
  printf("Pthread create returned: %d\n", p);

  char buffer[bytesToWrite];
  int b = write(pipefd[1], buffer, bytesToWrite);
  printf("Process wrote this many bytes: %d\n", b);
  printf("Just gonna exit now.\n");

  exit(0);
}
