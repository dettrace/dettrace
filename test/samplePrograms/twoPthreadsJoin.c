
#include <pthread.h>
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

void* second_thread(void *arg){
  printf("Thread 2 pid: %d\n", getpid());
  printf("Thread2 trying to read from pipe.\n");
  char buf[bytesToRead];
  int bytes = read(pipefd[0], buf, bytesToRead);
  printf("Thread2 read this many bytes: %d\n", bytes);
  printf("Thread2 is done.\n");
  fflush(NULL);
  return NULL;
}

void* first_thread(void *arg){
  printf("Thread 1 pid: %d\n", getpid());
  printf("Thread1 spawning thread2 with pthread create.\n");
  pthread_t thread2;
  pthread_create(&thread2, NULL, second_thread, NULL);
  printf("Thread1 made thread2.\n");

  char buffer[bytesToWrite];
  int b = write(pipefd[1], buffer, bytesToWrite);
  printf("Thread1 wrote this many bytes: %d\n", b);
  printf("Thread1 is done.\n");
  fflush(NULL);
  pthread_join(thread2, NULL);
  return NULL;
}

int main(void){
  int ret = pipe(pipefd);
  if(ret != 0){
    printf("Pipe errored.\n");
    exit(1);
  }

  printf("Process spawning thread1 with pthread create.\n");
  pthread_t thread1;
  pthread_create(&thread1, NULL, first_thread, NULL);
  printf("Process made thread1.\n");
  pthread_join(thread1, NULL);
  
  printf("Process is exiting.\n");
  exit(EXIT_SUCCESS);
}
