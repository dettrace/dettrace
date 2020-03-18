
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

const int bytesToRead = 100;
const int bytesToWrite = 100;
int pipefd[2];

void* second_thread(void *arg){
  printf("Thread2 trying to write to pipe.\n");
  char buf[bytesToWrite];
  int bytes = write(pipefd[1], buf, bytesToWrite);
  printf("Thread2 wrote this many bytes: %d\n", bytes);
  printf("Thread2 is done.\n");
  fflush(NULL);
  return NULL;
}

void* first_thread(void *arg){
  char buffer[bytesToRead];
  int b = read(pipefd[0], buffer, bytesToRead);
  printf("Thread1 read this many bytes: %d\n", b);
  printf("Thread1 is done.\n");
  fflush(NULL);
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
  pthread_t thread2;
  pthread_create(&thread1, NULL, first_thread, NULL);
  printf("Process spawning thread2 with pthread create.\n");
  pthread_create(&thread2, NULL, second_thread, NULL);
  pthread_join(thread1, NULL);
  pthread_join(thread2, NULL);
  
  printf("Process is exiting.\n");
  exit(EXIT_SUCCESS);
}
