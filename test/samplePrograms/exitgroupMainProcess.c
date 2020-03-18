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
#include <pthread.h>

#define STACK_SIZE (1024 * 1024)

const int bytesToRead = 100;
const int bytesToWrite = 100;
int pipefd[2];
// Process spawns thread with clone().
// Thread blocks trying to read from a pipe.
// Can the process still exit?
void* thread_func(void *arg){
  printf("Thread wants to read from pipe.\n");
  char buf[bytesToRead];
  read(pipefd[0], buf, bytesToRead);
  return NULL;
}

int main(void){
  printf("Process - my pid is: %d\n", getpid());
  printf("Process - my ppid is: %d\n", getppid());

  int ret = pipe(pipefd);
  if(ret != 0){
    printf("Pipe errored.\n");
    exit(1);
  }

  pthread_t threads[10];
  for(int i = 0; i < 10; i++){
    printf("Creating new thread.\n");
    pthread_create(&threads[i], NULL, thread_func, NULL);
  }

  // Give some time for threads to spawn...
  sleep(3);
  exit(EXIT_SUCCESS);
}
