#include <stdio.h>
#include <pthread.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>

// TODO: Thread function.
void* thread_func(void *arg){
  printf("Thread's pid: %d\n", getpid());
  printf("Thread's ppid: %d\n", getppid());
  pthread_exit(NULL);
}

int main() {
  pthread_t threads[10];
  int count;
  
  for(count = 0; count < 10; count++){
    pthread_create(&threads[count], NULL, thread_func, NULL);
    printf("Creating thread\n");
  }

  printf("Main process exiting.\n");
  return 0;
}
