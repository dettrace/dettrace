#include <pthread.h>
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>

#define handle_error_en(en, msg) \
               do { errno = en; perror(msg); exit(EXIT_FAILURE); } while (0)

void* threadFunction(void* args){
  printf("Hello from thread!\n");
  return NULL;
}

int main(){
  pthread_t handle;
  printf("Hello from parent\n");

  int s = pthread_create(& handle, NULL, *threadFunction, NULL);
  if(s != 0){
    handle_error_en(errno, "pthread create\n");
  }

  printf("Waiting for child to finish.\n");
  pthread_join(handle, NULL);

  printf("All done!\n");
  return 0;
}
