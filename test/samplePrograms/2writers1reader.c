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

int doWithCheck(int returnValue, char* errorMessage);
void writeToPipe(int writeEnd, int childNum);

const int bytesToUse = 100;

int main(){
  int pipefd[2];
  doWithCheck(pipe(pipefd), "pipe");

  int readEnd = pipefd[0];
  int writeEnd = pipefd[1];

  // Fork!
  pid_t pid = doWithCheck(fork(), "fork");

  // Child 1: write to pipe!
  if(pid == 0){
    writeToPipe(writeEnd, 1);
  }

  // Parent
  // Fork again!
  pid = doWithCheck(fork(), "fork");

  // Child 2: Also write to pipe!
  if(pid == 0){
    writeToPipe(writeEnd, 2);
  }

  char buffer[bytesToUse];
  for(int i = 0; i < 10; i++){
    int bytes = doWithCheck(read(readEnd, buffer, bytesToUse), "read");
    (void)bytes;
    /* if(bytesToUse != bytes){ */
      /* fprintf(stderr, "Wrote less bytes than expected..."); */
      /* exit(1); */
    /* } */
    if(buffer[0] == 1){
      printf("Read from child 1\n");
    }else{
      printf("Read from child 2\n");
    }

  }

  printf("Parent done!\n");
  int status;
  // Wait on both children.
  wait(&status);
  wait(&status);
  return 0;
}

int doWithCheck(int returnValue, char* errorMessage){
  char* whyError = strerror(errno);
  if(returnValue == -1){
    fprintf(stderr, "%s failed: %s\n", errorMessage, whyError);
    exit(1);
  }
  return returnValue;
}


void writeToPipe(int writeEnd, int childNum){
  char buffer[bytesToUse];
  memset(buffer, childNum, bytesToUse);

  for(int i = 0; i < 5; i++){
    printf("Child %d writing.\n", childNum);
    int bytes = doWithCheck(write(writeEnd, buffer, bytesToUse), "write");
    if(bytesToUse != bytes){
      fprintf(stderr, "Read %d bytes, expected %d...", bytes, bytesToUse);
      exit(1);
    }
  }

  printf("Child done!\n");

  exit(0);
}
