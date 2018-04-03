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

// Both parent and child try to read from the pipe. This should dead lock and be reported
// by our scheduler.

int doWithCheck(int returnValue, char* errorMessage);

const int bytesToUse = 100;

int main(){
  int pipefd[2];
  doWithCheck(pipe(pipefd), "pipe");

  int readEnd = pipefd[0];

  // Fork!
  pid_t pid = doWithCheck(fork(), "fork");

  // Child
  if(pid == 0){
    char buffer[bytesToUse];
    int bytes = doWithCheck(read(readEnd, buffer, bytesToUse), "read");
    if(bytesToUse != bytes){
      fprintf(stderr, "Read %d bytes, expected %d...", bytes, bytesToUse);
      exit(1);
    }

    printf("Child done!\n");

    return 0;
  }

  // Parent
  char buffer[bytesToUse];
  int bytes = doWithCheck(read(readEnd, buffer, bytesToUse), "read");
  if(bytesToUse != bytes){
      fprintf(stderr, "Read less bytes than expected...");
      exit(1);
    }

  printf("Parent done!\n");
  int status;
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
