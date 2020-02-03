#include <stdio.h>
#include <sys/types.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <time.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <wait.h>

int doWithCheck(int returnValue, char* errorMessage);
void writeToPipe(int writeEnd, int childNum);
void readFromPipe(int pipefd);

const int bytesToUse = 100;

int main(){
  int myPipe[2];
  doWithCheck(pipe(myPipe), "pipe");

  int readEnd = myPipe[0];
  int writeEnd = myPipe[1];

  // Forking Child 1
  pid_t pid = doWithCheck(fork(), "fork");

  if(pid == 0){
    writeToPipe(writeEnd, 1);
    printf("done writing!\n");
    return 0;
  }

  fd_set rfds;
  FD_ZERO(&rfds);
  FD_SET(readEnd, &rfds);
  int max_fd = readEnd + 1;

  doWithCheck(select(max_fd, &rfds, NULL, NULL, NULL), "select");
  if(FD_ISSET(readEndChild1, &rfds)){
    readFromPipe(readEndChild1);
  }
  else if(FD_ISSET(readEndParent, &rfds)){
    readFromPipe(readEndParent);
  }
  else{
    printf("Nothing ready\n");
  }

  readFromPipe(readEnd);
  int parentStatus;
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
    printf("writing.\n");
    int bytes = doWithCheck(write(writeEnd, buffer, bytesToUse), "write");
    if(bytesToUse != bytes){
      fprintf(stderr, "Read %d bytes, expected %d...", bytes, bytesToUse);
      exit(1);
    }
  }

  printf("Done writing!\n");
}

void readFromPipe(int pipefd){
  char buffer[bytesToUse];
  for(int i = 0; i < 5; i++){
    int bytes = doWithCheck(read(pipefd, buffer, bytesToUse), "read");
    printf("Read from pipe\n");
  }
}
