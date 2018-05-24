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
  int parentPipe[2];
  int child1Pipe[2];
  doWithCheck(pipe(parentPipe), "pipe");
  doWithCheck(pipe(child1Pipe), "pipe");

  int readEndParent = parentPipe[0];
  int writeEndParent = parentPipe[1];
  int readEndChild1 = child1Pipe[0];
  int writeEndChild1 = child1Pipe[1];

  // Forking Child 1
  pid_t pid1 = doWithCheck(fork(), "fork");

  printf("we are alive\n");
  // Child 1: Fork Child 2
	// And also write to the second pipe.
  if(pid1 == 0){
    pid_t pid2 = doWithCheck(fork(), "fork");

    // Child 2: Forked from Child 1
    // TODO: stuff
    if(pid2 == 0){
      fd_set rfds;
      int retVal;
      FD_ZERO(&rfds);
      FD_SET(readEndChild1, &rfds);
      FD_SET(readEndParent, &rfds);

      int max_fd = -1;
      if(readEndChild1 > readEndParent){
        max_fd = readEndChild1;
      }else{
      	max_fd = readEndParent;
      }

      doWithCheck(select(max_fd + 1, &rfds, NULL, NULL, NULL), "select");
      if(FD_ISSET(readEndChild1, &rfds)){
        readFromPipe(readEndChild1);
      }
      else if(FD_ISSET(readEndParent, &rfds)){
        readFromPipe(readEndParent);
      }
      else{ 
      	printf("Nothing ready\n");
      }

      doWithCheck(select(max_fd + 1, &rfds, NULL, NULL, NULL), "select");
      if(FD_ISSET(readEndChild1, &rfds)){
        readFromPipe(readEndChild1);
      }
      else if(FD_ISSET(readEndParent, &rfds)){
        readFromPipe(readEndParent);
      }
      else{ 
      	printf("Nothing ready\n");
      }
      return 0;
    }
    // Child1 = 2
    writeToPipe(writeEndChild1, 2);
    printf("parent done!\n");
    fflush(NULL);
    int child1Status;
    //waitpid(&child1Status);

    printf("parent is waiting\n");
    int v = waitpid(pid2, &child1Status, 0);
    printf("val is %d.\n", v);
    return 0;
  }
  // Parent = 1
  writeToPipe(writeEndParent, 1);
  printf("grandparent done!\n");
  fflush(NULL);
  int parentStatus;
  //wait(&parentStatus);
  //waitpid(pid1, &parentStatus, 0);
  printf("grandparent is waiting\n");
  int v = waitpid(pid1, &parentStatus, 0);
  printf("val is %d.\n", v);
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
    printf("PID %d writing.\n", childNum);
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
    if(buffer[0] == 1){
      printf("Read from grandparent\n");
    }else if (buffer[0] == 2){
      printf("Read from parent\n");
    }
  }
}
