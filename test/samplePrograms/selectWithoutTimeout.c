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
void readFromEither(int max_fd, int readEndParent, int readEndGrandparent, fd_set* rfds);

const int bytesToUse = 100;

int main(){
  int grandparentPipe[2];
  int parentPipe[2];
  doWithCheck(pipe(grandparentPipe), "pipe");
  doWithCheck(pipe(parentPipe), "pipe");

  int readEndGrandparent = grandparentPipe[0];
  int writeEndGrandparent = grandparentPipe[1];
  int readEndParent = parentPipe[0];
  int writeEndParent = parentPipe[1];

  // Forking Child 1
  pid_t pid1 = doWithCheck(fork(), "fork");

  printf("parent spawned\n");
  // Child 1: Fork Child 2
	// And also write to the second pipe.
  if(pid1 == 0){
    pid_t pid2 = doWithCheck(fork(), "fork");
    printf("grandchild spawned\n");

    // Grandchild
    if(pid2 == 0){
      fd_set rfds;
      int retVal;
      FD_ZERO(&rfds);
      FD_SET(readEndGrandparent, &rfds);
      FD_SET(readEndParent, &rfds);

      int max_fd = readEndGrandparent > readEndParent ?
        readEndGrandparent :
      	readEndParent;

      readFromEither(max_fd, readEndParent, readEndGrandparent, & rfds);

      FD_ZERO(&rfds);
      FD_SET(readEndGrandparent, &rfds);
      FD_SET(readEndParent, &rfds);
      readFromEither(max_fd, readEndParent, readEndGrandparent, & rfds);

      return 0;
    }
    // Parent
    printf("parent attempting to write...\n");
    writeToPipe(writeEndParent, 2);
    printf("parent wrote!\n");
    fflush(NULL);
    int child1Status;

    printf("parent is waiting\n");
    int v = waitpid(pid2, &child1Status, 0);
    return 0;
  }

  // Parent = 1
  printf("grandparent attempting to write...!\n");
  writeToPipe(writeEndGrandparent, 1);
  printf("grandparent wrote!\n");

  int parentStatus;
  //wait(&parentStatus);
  //waitpid(pid1, &parentStatus, 0);
  printf("grandparent is waiting\n");
  int v = waitpid(pid1, &parentStatus, 0);
  return 0;
}

void readFromEither(int max_fd, int readEndParent, int readEndGrandparent, fd_set* rfds){
  doWithCheck(select(max_fd + 1, rfds, NULL, NULL, NULL), "select");

  if(FD_ISSET(readEndParent, rfds)){
    printf("parent pipe ready for reading!\n");
    readFromPipe(readEndParent);
  }
  else if(FD_ISSET(readEndGrandparent, rfds)){
    printf("grandparent pipe ready for reading!\n");
    readFromPipe(readEndGrandparent);
  }
  else{
    printf("Nothing ready\n");
  }

  return;
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
    int bytes = doWithCheck(write(writeEnd, buffer, bytesToUse), "write");
    if(bytesToUse != bytes){
      fprintf(stderr, "Read %d bytes, expected %d...", bytes, bytesToUse);
      exit(1);
    }
  }
}

void readFromPipe(int pipefd){
  char buffer[bytesToUse];
  for(int i = 0; i < 5; i++){
    int bytes = doWithCheck(read(pipefd, buffer, bytesToUse), "read");
    if(buffer[0] == 1){
    }else if (buffer[0] == 2){
    }
  }
}
