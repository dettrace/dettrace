#include <stdio.h>
#include <sys/types.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <time.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <wait.h>
#include <poll.h>

int doWithCheck(int returnValue, char* errorMessage);
void writeToPipe(int writeEnd, int childNum);
void readFromPipe(int pipefd);
void readFromEither(nfds_t nfds, int readEndParent, int readEndGrandparent, struct pollfd *fds);

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
      // array of pollfds, which are wrappers for fds
      struct pollfd fds[2];

      // set fds[1] to be the fd for readEndGrandparent
      fds[1].fd = readEndGrandparent;
      fds[1].events = POLLIN;

      // set fds[0] to be the fd for readEndParent
      fds[0].fd = readEndParent;
      fds[0].events = POLLIN;
      
      // read for the first time
      readFromEither(2, readEndParent, readEndGrandparent, fds);
      // reset revents bits to 0
      fds[0].revents &= 0;
      fds[1].revents &= 0;

      // read again
      readFromEither(2, readEndParent, readEndGrandparent, fds);

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
    (void) v;
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
  (void) v;
  return 0;
}

void readFromEither(nfds_t nfds, int readEndParent, int readEndGrandparent, struct pollfd *fds){
  // timeout is set to 0, poll will return immediately
  doWithCheck(poll(fds, nfds, 0), "poll");

  if(fds[0].revents & POLLIN){
    printf("parent pipe ready for reading!\n");
    readFromPipe(readEndParent);
  }
  else if(fds[1].revents & POLLIN){
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
    (void) bytes;
    if(buffer[0] == 1){
    }else if (buffer[0] == 2){
    }
  }
}
