#include <assert.h>
#include <fcntl.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

void readRand(char* path) {
  char randomBuf[3907];

  int fd = open(path, O_RDONLY);
  if(fd < 0){
    perror("open() error");
    close(fd);
    return;
  }

  size_t bytesRead = read(fd, randomBuf, sizeof(randomBuf));
  assert(sizeof(randomBuf) == bytesRead);
  close(fd);
  for(int i = 0; i < sizeof(randomBuf); i++){
    printf("%d ", randomBuf[i]);
  }
  printf("\n");
}

int main(){
  // read about 117KB from each fifo, to exceed default fifo buffer size of 64KB
  for (int i = 0; i < 30; i++) {
    readRand("/dev/random");
    readRand("/dev/urandom");
  }
  return 0;
}
