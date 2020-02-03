#include <stdio.h>
#include <sys/types.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <time.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <sched.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>

int main(){
  size_t length = 100;
  char randomBuf[length];
  unsigned int noFlags = 0;
#ifdef SYS_getrandom
  ssize_t ret = syscall(SYS_getrandom, randomBuf, length, noFlags);
  if(ret == -1){
    printf("Error: %s\n", strerror(errno));
  }
#endif

  printf("Random: \"");
  for(int i = 0; i < length; i++){
    printf("%d ", randomBuf[i]);
  }
  printf("\"");
  return 0;
}
