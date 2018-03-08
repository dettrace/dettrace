#include <sys/random.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>

int main(){
  size_t length = 100;
  char randomBuf[length];
  unsigned int noFlags = 0;
  ssize_t ret = getrandom(randomBuf, length, noFlags);
  if(ret == -1){
    printf("Error: %s\n", strerror(errno));
  }

  printf("Random: \"");
  for(int i = 0; i < length; i++){
    printf("%d ", randomBuf[i]);
  }
  printf("\"");
  return 0;
}
