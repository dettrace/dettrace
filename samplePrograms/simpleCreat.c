#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <err.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/syscall.h>   /* For SYS_xxx definitions */

int withError(int returnCode, char* call);

int main(){
  int fd = withError(creat("temp1.txt", S_IRWXU), "creat");
  struct stat myStat;

  withError(fstat(fd, &myStat), "fstat");
  time_t time = myStat.st_mtime;
  system("rm -f temp.txt");

  printf("mtime %ld\n", time);
  return 0;
}

int withError(int returnCode, char* call){
  if(returnCode == -1){
    printf("Unable to %s file: %s", call, strerror(errno));
    exit(1);
  }

  return returnCode;
}
