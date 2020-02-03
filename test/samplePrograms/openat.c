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
  int fd = withError(syscall(SYS_openat, AT_FDCWD, "./temp.txt", O_CREAT|O_WRONLY|O_TRUNC),
                     "openat1");

  int fd2 = withError(syscall(SYS_openat, AT_FDCWD, "./temp2.txt", O_CREAT|O_WRONLY|O_TRUNC),
                     "openat2");

  struct stat myStat;
  withError(fstat(fd, &myStat), "fstat");
  struct stat myStat2;
  withError(fstat(fd2, &myStat2), "fstat");

  time_t time = myStat.st_mtime;
  time_t time2 = myStat2.st_mtime;

  system("rm -f temp.txt");
  system("rm -f temp2.txt");

  printf("Modified time temp.txt: %ld\n", time);
  printf("Modified time temp2.txt: %ld\n", time2);

  return 0;
}

int withError(int returnCode, char* call){
  if(returnCode == -1){
    printf("Unable to %s file: %s", call, strerror(errno));
    exit(1);
  }

  return returnCode;
}
