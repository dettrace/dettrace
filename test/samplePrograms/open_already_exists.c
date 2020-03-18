#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
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
  int fd = withError(open("temp.txt", O_CREAT|O_RDWR|O_TRUNC, S_IRWXU),
                     "open1");
  close(fd);
  int fd2 = withError(open("temp.txt", O_CREAT|O_RDWR|O_TRUNC),
                     "open2");

  int fd3 = withError(open("temp.txt", O_RDWR),
                     "open3");

  struct stat myStat;
  withError(fstat(fd, &myStat), "fstat");
  struct stat myStat2;
  withError(fstat(fd2, &myStat2), "fstat");
  struct stat myStat3;
  withError(fstat(fd3, &myStat3), "fstat");

  time_t time = myStat.st_mtime;
  time_t time2 = myStat2.st_mtime;
  time_t time3 = myStat3.st_mtime;

  system("rm -f temp.txt");

  printf("mtime %ld\n", time);
  printf("mtime2 %ld\n", time2);
  printf("mtime3 %ld\n", time3);

  return 0;
}

int withError(int returnCode, char* call){
  if(returnCode == -1){
    printf("Unable to %s file: %s", call, strerror(errno));
    exit(1);
  }

  return returnCode;
}
