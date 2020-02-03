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
#define file "mknod.txt"

int main(){
  withError(mknod(file, S_IFREG, 0), "cannot mknod");

  struct stat myStat;
  withError(lstat(file, &myStat), "stat");
  time_t mtime = myStat.st_mtime;
  withError(unlink(file), "Unlink "file);

  printf("mtime %ld\n", mtime);

  return 0;
}

int withError(int returnCode, char* call){
  if(returnCode == -1){
    printf("Unable to %s: %s", call, strerror(errno));
    exit(1);
  }

  return returnCode;
}
