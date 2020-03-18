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
#define file "mkdirat_temp_dir/"

// simple: mkdirat using a custom fd from open on path.

int main(){
  withError(mkdirat(AT_FDCWD, file, S_IRWXU), "mkdirat");

  struct stat myStat;
  withError(stat(file, &myStat), "stat");
  time_t mtime = myStat.st_mtime;
  // ino_t inode = myStat.st_ino;

  system("rm -rf "file);
  printf("mtime %ld\n", mtime);
  return 0;
}

int withError(int returnCode, char* call){
  if(returnCode == -1){
    printf("Unable to %s file: %s", call, strerror(errno));
    exit(1);
  }

  return returnCode;
}
