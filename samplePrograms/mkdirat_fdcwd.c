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
#define file "mkdirat_dirfd_temp_dir"

// mkdirat using AT_FDCWD

int main(){
  /* withError(mkdir(file"2", file, S_IRWXU), "mkdirat"); */
  int dirfd = withError(open(".", O_DIRECTORY | O_RDONLY), "open");
  withError(mkdirat(dirfd, file, S_IRWXU), "mkdirat");

  struct stat myStat;
  withError(stat(file, &myStat), "stat");
  time_t mtime = myStat.st_mtime;

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
