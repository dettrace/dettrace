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
  withError(mkdir("temp_dir", S_IRWXU), "mkdir");

  struct stat myStat;
  withError(stat("temp_dir/", &myStat), "stat");
  time_t mtime = myStat.st_mtime;

  system("rm -rf temp_dir");
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
