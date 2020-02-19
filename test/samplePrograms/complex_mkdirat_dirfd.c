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

void print_mtime(char* file, int dirfd);
#define dir "mkdirat_temp_dir"


// complex example: mkdirat using a custom fd from open on a path that is not CWD

int main(){
  withError(mkdirat(AT_FDCWD, dir, S_IRWXU), "mkdirat");
  int dirfd = open(dir, O_DIRECTORY | O_RDONLY);
  withError(mkdirat(dirfd, dir, S_IRWXU), "mkdirat");

  print_mtime(dir, AT_FDCWD);
  print_mtime(dir, dirfd);

  system("rm -rf "dir);
  return 0;
}

int withError(int returnCode, char* call){
  if(returnCode == -1){
    printf("Unable to %s file: %s\n", call, strerror(errno));
    exit(1);
  }

  return returnCode;
}

void print_mtime(char* file, int dirfd){
  struct stat st;
  withError(fstatat(dirfd, dir, &st, 0), "fstatat");
  printf("file mtime tv_sec = %ld, tv_nsec = %ld\n",
         st.st_mtim.tv_sec, st.st_mtim.tv_nsec);
}
