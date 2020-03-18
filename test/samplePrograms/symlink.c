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
#define symlink_target "./symlink_target.txt"
#define symlink_name "./symlink.txt"

// test symlink modified time.

int main(){
  withError(system("touch "symlink_target ), "create target file");
  char* fulltarget = realpath(symlink_target, NULL);
  if (fulltarget == NULL) {
    printf("Unable to get full path.");
    return 1;
  }

  withError(symlink(fulltarget, symlink_name), "create symlink");

  struct stat st;
  withError(lstat(symlink_name, &st), "stat");
  // ino_t inode = st.st_ino;

  withError(unlink(symlink_target), "Unlink "symlink_target);
  withError(unlink(symlink_name), "Unlink symlink");

  printf("mtime tv_sec = %ld, tv_nsec = %ld\n",
         st.st_mtim.tv_sec, st.st_mtim.tv_nsec);
  return 0;
}

int withError(int returnCode, char* call){
  if(returnCode != 0){
    printf("Unable to %s: %s", call, strerror(errno));
    exit(1);
  }

  return returnCode;
}
