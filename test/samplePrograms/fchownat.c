#include <fcntl.h>           /* Definition of AT_* constants */
#include <unistd.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>

// int fchownat(int dirfd, const char *pathname,
// uid_t owner, gid_t group, int flags);

int main(){
  uid_t uid = getuid();
  uid_t gid = getgid();
  printf("uid = %d\n", uid);
  printf("gid = %d\n", gid);

  if(-1 == fchownat(AT_FDCWD, "file.txt", uid, gid, AT_SYMLINK_NOFOLLOW)){
    fprintf(stderr, "fchownat error: %s\n", strerror(errno));
    return 1;
  }
  printf("Success\n");
  return 0;
}
