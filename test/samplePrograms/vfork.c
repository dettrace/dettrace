#include <stdio.h>
#include <sys/types.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <time.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>

// Program testing ordering for multiple processes.
// Parent should print pid of 1.
// Child should print pid of 2.
// Child's child should print pid of 3.
int main(void){
  pid_t pid = vfork();
  if(pid == -1){
    printf("Fork failed, reason:\n%s\n", strerror(errno));
    exit(1);
  }

  if(pid == 0){
    _exit(2);
  }else{
    printf("Parent: My pid: %d\n", getpid());
    printf("Parent: My child's pid: %d\n", pid);
  }
  return 0;
}
