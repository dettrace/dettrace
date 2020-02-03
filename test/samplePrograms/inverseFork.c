#include <stdio.h>
#include <sys/types.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <time.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>

#include <sys/types.h>
#include <sys/wait.h>

// Program testing ordering for processes, have child wait for child to finish.
// Parent should print pid of 1.
// Child should print pid of 2.
int main(void){
  pid_t pid = fork();
  if(pid == -1){
    printf("Fork failed, reason:\n%s\n", strerror(errno));
    exit(1);
  }

  if(pid == 0){
    sleep(2);
    printf("Child: My pid: %d\n", getpid());
  }
  else{
    printf("Parent: My pid: %d\n", getpid());
  }
  return 0;
}
