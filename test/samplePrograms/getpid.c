#include <stdio.h>
#include <sys/types.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <time.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <sched.h>


int main(void){
  pid_t pid = getpid();
  printf("My pid: %d\n", pid);
}
