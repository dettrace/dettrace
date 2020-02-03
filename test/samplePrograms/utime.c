#include <sched.h>
#include <stdlib.h>
#include <sys/utsname.h>
#include <stdio.h>
#include <sys/types.h>
#include <utime.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdint.h>
#include <sys/user.h>
#include <sys/vfs.h>
#include <sys/ptrace.h>
#include <sys/reg.h>     /* For constants ORIG_EAX, etc */
#include <string.h>
#include <sys/wait.h>
#include <sys/syscall.h>    /* For SYS_write, etc */

#include <sys/time.h>
#include <sys/sysinfo.h>
#include <sys/resource.h>

#include <unistd.h>
#include <sys/types.h>


int main(){
  char* test = "utimeTestFile.txt";
  system("touch utimeTestFile.txt");
  if(-1 == utime(test, NULL)){
    exit(1);
  }

  // Verify timestamp is zero:
  struct stat myStat;
  if(-1 == stat(test, &myStat)){
    exit(1);
  }

  if(myStat.st_atim.tv_sec != 0){
    printf("st_atim.tv_sec does not equal zero\n");
  }
  if(myStat.st_atim.tv_nsec != 0){
    printf("st_atim.tv_nsec does not equal zero\n");
  }
  if(myStat.st_mtim.tv_sec != 0){
    printf("st_atim.tv_sec does not equal zero\n");
  }
  if(myStat.st_mtim.tv_nsec != 0){
    printf("st_mtim.tv_nsec does not equal zero\n");
  }

  return 0;
}
