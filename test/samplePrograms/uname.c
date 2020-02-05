#include <sched.h>

#include <sys/utsname.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>

int main(){
  struct utsname buf;
  int ret = uname(&buf);
  if(ret == -1){
    printf("Uname failed\nReason: %s\n", strerror(errno));
  }

  printf("Operating name: %s\n", buf.sysname);
  printf("Node name: %s\n", buf.nodename);
  printf("Operating system release: %s\n", buf.release);
  printf("Operating system version: %s\n", buf.version);
  printf("Hardware identifier: %s\n", buf.machine);

}
