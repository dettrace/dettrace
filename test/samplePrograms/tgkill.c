
#include <stdlib.h>
#include <unistd.h>
#include <sys/syscall.h>

#include <assert.h>

int main(int argc, char** argv) {

  assert(2 == argc);
  char* endptr = NULL;
  int signum = (int) strtol(argv[1], &endptr, 10);
  assert(endptr != argv[1] && signum != 0 && "invalid argument");

  pid_t tid;
  tid = syscall(SYS_gettid);
  tid = syscall(SYS_tgkill, getpid(), tid, signum);
  
  return 0;
}
