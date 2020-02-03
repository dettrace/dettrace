
#include <stdlib.h>
#include <sys/types.h>
#include <signal.h>
#include <assert.h>

int main(int argc, char** argv) {

  assert(2 == argc);
  char* endptr = NULL;
  int signum = (int) strtol(argv[1], &endptr, 10);
  assert(endptr != argv[1] && signum != 0 && "invalid argument");
  
  kill(0/*my process group, i.e., me*/, signum);
  
  return 0;
}
