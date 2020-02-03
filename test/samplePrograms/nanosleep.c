#include <stdio.h>
#include <time.h>

int main(){
  // Big number, dettrace will turn it to zero. So if it's takes any amount of time,
  // or times out in our tests, dettrace did something wrong...
  const struct timespec req = { 100, 1};
  struct timespec rem = {0};
  int ret = nanosleep(& req, & rem);
  printf("nanosleep ret %d\n", ret);
  return 0;
}
