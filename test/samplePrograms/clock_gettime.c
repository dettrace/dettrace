// int clock_gettime(clockid_t clk_id, struct timespec *tp);
#include<unistd.h>
#include<time.h>
#include<stdio.h>

int main(){
  struct timespec res;
  clock_gettime(CLOCK_REALTIME, &res);
  printf("res: {.tv_sec = %lu, .tv_nsec = %lu}\n", res.tv_sec, res.tv_nsec);
  return 0;
}
