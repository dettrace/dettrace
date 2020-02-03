#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <assert.h>

int main() {

  alarm( 1/*second*/ );

  while (1) {}
  printf("This should never print under dettrace!\n");
  
  return 0;
}
