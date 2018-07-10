#include <stdio.h>

int main()
{
  unsigned int rand = 100;
  char ok;

  asm volatile("rdrand %0; setc %1"
   : "=r" (rand), "=qm" (ok));

   if (ok) {
    rand = rand % 99;
    if (rand > 0 && rand <= 99)
     printf("pass\n");
   }
}
