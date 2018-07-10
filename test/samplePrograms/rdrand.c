#include <stdio.h>

int main()
{
  unsigned int rand = 100;
  char ok;

  asm volatile("rdrand %0; setc %1"
   : "=r" (rand), "=qm" (ok));

   if (ok) {
    printf("RDRAND value: %u\n", rand % 99);
   }
}
