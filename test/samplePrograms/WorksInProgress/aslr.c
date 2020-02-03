
// Evertime the binary is changed the address is moved a little bit. So this is not ready
// to be integrated with our unit tests.

#include<stdio.h>

int main(){
  int x;
  printf("My address: %p\n", &x);
}
