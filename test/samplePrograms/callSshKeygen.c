#include <stdlib.h>

int main(){
  // No error if file not found.
  system("rm -f thisKey");
  system("rm -f thisKey.pub");
  system("ssh-keygen -f thisKey -N \"\"");
}
