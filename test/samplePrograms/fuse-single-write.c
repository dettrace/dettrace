#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <assert.h>

#include <sys/syscall.h>    /* For SYS_write, etc */


/* 
Program that uses write() to write a file.
*/

int main(int argc, char *argv[]) {

  assert(2 == argc);
  int fd = open(argv[1], O_RDWR);
  assert( -1 != fd );
    
  int bytesWritten;
  char bufferToWrite[4097];

  bytesWritten = write(fd, bufferToWrite, sizeof(bufferToWrite));
  assert(-1 != bytesWritten);
  printf("write() returned %d bytes...\n", bytesWritten);
  return 0;
}
