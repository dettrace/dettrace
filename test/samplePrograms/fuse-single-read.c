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
Program that uses read() to read a file.
*/

int main(int argc, char *argv[]) {

  assert(2 == argc);
  int fd = open(argv[1], O_RDONLY);
  assert( -1 != fd );
    
  int bytesRead;
  char readbuffer[4097];

  bytesRead = read(fd, readbuffer, sizeof(readbuffer));
  assert(-1 != bytesRead);
  printf("Read returned %d bytes...\n", bytesRead);
  return 0;
}
