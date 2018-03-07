#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <assert.h>

/* 
Program that uses fork to create two processes that write to
the same pipe. Should raise an error with dettrace.
*/

// the number of bytes to send through the pipe
const unsigned BYTES_TO_SEND = 100;

int main(void) {
  int     fd[2], rv;
  pid_t   childpid;
  
  // fd[0] is for reading, fd[1] for writing
  rv = pipe(fd);
  assert(0 == rv);
  
  if ((childpid = fork()) == -1) {
    perror("fork");
    exit(1);
  }
  
  // both parent and child write to the pipe

  // close the read end
  rv = close(fd[0]);
  assert(0 == rv);

  uint32_t bytes = (childpid == 0) ? 0xDEAD : 0xBEEF ;
  unsigned bytesWritten = 0;
  do {
    rv = write(fd[1], &bytes, sizeof(bytes));
    assert(-1 != rv);
    bytesWritten += rv;
  } while (bytesWritten < BYTES_TO_SEND);

  // close write end
  rv = close(fd[1]);
  assert(0 == rv);
  
  return 0;
}
