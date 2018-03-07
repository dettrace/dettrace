#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <assert.h>

/* 
Program that uses fork to create two processes that read from the same pipe. 
Should raise an error with dettrace.
*/

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
  

  // both parent and child read from the pipe

  // close the write end
  rv = close(fd[1]);
  assert(0 == rv);
    
  int bytesRead;
  char readbuffer[79]; // prime, to encourage partial results from read()

  do {
    bytesRead = read(fd[0], readbuffer, sizeof(readbuffer));
    assert(-1 != bytesRead);
    // NB: bytesRead is often partial but not EOF
    //assert(bytesRead == sizeof(readbuffer) || bytesRead == 0);
    for (int i = 0; i < bytesRead; i++) {
      printf("%x", readbuffer[i]);
    }
    printf("\n");
  } while (0 != bytesRead); // EOF

  // close the read end
  rv = close(fd[0]);
  assert(0 == rv);
  
  return 0;
}
