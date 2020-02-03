#include <stdlib.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <assert.h>

/*
Program that uses fork to create two processes that share a pipe, with different
combinations of writers/readers possible.
*/

// the number of bytes each writer sends through the pipe
const unsigned BYTES_TO_SEND = 1000;

// with child-runs-first scheduling, can only support (both-write parent-read)
// TODO: should add (one-write both-read) and (both-write both-read) variants, generated via CPP macros
#ifndef PARENT_WRITE
#define PARENT_WRITE false
#endif
#ifndef CHILD_WRITE
#define CHILD_WRITE false
#endif
#ifndef PARENT_READ
#define PARENT_READ false
#endif
#ifndef CHILD_READ
#define CHILD_READ false
#endif

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


  bool amChild = (0 == childpid);
  // FIRST, parent and/or child write to the pipe

  if ((amChild && CHILD_WRITE) || (!amChild && PARENT_WRITE)) {
    // PRNG from https://en.wikipedia.org/wiki/Linear-feedback_shift_register#Galois_LFSRs
    // 16-bit PRNG will generate 128KB unique bytes before repeating.
    // Can scale this if needed to 32-bit for 2^34 unique bytes.
    uint16_t start_state = (0 == childpid) ? 0xDEAD : 0xBEEF ;  // Any nonzero start state will work.
    uint16_t lfsr = start_state;
    unsigned bytesWritten = 0;

    do {
      unsigned lsb = lfsr & 1;
      lfsr >>= 1;
      lfsr ^= (-lsb) & 0xB400u;

      rv = write(fd[1], &lfsr, sizeof(lfsr));
      assert(-1 != rv);

      bytesWritten += rv;
    } while (bytesWritten < BYTES_TO_SEND);

  }
  // close the write end
  rv = close(fd[1]);
  assert(0 == rv);


  // SECOND, read from the pipe
  if ((amChild && CHILD_READ) || (!amChild && PARENT_READ)) {

    int bytesRead;
    unsigned char readbuffer[79]; // prime, to encourage partial results from read()

    do {
      bytesRead = read(fd[0], readbuffer, sizeof(readbuffer));
      assert(-1 != bytesRead);
      // NB: bytesRead is often partial but not EOF
      //assert(bytesRead == sizeof(readbuffer) || bytesRead == 0);
      printf("%s: ", 0 == childpid ? "child" : "parent");
      for (int i = 0; i < bytesRead; i++) {
        printf("%x", readbuffer[i]);
      }
      printf("\n");
    } while (0 != bytesRead); // EOF

  }
  // close the read end
  rv = close(fd[0]);
  assert(0 == rv);

  return 0;

}
