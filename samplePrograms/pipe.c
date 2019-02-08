#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <assert.h>

/*
Program that uses fork to create one process that writes the pipe and another
that reads from it. Writer sends pseudo-random bytes through the pipe, and reader
reads from the pipe and echoes output to stdout (formatted with %x). In the reader,
the results of each call to read() appears on its own line, so the output is only
deterministic if read() calls are deterministic.
*/

// the number of bytes to send through the pipe
const unsigned BYTES_TO_SEND = 5000;

int main(void) {
  int     fd[2], rv;
  pid_t   childpid;

  // fd[0] is for reading, fd[1] for writing
  rv = pipe(fd);
  assert(0 == rv);

  if ((childpid = fork()) == -1) {
    perror("fork");
    return 1;
  }

  if (childpid == 0) { // child: write random bytes to pipe
    // close the read end
    rv = close(fd[0]);
    assert(0 == rv);

    // PRNG from https://en.wikipedia.org/wiki/Linear-feedback_shift_register#Galois_LFSRs
    // 16-bit PRNG will generate 128KB unique bytes before repeating.
    // Can scale this if needed to 32-bit for 2^34 unique bytes.
    uint16_t start_state = 0xACE1u;  // Any nonzero start state will work.
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

    rv = close(fd[1]);
    assert(0 == rv);

    return 0;

  } else { // parent: read from pipe
    // close the write end
    rv = close(fd[1]);
    assert(0 == rv);

    int bytesRead;
    unsigned char readbuffer[79]; // prime, to encourage partial results from read()

    do {
      bytesRead = read(fd[0], readbuffer, sizeof(readbuffer));
      assert(-1 != bytesRead);
      // NB: bytesRead is often partial but not EOF
      //assert(bytesRead == sizeof(readbuffer) || bytesRead == 0);
      for (int i = 0; i < bytesRead; i++) {
        printf("%02x", readbuffer[i]);
      }
      printf("\n");
    } while (0 != bytesRead); // EOF
  }

  return 0;
}
