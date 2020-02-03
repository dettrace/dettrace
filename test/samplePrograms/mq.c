/* link with -lrt */
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <mqueue.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <assert.h>

static const char mq_name[] = "/posix-message-queue";
static const unsigned BYTES_TO_SEND = 5000;

#define MSGSIZE_MAX 8192
#define MQ_MAXMSG   8

int main(void) {
  pid_t   childpid;
  ssize_t rv;
  mqd_t mqd;
  
  struct mq_attr attr;
  memset(&attr, 0, sizeof(struct mq_attr));
  attr.mq_maxmsg = MQ_MAXMSG;
  attr.mq_msgsize = MSGSIZE_MAX;

  mqd = mq_open(mq_name, O_CREAT | O_RDWR | O_CLOEXEC | O_EXCL, 0644, &attr);
  if (mqd == -1) {
    perror("mq_open");
    exit(1);
  }

  mq_unlink(mq_name);

  if ((childpid = fork()) == -1) {
    perror("fork");
    exit(1);
  }

  if (childpid == 0) { // child: write random bytes
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

      rv = mq_send(mqd, (const char*)&lfsr, sizeof(lfsr), 0);
      if (rv == -1) {
	perror("mq_send:");
	exit(1);
      }

      bytesWritten += sizeof(lfsr);
    } while (bytesWritten < BYTES_TO_SEND);
    mq_close(mqd);
    return 0;
  } else {
    long bytesRead = 0;
    char readbuffer[1+MSGSIZE_MAX];
    do {
      unsigned prio;
      ssize_t received;
      received = mq_receive(mqd, readbuffer, sizeof(readbuffer), &prio);
      if (received == -1) {
	perror("mq_receive");
	exit(1);
      }
      for (int i = 0; i < received; i++) {
        printf("%02x", readbuffer[i] & 0xff);
      }
      printf("\n");
      bytesRead += received;
    } while (BYTES_TO_SEND > bytesRead); // EOF
    mq_close(mqd);
  }

  return 0;
}
