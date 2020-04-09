#include <iostream>
#include <string>

#include <fcntl.h>
#include <pthread.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "PRNG.hpp"
#include "devrand.hpp"
#include "util.hpp"

RandThread::RandThread(const std::string& fifo, unsigned short seed)
    : fifo{fifo},
      seed(seed),
      thread_mutex(PTHREAD_MUTEX_INITIALIZER),
      thread_ready(PTHREAD_COND_INITIALIZER) {
  // NB: we copy *FifoPath to the heap as our stack storage goes away: these
  // allocations DO get leaked If we wanted to not leak them, devRandThread
  // could copy to its stack and free the heap copy
  pthread_mutex_lock(&thread_mutex);
  doWithCheck(
      pthread_create(&thread, NULL, runThread, this),
      "pthread_create /dev/random pthread");
  pthread_cond_wait(&thread_ready, &thread_mutex);
  // we should unlock then lock the mutex again, but just leave the mutex
  // locked assuming: unlock -> lock = ID?
  pthread_mutex_unlock(&thread_mutex);
  pthread_mutex_destroy(&thread_mutex);
}

void RandThread::shutdown() {
  // We should check the return value, but we shouldn't throw exceptions in a
  // destructor.
  pthread_cancel(thread);
}

/**
 * Thread that writes pseudorandom output to a /dev/[u]random fifo.
 */
void* RandThread::runThread(void* data_) {
  RandThread* t = (RandThread*)data_;

  pthread_mutex_lock(&t->thread_mutex);

  // allow this thread to be unilaterally killed when tracer exits
  int oldCancelType;
  doWithCheck(
      pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, &oldCancelType),
      "pthread_setcanceltype");

  // fprintf(stderr, "[devRandThread] using fifo  %s, seed: %x\n", fifo,
  // param->seed);

  PRNG prng(t->seed);

  uint32_t totalBytesWritten = 0;
  uint16_t random = 0;
  bool getNewRandom = true;

  // NB: if the fifo is ever closed by all readers/writers, then contents
  // buffered within it get dropped. This leads to nondeterministic results, so
  // we always keep the fifo open here. We open the fifo for writing AND reading
  // as that eliminates EPIPE ("other end of pipe closed") errors when the
  // tracee has closed the fifo and we call write(). Instead, our write() call
  // will block once the fifo fills up. Once a tracee starts reading, the buffer
  // will drain and our write() will get unblocked. However, no bytes should get
  // lost during this process, ensuring the tracee(s) always see(s) a
  // deterministic sequence of reads.
  int fd = open(t->fifo.c_str(), O_RDWR);
  if (fd == -1) {
    auto err = std::string("open: ") + t->fifo;
    sysError(err.c_str());
  }
  pthread_cond_signal(&t->thread_ready);
  pthread_mutex_unlock(&t->thread_mutex);

  while (true) {
    if (getNewRandom) {
      random = prng.get();
    }
    int bytesWritten = write(fd, &random, 2);
    if (2 != bytesWritten) {
      perror("[devRandThread] error writing to fifo");
      // need to try writing these bytes again so that the fifo generates
      // deterministic output
      getNewRandom = false;

    } else {
      fsync(fd);
      getNewRandom = true;
      totalBytesWritten += 2;
      // printf("[devRandThread] wrote %u bytes so far...\n",
      // totalBytesWritten);
    }
  }

  close(fd);
  return NULL;
}
