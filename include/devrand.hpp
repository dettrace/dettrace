#ifndef DEVRAND_H
#define DEVRAND_H

#include <string>

#include <pthread.h>

class RandThread {
private:
  std::string fifo;
  unsigned short seed;

  pthread_t thread;
  pthread_mutex_t thread_mutex;
  pthread_cond_t thread_ready;

  static void* runThread(void* data);

public:
  RandThread(const std::string& fifo, unsigned short seed);

  // Shuts down the thread.
  void shutdown();

  const std::string& path() const { return fifo; }
};

#endif // DEVRAND_H
