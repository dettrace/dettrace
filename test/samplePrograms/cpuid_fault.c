#include <sys/types.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/prctl.h>
#include <asm/prctl.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <cpuid.h>
#include <signal.h>
#include <string.h>

#include "util/assert.h"

int arch_prctl(int code, unsigned long addr);

int cpuid_fault_supported(void) {
#define BUFF_SIZE 4096
  int fd;
  char buffer[1 + BUFF_SIZE];

  fd = open("/proc/cpuinfo", O_RDONLY);
  assert(fd >= 0);

  long nb = read(fd, buffer, BUFF_SIZE);
  assert(nb >= 0);
  buffer[nb] = 0;

  close(fd);

  char* p = buffer;
  char* end = &buffer[nb];

  int found_flags = 0;

  while (p < end) {
    char* q = strchr(p, '\n');
    if (!q) break;
    p[q-p] = '\0';
    if (strncmp(p, "flags", 5) == 0) {
      found_flags = 1;
      break;
    } else {
      p = 1 + q;
    }
  }
#undef BUFF_SIZE

  if (!found_flags) {
    return 0;
  }

  // skip any chars
  do {
    ++p;
  } while(p < end && *p && *p != ':');

  char* q;
  while (p < end && (q = strsep(&p, " \t")) != NULL) {
      if (strncmp(q, "cpuid_fault", strlen("cpuid_fault")) == 0) {
	return 1;
      }
  }
  return 0;
}

static void sigsegv_action(int signo, siginfo_t* siginfo, void* ucontext) {
  _exit(0);
}

int main(int argc, char* argv[])
{
  if (!cpuid_fault_supported()) {
    return 0;
  }

  assert(arch_prctl(ARCH_SET_CPUID, 0) == 0);

  unsigned long eax, ebx, ecx, edx;

  struct sigaction sa;
  memset(&sa, 0, sizeof(sa));

  sa.sa_flags = SA_ONESHOT | SA_RESTART | SA_SIGINFO | SA_RESETHAND;
  sa.sa_sigaction = sigsegv_action;
  assert(sigaction(SIGSEGV, &sa, NULL) == 0);

  // should segfault
  __cpuid(0x1, eax, ebx, ecx, edx);
  printf("eax=%lx\n", eax);

  return 0;
}
