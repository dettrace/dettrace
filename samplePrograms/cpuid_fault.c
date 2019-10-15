#include <sys/types.h>
#include <sys/syscall.h>
#include <sys/prctl.h>
#include <asm/prctl.h>
#include <assert.h>
#include <unistd.h>
#include <stdio.h>
#include <cpuid.h>
#include <signal.h>
#include <string.h>

int arch_prctl(int code, unsigned long addr);

static void sigsegv_action(int signo, siginfo_t* siginfo, void* ucontext) {
  const char msg[] = "got expected sigsegv\n\0";
  write(STDOUT_FILENO, msg, sizeof(msg));
  _exit(0);
}

int main(int argc, char* argv[])
{
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
