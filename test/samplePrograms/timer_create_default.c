

#include <stdlib.h>
#include <signal.h>
#include <stdio.h>
#include <stdbool.h>
#include <time.h>
#include <assert.h>
#include <ucontext.h>
#include <stdatomic.h>

#include <unistd.h> /* For syscall() */
#include <sys/syscall.h> /* For SYS_xxx definitions */

atomic_int counter = 0;

static void handle_alarm(int sig, siginfo_t *si, void *ctxt) {
  printf("counter=%d\n", atomic_load(&counter));

  // TODO: we are currently FAILING to rewrite the si_timerid here, which is leaking the raw kernel value.
  // signo=14 is SIGALRM:
  printf("Received signal %d\n siginfo_t fields: signo:%d errno:%d code:%d overrun:%d si_timerid:%d\n",
         sig, si->si_signo, si->si_errno, si->si_code, si->si_overrun, si->si_timerid);

  // TODO: re-enable these extra checks if we switch to a run-twice-and-compare-outputs model
  /* printf("(technically undefined) siginfo_t fields: pid:%d uid:%d status:%d utime:%ld stime:%ld value:%p int:%d ptr:%p addr:%p band:%ld fd:%d addr_lsb:%d lower:%p upper:%p call_addr:%p syscall:%d uarch:%u\n", */
  /*        si->si_pid, si->si_uid, si->si_status, */
  /*        si->si_utime, si->si_stime, si->si_value.sival_ptr, si->si_int, si->si_ptr,  */
  /*        si->si_addr, si->si_band, si->si_fd, si->si_addr_lsb, si->si_lower, si->si_upper, */
  /*        si->si_call_addr, si->si_syscall, si->si_arch); */

  /* ucontext_t* c = (ucontext_t*) ctxt; */
  /* printf("context: R8:%llx, R9:%llx, R10:%llx, R11:%llx, R12:%llx, R13:%llx, R14:%llx, R15:%llx\n RDI:%llx, RSI:%llx, RBP:%llx, RBX:%llx, RDX:%llx, RAX:%llx, RCX:%llx, RSP:%llx, RIP:%llx\n", */
  /*        c->uc_mcontext.gregs[REG_R8], */
  /*        c->uc_mcontext.gregs[REG_R9], */
  /*        c->uc_mcontext.gregs[REG_R10], */
  /*        c->uc_mcontext.gregs[REG_R11], */
  /*        c->uc_mcontext.gregs[REG_R12], */
  /*        c->uc_mcontext.gregs[REG_R13], */
  /*        c->uc_mcontext.gregs[REG_R14], */
  /*        c->uc_mcontext.gregs[REG_R15], */
  /*        c->uc_mcontext.gregs[REG_RDI], */
  /*        c->uc_mcontext.gregs[REG_RSI], */
  /*        c->uc_mcontext.gregs[REG_RBP], */
  /*        c->uc_mcontext.gregs[REG_RBX], */
  /*        c->uc_mcontext.gregs[REG_RDX], */
  /*        c->uc_mcontext.gregs[REG_RAX], */
  /*        c->uc_mcontext.gregs[REG_RCX], */
  /*        c->uc_mcontext.gregs[REG_RSP], */
  /*        c->uc_mcontext.gregs[REG_RIP]); */
  
  exit(0);
}

int main() {

  // establish SIGALRM handler
  sigset_t sigset;
  sigemptyset( &sigset );
  struct sigaction sa;
  sa.sa_mask = sigset;
  sa.sa_flags = SA_SIGINFO;
  sa.sa_sigaction = handle_alarm;
  int rv = sigaction(SIGALRM, &sa, NULL);  
  assert( 0 == rv );
  
  timer_t timerid = 0;
  printf("initial timerid: %lu\n", (unsigned long)timerid);

  // by default, send our process a SIGALRM
  rv = syscall(SYS_timer_create, CLOCK_MONOTONIC, NULL, &timerid);
  printf("timer_create returned %d\n", rv);
  assert( 0 == rv );

  // TODO: Apparent portability bug here (see issue 262)
  printf("created timerid %lu\n", (unsigned long)timerid);

  // TODO: between different machines / ubuntu versions, we're getting different addresses here.  
  // for example, 0x7fffffffeba8 vs 0x7fffffffebc0
  // here:   https://dev.azure.com/upenn-acg/detTrace/_build/results?buildId=512&view=logs&j=12f1170f-54f2-53f3-20dd-22fc7dff55f9&t=bd05475d-acb5-5619-3ccb-c46842dbc997
  // But these surely have different fingerprints/hashes, because there must be different input files in the base image.
  printf("  (NONPORTABLE) residing at address %p, size %ld\n",
	 &timerid, sizeof(timerid));
  
  struct itimerspec ts;
  ts.it_interval.tv_sec = ts.it_interval.tv_nsec = 0; // 1-shot timer
  ts.it_value.tv_sec = ts.it_value.tv_nsec = 1; // 1 second from now
  rv = syscall(SYS_timer_settime, timerid, 0, &ts, NULL);
  printf("after timer_settime, timerid %lu\n", (unsigned long)timerid);  
  
  assert( 0 == rv );

  while (true) {
    atomic_fetch_add(&counter, 1);
  }
  
  return 0;
}
