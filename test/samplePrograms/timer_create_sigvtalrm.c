#define _GNU_SOURCE

#include <stdlib.h>
#include <signal.h>
#include <stdio.h>
#include <stdbool.h>
#include <time.h>
#include <assert.h>
#include <ucontext.h>
#include <stdatomic.h>

atomic_int counter = 0;

static void handle_alarm(int sig, siginfo_t *si, void *ctxt) {
  printf("counter=%d\n", atomic_load(&counter));

  printf("Received signal %d\n siginfo_t fields: signo:%d errno:%d code:%d pid:%d uid:%d status:%d utime:%ld stime:%ld value:%p int:%d ptr:%p overrun:%d timerid:%d addr:%p band:%ld fd:%d addr_lsb:%d lower:%p upper:%p call_addr:%p syscall:%d uarch:%u\n",
         sig, 
         si->si_signo, si->si_errno, si->si_code, si->si_pid, si->si_uid, si->si_status,
         si->si_utime, si->si_stime, si->si_value.sival_ptr, si->si_int, si->si_ptr, si->si_overrun, si->si_timerid,
         si->si_addr, si->si_band, si->si_fd, si->si_addr_lsb, si->si_lower, si->si_upper,
         si->si_call_addr, si->si_syscall, si->si_arch);

  ucontext_t* c = (ucontext_t*) ctxt;
  printf("context: R8:%llx, R9:%llx, R10:%llx, R11:%llx, R12:%llx, R13:%llx, R14:%llx, R15:%llx\n RDI:%llx, RSI:%llx, RBP:%llx, RBX:%llx, RDX:%llx, RAX:%llx, RCX:%llx, RSP:%llx, RIP:%llx\n",
         c->uc_mcontext.gregs[REG_R8],
         c->uc_mcontext.gregs[REG_R9],
         c->uc_mcontext.gregs[REG_R10],
         c->uc_mcontext.gregs[REG_R11],
         c->uc_mcontext.gregs[REG_R12],
         c->uc_mcontext.gregs[REG_R13],
         c->uc_mcontext.gregs[REG_R14],
         c->uc_mcontext.gregs[REG_R15],
         c->uc_mcontext.gregs[REG_RDI],
         c->uc_mcontext.gregs[REG_RSI],
         c->uc_mcontext.gregs[REG_RBP],
         c->uc_mcontext.gregs[REG_RBX],
         c->uc_mcontext.gregs[REG_RDX],
         c->uc_mcontext.gregs[REG_RAX],
         c->uc_mcontext.gregs[REG_RCX],
         c->uc_mcontext.gregs[REG_RSP],
         c->uc_mcontext.gregs[REG_RIP]);
  
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
  int rv = sigaction(SIGVTALRM, &sa, NULL);  
  assert( 0 == rv );
  
  // send our process a SIGVTALRM
  struct sigevent se;
  se.sigev_notify = SIGEV_SIGNAL;
  se.sigev_signo = SIGVTALRM;
  se.sigev_value.sival_int = 42;
  
  timer_t timerid;  
  rv = timer_create(CLOCK_THREAD_CPUTIME_ID, &se, &timerid);
  printf("timer_create returned %d\n", rv);
  assert( 0 == rv );

  printf("created timerid %p\n", timerid);
  
  struct itimerspec ts;
  ts.it_interval.tv_sec = ts.it_interval.tv_nsec = 0; // 1-shot timer
  ts.it_value.tv_sec = ts.it_value.tv_nsec = 1; // 1 second from now
  rv = timer_settime(timerid, 0, &ts, NULL);
  assert( 0 == rv );

  while (true) {
    atomic_fetch_add(&counter, 1);
  }
  
  return 0;
}
