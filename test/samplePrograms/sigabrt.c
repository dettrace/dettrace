

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <ucontext.h>
#include <inttypes.h>

static void handler(int sig, siginfo_t *si, void *ctxt) {
  printf("Received signal %d\n siginfo_t fields: signo:%d errno:%d code:%d\n",
         sig, 
         si->si_signo, si->si_errno, si->si_code);
  
  // TODO: re-enable these extra checks if we switch to a run-twice-and-compare-outputs model
    /* printf("Other (technically undefined) siginfo_t fields: pid:%d uid:%d status:%d utime:%ld stime:%ld value:%p int:%d ptr:%p overrun:%d timerid:%d addr:%p band:%ld fd:%d addr_lsb:%d lower:%p upper:%p call_addr:%p syscall:%d uarch:%u\n", */
    /*      si->si_pid, si->si_uid, si->si_status, */
    /*      si->si_utime, si->si_stime, si->si_value.sival_ptr, si->si_int, si->si_ptr, si->si_overrun, si->si_timerid, */
    /*      si->si_addr, si->si_band, si->si_fd, si->si_addr_lsb, si->si_lower, si->si_upper, */
    /*      si->si_call_addr, si->si_syscall, si->si_arch); */

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

int main(int argc, char** argv) {

  struct sigaction sa;
  sa.sa_flags = SA_SIGINFO;
  sigemptyset(&sa.sa_mask);
  sa.sa_sigaction = handler;
  if (sigaction(SIGABRT, &sa, NULL) == -1) {
    printf("ERROR: sigaction() returned -1\n");
    return -1;
  }
  
  abort();
  
  return 0;
}
