#include <sys/types.h>

#include "rnr_loader.hpp"
#include "util.hpp"
#include "utilSystemCalls.hpp"

// TODO: Currently passing PID into prehook and posthook for both PID and TIG
// arguments. Fix this.

// Fingerprinter State
static bool isNoop = false;
static int noopSyscall = -1;
static long noopRetval = -1;

bool rnr::callPreHook(
    void* user_data,
    SysEnter sysenter,
    int syscallNumber,
    globalState& gs,
    state& s,
    ptracer& t,
    scheduler& sched) {
  struct SyscallState syscallState;
  syscallState.noop = false;
  auto regs = t.getRegs();

  long prehook_retval = sysenter(
      user_data, &syscallState, s.traceePid, s.traceePid, syscallNumber,
      regs.rdi, regs.rsi, regs.rdx, regs.r10, regs.r8, regs.r9);
  // If fingerprinter indicates that the syscall shouldn't be run,
  // cancel the syscall and set the return value
  if (syscallState.noop) {
    isNoop = true;
    noopSyscall = syscallNumber;
    noopRetval = prehook_retval;
    replaceSystemCallWithNoop(gs, s, t);
    t.setReturnRegister((uint64_t)prehook_retval);
  }
  // Return flag indicating whether to run post-hook
  return true;
}

void rnr::callPostHook(
    void* user_data,
    SysExit sysexit,
    int syscallNumber,
    globalState& gs,
    state& s,
    ptracer& t,
    scheduler& sched) {
  struct SyscallState syscallState;
  syscallState.noop = false;
  if (isNoop) {
    t.changeSystemCall((uint64_t)noopSyscall);
    t.setReturnRegister((uint64_t)noopRetval);
    isNoop = false;
  }
  auto regs = t.getRegs();
  sysexit(
      user_data, &syscallState, s.traceePid, s.traceePid, regs.orig_rax,
      (long)regs.rax, regs.rdi, regs.rsi, regs.rdx, regs.r10, regs.r8, regs.r9);
}
