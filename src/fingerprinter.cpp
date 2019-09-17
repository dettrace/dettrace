#include "fingerprinter.hpp"
#include "utilSystemCalls.hpp"

using namespace std;

// TODO: Currently passing PID into prehook and posthook for both PID and TIG arguments. Fix this.

bool fingerprinter::callPreHook(int syscallNumber, globalState& gs, state& s, ptracer& t, scheduler& sched){
  struct SyscallState syscallState;
  syscallState.noop = false;
  auto regs = t.getRegs();
  auto prehook_retval = fingerprinter_prehook(
    &syscallState, s.traceePid, s.traceePid, syscallNumber, (long)regs.rax, regs.rdi,
    regs.rsi, regs.rdx, regs.r10, regs.r8,  regs.r9);
  // If fingerprinter indicates that the syscall shouldn't be run,
  // cancel the syscall and set the return value
  if(syscallState.noop) {
    cancelSystemCall(gs, s, t);
    t.writeRax((uint64_t)prehook_retval);
  }
  // Return flag indicating whether to run post-hook
  return true;
}

void fingerprinter::callPostHook(int syscallNumber, globalState& gs, state& s, ptracer& t, scheduler& sched){
  struct SyscallState syscallState;
  syscallState.noop = false;
  auto regs = t.getRegs();
  fingerprinter_posthook(
    &syscallState, s.traceePid, s.traceePid, syscallNumber, (long)regs.rax, regs.rdi,
    regs.rsi, regs.rdx, regs.r10, regs.r8, regs.r9);
}

// Implementation is required due to captured_syscall being exposed from lib,
// even though it's not used here in DetTrace
extern "C" long untraced_syscall(
  int no,
  unsigned long a0,
  unsigned long a1,
  unsigned long a2,
  unsigned long a3,
  unsigned long a4,
  unsigned long a5
) {
  return 0;
}
