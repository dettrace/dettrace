#include "fingerprinter.hpp"
#include "utilSystemCalls.hpp"

using namespace std;

bool fingerprinter::callPreHook(int syscallNumber, globalState& gs, state& s, ptracer& t, scheduler& sched){
  struct ProcessState processState;
  processState.tid = s.traceePid;
  auto regs = t.getRegs();
  fingerprinter_prehook(
    &processState, syscallNumber, (long)regs.rax, regs.rdi,
    regs.rsi, regs.rdx, regs.r10, regs.r8,  regs.r9);
  // If fingerprinter indicates that the syscall shouldn't be run,
  // cancel the syscall and set the return value
  if(processState.noop) {
    cancelSystemCall(gs, s, t);
    t.writeRax((uint64_t)processState.retval);
  }
  // Return flag indicating whether to run post-hook
  return true;
}

void fingerprinter::callPostHook(int syscallNumber, globalState& gs, state& s, ptracer& t, scheduler& sched){
  struct ProcessState processState;
  processState.tid = s.traceePid;
  auto regs = t.getRegs();
  fingerprinter_posthook(
    &processState, syscallNumber, (long)regs.rax, regs.rdi,
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
