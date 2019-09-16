#include "fingerprinter.hpp"
#include "utilSystemCalls.hpp"

using namespace std;

bool fingerprinter::handleDetPre(int syscallNumber, globalState& gs, state& s, ptracer& t, scheduler& sched){
  struct ProcessState processState;
  processState.tid = s.traceePid;
  auto regs = t.getRegs();
  fingerprinter_prehook(&processState, syscallNumber, (long)regs.rax,
        regs.rdi, regs.rsi,
        regs.rdx, regs.r10,
        regs.r8,  regs.r9);
  // If fingerprinter indicates that the syscall shouldn't be run,
  // cancel the syscall and set the return value
  if(processState.noop) {
    cancelSystemCall(gs, s, t);
    t.writeRax((uint64_t)processState.retval);
  }
  return true;
}

void fingerprinter::handleDetPost(int syscallNumber, globalState& gs, state& s, ptracer& t, scheduler& sched){
  struct ProcessState processState;
  processState.tid = s.traceePid;
  auto regs = t.getRegs();
  fingerprinter_posthook(&processState, syscallNumber, (long)regs.rax,
        regs.rdi, regs.rsi,
        regs.rdx, regs.r10,
        regs.r8,  regs.r9);
}
