#include <dlfcn.h>
#include <sys/types.h>

#include "rnr_loader.hpp"
#include "utilSystemCalls.hpp"
#include "util.hpp"

using namespace std;

// TODO: Currently passing PID into prehook and posthook for both PID and TIG
// arguments. Fix this.

// Fingerprinter State
static bool isNoop = false;
static int noopSyscall = -1;
static long noopRetval = -1;

extern "C" {
static long rnr_nop_sysenter(
    struct SyscallState* s,
    int pid,
    int tid,
    int syscallno,
    unsigned long arg0,
    unsigned long arg1,
    unsigned long arg2,
    unsigned long arg3,
    unsigned long arg4,
    unsigned long arg5) {
  return -ENOSYS;
}

static long rnr_nop_sysexit(
    struct SyscallState* s,
    int pid,
    int tid,
    int syscallno,
    unsigned long retval,
    unsigned long arg0,
    unsigned long arg1,
    unsigned long arg2,
    unsigned long arg3,
    unsigned long arg4,
    unsigned long arg5) {
  return 0;
}
}

/* override by `--rnr` command line flag */
static rnr_loader __rnr__ = {
    .rnr_sysenter = rnr_nop_sysenter,
    .rnr_sysexit = rnr_nop_sysexit,
};

bool rnr::callPreHook(
    int syscallNumber,
    globalState& gs,
    state& s,
    ptracer& t,
    scheduler& sched) {
  struct SyscallState syscallState;
  syscallState.noop = false;
  auto regs = t.getRegs();
  auto sysenter = __rnr__.rnr_sysenter;

  long prehook_retval = sysenter(
      &syscallState, s.traceePid, s.traceePid, syscallNumber, regs.rdi,
      regs.rsi, regs.rdx, regs.r10, regs.r8, regs.r9);
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
  auto sysexit = __rnr__.rnr_sysexit;
  sysexit(
      &syscallState, s.traceePid, s.traceePid, regs.orig_rax, (long)regs.rax,
      regs.rdi, regs.rsi, regs.rdx, regs.r10, regs.r8, regs.r9);
}

/* must be called early, no lock is provied */
void rnr::loadRnr(const string& dso) {
  void* handle = dlopen(dso.c_str(), RTLD_NOW);

  auto sysenter = dlsym(handle, "rnr_sysenter");
  if (!sysenter) {
    runtimeError("could not find rnr_sysenter");
  }
  auto sysexit = dlsym(handle, "rnr_sysexit");
  if (!sysexit) {
    runtimeError("could not find rnr_sysexit");
  }

  __rnr__.rnr_sysenter = reinterpret_cast<decltype(rnr_nop_sysenter)*>(
      reinterpret_cast<unsigned long>(sysenter));
  __rnr__.rnr_sysexit = reinterpret_cast<decltype(rnr_nop_sysexit)*>(
      reinterpret_cast<unsigned long>(sysexit));

  // NB: no dlclose to keep keep the symbols intact.
}
