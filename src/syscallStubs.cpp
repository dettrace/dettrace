#include <sys/types.h>
#include <sys/ptrace.h>
#include <tuple>

#include "utilSystemCalls.hpp"
#include "syscallStubs.hpp"

// =======================================================================================
extern "C" long untraced_syscall(pid_t pid, struct SyscallTrap* trap_syscall, int syscall, const unsigned long args[]) {
  struct user_regs_struct regs;
  VERIFY(ptrace(PTRACE_GETREGS, pid, NULL, (void*)&regs) == 0);

  auto old_regs = regs;

  regs.orig_rax = syscall;
  regs.rax = syscall;
  regs.rdi = args[0];
  regs.rsi = args[1];
  regs.rdx = args[2];
  regs.r10 = args[3];
  regs.r8 = args[4];
  regs.r9 = args[5];
  regs.rip = 0x70000008;

  VERIFY(ptrace(PTRACE_SETREGS, pid, 0, (void*)&regs) == 0);
  VERIFY(ptrace(PTRACE_CONT, pid, 0, 0) == 0);

  int status;
  VERIFY(waitpid(pid, &status, 0) == pid);
  VERIFY(WIFSTOPPED(status) && WSTOPSIG(status) == SIGTRAP);

  VERIFY(ptrace(PTRACE_GETREGS, pid, 0, (void*)&regs) == 0);
  long retval = regs.rax;

  VERIFY(regs.rip == 0x7000000e);

  if (trap_syscall) {
    trap_syscall->syscall_resume_ip = old_regs.rip;
    trap_syscall->syscall_trap_ip = regs.rip;
    old_regs.rip = regs.rip;
  }

  VERIFY(ptrace(PTRACE_SETREGS, pid, 0, (void*)&old_regs) == 0);

  return retval;
}
// =======================================================================================

long injectSystemCall(pid_t pid, int syscall, SyscallArgs& args) {
  return untraced_syscall(pid, NULL, syscall, args.args);
}

std::tuple<long, unsigned long, unsigned long> injectTrappedSystemCall(pid_t pid, int syscall, const SyscallArgs& args) {
  SyscallTrap trap;
  long retval = untraced_syscall(pid, &trap, syscall, args.args);
  std::tuple<long, unsigned long, unsigned long> res;
  std::get<0>(res) = retval;
  std::get<1>(res) = trap.syscall_trap_ip;
  std::get<2>(res) = trap.syscall_resume_ip;

  return res;
}
