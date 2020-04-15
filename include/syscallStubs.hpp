
#pragma once

#include <sys/types.h>

#include <tuple>

#define SYSCALL_STUB_PAGE_START 0x70000000UL
#define SYSCALL_STUB_PAGE_SIZE 0x1000UL

class SyscallArgs {
public:
  unsigned long args[6];
  SyscallArgs(
      unsigned long a0,
      unsigned long a1,
      unsigned long a2,
      unsigned long a3,
      unsigned long a4,
      unsigned long a5) {
    args[0] = a0;
    args[1] = a1;
    args[2] = a2;
    args[3] = a3;
    args[4] = a4;
    args[5] = a5;
  }
  SyscallArgs(
      unsigned long a0,
      unsigned long a1,
      unsigned long a2,
      unsigned long a3,
      unsigned long a4) {
    args[0] = a0;
    args[1] = a1;
    args[2] = a2;
    args[3] = a3;
    args[4] = a4;
    args[5] = 0;
  }
  SyscallArgs(
      unsigned long a0, unsigned long a1, unsigned long a2, unsigned long a3) {
    args[0] = a0;
    args[1] = a1;
    args[2] = a2;
    args[3] = a3;
    args[4] = 0;
    args[5] = 0;
  }
  SyscallArgs(unsigned long a0, unsigned long a1, unsigned long a2) {
    args[0] = a0;
    args[1] = a1;
    args[2] = a2;
    args[3] = 0;
    args[4] = 0;
    args[5] = 0;
  }
  SyscallArgs(unsigned long a0, unsigned long a1) {
    args[0] = a0;
    args[1] = a1;
    args[2] = 0;
    args[3] = 0;
    args[4] = 0;
    args[5] = 0;
  }
  SyscallArgs(unsigned long a0) {
    args[0] = a0;
    args[1] = 0;
    args[2] = 0;
    args[3] = 0;
    args[4] = 0;
    args[5] = 0;
  }
  SyscallArgs() {
    args[0] = 0;
    args[1] = 0;
    args[2] = 0;
    args[3] = 0;
    args[4] = 0;
    args[5] = 0;
  }
  ~SyscallArgs() {}
};

struct SyscallTrap {
  unsigned long syscall_trap_ip; // where current ip is trapped.
  unsigned long syscall_resume_ip; // where should we resume afterwards.
};

/**
 * do a synchronous syscall for tracee @pid.
 *  @pid: tracee to inject untraced syscall
 *  @trap_syscall: when non-null, stopped at breakpoint from injected
 *   syscall stub page defined as SYSCALL_STUB_PAGE_START.
 *  @syscall: syscall number
 *  @args: syscall arguments up to six.
 *  @return: injected syscall return value, note errno won't be set
 *   hence the caller must do proper syscall_ret decoding.
 */
extern "C" long untraced_syscall(
    pid_t pid,
    struct SyscallTrap* trap_syscall,
    int syscall,
    const unsigned long args[]);

/**
 * do a synchronous syscall for tracee @pid.
 *  @pid: tracee to inject untraced syscall
 *  @syscall: syscall number
 *  @args: syscall arguments up to six.
 *  @return: injected syscall return value, note errno won't be set
 *   hence the caller must do proper syscall_ret decoding.
 */
long injectSystemCall(pid_t pid, int syscall, SyscallArgs& args);

/**
 * do a synchronous syscall for tracee @pid.
 *  @pid: tracee to inject untraced syscall
 *  @syscall: syscall number
 *  @args: syscall arguments up to six.
 *  @return.0: injected syscall return value, note errno won't be set
 *   hence the caller must do proper syscall_ret decoding.
 *  @return.1: tracee's current PC being trapped (as breakpoint).
 *  @return.2: tracee's original PC before syscall was injected.
 */
std::tuple<long, unsigned long, unsigned long> injectTrappedSystemCall(
    pid_t pid, int syscall, const SyscallArgs& args);
