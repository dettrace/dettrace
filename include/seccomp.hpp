#ifndef SECCOMP_H
#define SECCOMP_H

/**
 * seccomp class.
 * Helper class for working with seccomp (short for secure computing mode), a
 * computer security facility in the Linux kernel. seccomp allows a process to
 * make a one-way transition into a "secure" state where it cannot make any
 * system calls except exit(), sigreturn(), read() and write() to already-open
 * file descriptors.
 */

class seccomp {
public:
  /**
   * Constructor.
   * Initialize a seccomp + bpf with all our rules.
   * Default action to take when no rule applies to system call. We send a
   * PTRACE_SECCOMP event message to the tracer with a unique data: INT16_MAX
   *
   * PTRACEME should be called by the tracee before this call.
   *
   * @param debugLevel: If 4 or 5, will intercept several more system calls.
   */
  seccomp(int debugLevel, bool convertUids);

  /**
   * Destructor.
   * Free all resources now that kernel has filter.
   */
  ~seccomp() {}
};

#endif
