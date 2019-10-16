#ifndef SECCOMP_H
#define SECCOMP_H

#include <fcntl.h>
#include <libgen.h>
#include <seccomp.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <cstdio> // for perror
#include <cstdlib>
#include <cstring> // for strlen
#include <string>

#include <sched.h>
#include <iostream>
#include <tuple>

/**
 * seccomp class.
 * Helper class for working with seccomp (short for secure computing mode), a
 * computer security facility in the Linux kernel. seccomp allows a process to
 * make a one-way transition into a "secure" state where it cannot make any
 * system calls except exit(), sigreturn(), read() and write() to already-open
 * file descriptors.
 */

class seccomp {
private:
  /**
   * Context for seccomp filter.
   * Holds return state of seccomp_init.
   * @see seccomp_init.
   */
  scmp_filter_ctx ctx;

  /**
   * Code defining all system call that we implement or let through with debug
   * calls. Similar to loadRules except intercepts a few extra system calls for
   * debugging purposes. Mainly, anything having to do with paths.
   * @see loadRules
   */
  void loadRulesDebug();

  /**
   * Code defining all system call that we implement or let through.
   * @param debug True for debug mode. (Extra logging if true).
   */
  void loadRules(bool debug, bool convertUids);

  /**
   * Add system call to whitelist but no call to ptrace.
   * @param systemCall system call to add to whitelist.
   */
  void noIntercept(uint16_t systemCall);

  /**
   * Add system call to whitelist but everytime it is called call ptrace to
   * intercept.
   * @param systemCall
   */
  void intercept(uint16_t systemCall);

  /**
   * Add system call to whitelist.
   * Intercept based on whether cond is true, otherwise,
   * no. (useful debugging).
   * @param systemCall
   */
  void intercept(uint16_t systemCall, bool cond);

public:
  /**
   * Constructor.
   * Initialize a seccomp + bpf with all our rules.
   * Default action to take when no rule applies to system call. We send a
   * PTRACE_SECCOMP event message to the tracer with a unique data: INT16_MAX
   *
   * This system call doesn't actually load the filter to the kernel. Merely
   * initializes it. Please use loadFilterToKernel.
   *
   * PTRACEME should be called by the tracee before this call.
   *
   * @param debugLevel: If 4 or 5, will intercept several more system calls.
   */
  seccomp(int debugLevel, bool convertUids);

  /**
   * Used to avoid raise conditions between the tracee and tracee of a ptrace
   * setup. This function should only be called after the raise(SIGSTOP) needed
   * to avoid raise conditions between the tracee and tracee of a ptrace setup.
   */
  void loadFilterToKernel();

  /**
   * Destructor.
   * Free all resources now that kernel has filter.
   */
  ~seccomp();
};

#endif
