#ifndef SECCOMP_H
#define SECCOMP_H

#include <seccomp.h>
#include <stdint.h>
#include <cstdlib>
#include <stdio.h>
#include <cstdio> // for perror
#include <cstring> // for strlen
#include <sys/stat.h>
#include <fcntl.h>
#include <stdarg.h>
#include <libgen.h>
#include <sys/mount.h>
#include <string>

#include <iostream>
#include <tuple>
#include <sched.h>

class seccomp{
private:
  scmp_filter_ctx ctx;

  /**
   * Similar to @loadRules except intercepts a few extra system calls for debugging
   * purposes. Mainly, anything having to do with paths.
   */
  void loadRulesDebug();

  /**
   *
   * Code defining all system call that we implement or let through.
   * @debug: Is this debug mode? (Extra logging if yes).
   *
   */
  void loadRules(bool debug);

  /**
   * Add system call to whitelist but no call to ptrace.
   */
  void noIntercept(uint16_t systemCall);

  /**
   * Add system call to whitelist but everytime it is called call ptrace to intercept.
   */
  void intercept(uint16_t systemCall);

  /**
   * Add system call to whitelist. Intercept based on whether cond is true, otherwise,
   * no. (useful debugging).
   */
  void intercept(uint16_t systemCall, bool cond);
public:
  /**
   *
   * Initialize a seccomp + bpf with all our rules.
   * Default action to take when no rule applies to system call. We send a PTRACE_SECCOMP
   * event message to the tracer with a unique data: INT16_MAX
   *
   * This system call doesn't actually load the filter to the kernel. Merely initializes it.
   * Please use loadFilterToKernel.
   *
   * PTRACEME should be called by the tracee before this call.
   *
   * @param debugLevel: If 4 or 5, will intercept several more system calls.
   */
  seccomp(int debugLevel);

  /**
   *
   * This function should only be called after the raise(SIGSTOP) needed to avoid raise
   * conditions between the tracee and tracee of a ptrace setup.
   */
  void loadFilterToKernel();

  // Free all resources now that kernel has filter.
  ~seccomp();
};

#endif
