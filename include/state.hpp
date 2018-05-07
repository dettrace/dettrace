#ifndef STATE_H
#define STATE_H

#include<linux/version.h>
#include <sys/ptrace.h>
#include <sys/reg.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/vfs.h>
#include <unordered_map>

#include "ptracer.hpp"
#include "ValueMapper.hpp"
#include "systemCall.hpp"
#include "directoryEntries.hpp"

using namespace std;

// Needed to avoid recursive dependencies between classes.
class systemCall;

/**
 * Class to hold all state that we will need to update in between system calls inside the
 * tracer so far this includes:
 * Inodes Mappings.
 * PID Mappings.
 * Logical Clocks.
 * Logger.
 */
class state{
private:
  /**
   * Logical clock. Ticks only on time related system calls where the user can observe
   * time since we want to present progress.
   * See [[https://github.com/upenn-acg/detTrace/issues/24][Github issue]] for more
   * information.
   * Start at this number to avoid seeing files "in the future", if we were to start at
   * zero.
   */
  size_t clock = 744847200;

public:
  /**
   * @pidMap: Notice this is a reference -> same map is shared among all instances of
   * of state.
   * @ppid: Parent pid of this process.
   */
  state(logger& log, ValueMapper<ino_t, ino_t>& inodeMap,
        ValueMapper<ino_t, time_t>& mtimeMap, pid_t myPid, int debugLevel);

  /**
   * Map from file descriptors to directory entries.
   *
   */
  unordered_map<int, directoryEntries<linux_dirent>> dirEntries;

  /**
   * The pid of the process represented by this state.
   */
  pid_t traceePid;
#if LINUX_VERSION_CODE < KERNEL_VERSION(4,8,0)
  /*
   * Per process bool to know if this is the pre or post hook event as ptrace does
   * not track this for us. Only needed for older versions of seccomp.
   */
  bool isPreExit = true;
#endif
  /*
   * Isomorphism between inodes and vitual inodes.
   */
  ValueMapper<ino_t, ino_t>& inodeMap;

  /*
   * Tracker of mtimes.
   */
  ValueMapper<ino_t, time_t>& mtimeMap;


  logger log;

  /**
   * Signal to deliver for next time this process runs. Zero means none. Otherwise
   * this int represents the signal number.
   */
  int signalToDeliver = 0;

  /*
   * register values from (the post-hook) before any retries
   */
  struct user_regs_struct beforeRetry = {0};
  uint64_t totalBytes = 0;
  bool firstTryReadWrite = true;

  // For deterministic modified times we inject fstat system calls, this variable lets
  // fstat know if it is in this event.
  bool fstatMtimeInjection = false;

  // Our old values before post hook, for simple restoring of the user's register state.
  struct user_regs_struct prevRegisterState = {0};

  /**
   * Original register arguments before we modified them. We need to restore them at the
   * post-hook after modifying. Sometimes.
   */
  uint64_t originalArg1 = 0;
  uint64_t originalArg2 = 0;
  uint64_t originalArg3 = 0;
  uint64_t originalArg4 = 0;
  uint64_t originalArg5 = 0;

  /**
   * Debug level. Mainly used by the dettraceSytemCall classes to avoid doing unnecesary
   * work when logging data if not needed.
   */
  const int debugLevel;

  // Bytes to allocate for our directory entries.
  // This is what glibc uses as it's standard size, so do we.
  const size_t dirEntriesBytes = 32768;

  /*
   * We need to know what system call was/is that we are not. This is important in
   * cases like clone:
   * 1) Parent performs clone.
   * 2) We receive a pre-exit for clone.
   * 3) The process is switched to the child.
   * 4) Child does an arbitrary number of system calls before exiting.
   * 5) Without this variable the fact we were doing a clone is lost.

   * Basically, we cannot guarantee we will always be able to do system calls in a
   * pre-post pairs. As we extend to multi processes, this will become more useful.

   * We use a a pointer since we rely on dynamic dispatch for the right subclass for
   * the methods to work properly.
   */
  unique_ptr<systemCall> systemcall;

  /**
   * Increase value of internal logical clock.
   */
  void incrementTime();

  /**
   * Get value of internal logical clock.
   */
  int getLogicalTime();
};

#endif
