#ifndef STATE_H
#define STATE_H

#include <sys/ptrace.h>
#include <sys/reg.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/vfs.h>
#include <unordered_map>
#include <sys/select.h>

#include "ptracer.hpp"
#include "ValueMapper.hpp"
#include "systemCall.hpp"
#include "directoryEntries.hpp"
#include "registerSaver.hpp"

using namespace std;

// Needed to avoid recursive dependencies between classes.
class systemCall;

/**
 * Class to hold all state that we will need to update in between system calls inside the
 * tracer so far this includes:
 *  - Logical Clocks.
 */
class state{
private:
  /**
   * Logical clock. Ticks only on time related system calls where the user
   * can observe time since we want to present progress.
   * See [Github issue](https://github.com/upenn-acg/detTrace/issues/24) for more
   * information. The clock starts at this number to avoid seeing
   * files "in the future", if we were to start at zero.
   */
  size_t clock = 744847200;

public:
 /**
   * Constructor.
   * Initialize traceePid and debugLevel to the provided values, and
   * clock is initialized to 0.
   * @param traceePid pid of tracee
   * @param debugLevel debug level to be used
   */
  state(pid_t traceePid, int debugLevel);

  /**
   * Map from file descriptors to directory entries.
   */
  unordered_map<int, directoryEntries<linux_dirent>> dirEntries;

  /**
   * The pid of the process represented by this state.
   */
  pid_t traceePid;

  /*
   * Per process bool to know if this is the pre or post hook event as ptrace does
   * not track this for us. Only used for older kernel vesions.
   */
  bool onPreExitEvent = true;

  /**
   * Signal to be delivered the next time this process runs. If 0, no signal
   * will be delivered. Otherwise the value represents the signal number.
   */
  int signalToDeliver = 0;

  /**
   * inode number to be deleted.
   * We need to delete inodes from our maps whenever the tracee calls unlink, unlinkat,
   * or rmdir, that is, any system call that removes files. This is necessary since the
   * filesystem may recycle this inode leading to unreproducible behavior when:
   * 1) Some file is given an inode say i1.
   * 2) Our inode map says i1 -> n1.
   * 3) This file is deleted by a call to unlink, unlinkat, rmdir.
   * 4) Some new file comes around and _sometimes_ gets assigned i1.
   *
   * This messes up our assumption that files get unique inodes for the lifetime of the
   * program. So we delete inodes when they're done and delete them from our maps.
   *
   * We would like to do:
   * 1) See a call to unlink, unlinkat, or rmdir.
   * 2) On the post hook we inject a call to newfstatat to find what the inode belonging
   *    to this file is. We use this inode as a key to delete that entry from our inode map
   *    and mtime map.
   *
   * This doesn't work though, as the call to newfstatat fails since the file has already
   * been deleted at this point! So instead we do:
   * 1) See a call to unlink, unlinkat, or rmdir. If this is the first time we have seen
   *    this syscall we cut if off early at the pre hook and do a call to newfstatat to
   *    find the correct inode, we populate inodeToDelete in the state class. From
   *    newfstatat we replay the call to unlink, unlinkat, or rmdir respectively. In the
   *    post hook of the original call we use inodeToDelete to remove the correct entries.
   */
  ino_t inodeToDelete = -1;

  /*
   * register values from (the post-hook) before any retries
   */
  struct user_regs_struct beforeRetry = {0};

  /**
   * Number of total bytes.
   */
  uint64_t totalBytes = 0;

  /*
   * Indicator to differentiate between a syscall we are injecting and one that has already been replayed.
   * Used since Ptrace cannot tell the difference.
   *
   * If true, system call is being injected for the first try.
   * If false, system call is being replayed.
   */
  bool firstTrySystemcall = true;


  /** Flag to let us know if the current system call was artifically injected by us. */
  bool syscallInjected = false;

  bool rdfsNotNull = false; /**< Indicates whether rdfs is NULL. */
  bool wrfsNotNull = false; /**< Indicates whether wrfs is NULL. */
  bool exfsNotNull = false; /**< Indicates whether exfs is NULL. */
  fd_set origRdfs; /**< Original file descriptors set to watch for read availability. */
  fd_set origWrfs; /**< Original file descriptors set to watch for write availability. */
  fd_set origExfs; /**< Original file descriptors set to watch for exceptions. */

  /** Flag to differentiate between our injected timeout into a system call from a user one. */
  bool userDefinedTimeout = false;

  /** Our old values before post hook, for simple restoring of the user's register state. */
  struct user_regs_struct prevRegisterState = {0};

  /**
   * Original register arguments before we modified them. We sometimes need to restore them at the
   * post-hook after modification.
   */
  uint64_t originalArg1 = 0; /**< original register arg 1 */
  uint64_t originalArg2 = 0; /**< original register arg 2 */
  uint64_t originalArg3 = 0; /**< original register arg 3 */
  uint64_t originalArg4 = 0; /**< original register arg 4 */
  uint64_t originalArg5 = 0; /**< original register arg 5 */

  /**
   * Debug level. Mainly used by the dettraceSytemCall classes to avoid doing unnecesary
   * work when logging data if not needed.
   */
  const int debugLevel;

  /**
   * Bytes to allocate for our directory entries. We use the standard size used in glibc.
   */
  const size_t dirEntriesBytes = 32768;

  /*
   * Smart pointer to the system call being processed.
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
   * Function to increase value of internal logical clock.
   */
  void incrementTime();

  /**
   * Function to get value of internal logical clock.
   */
  int getLogicalTime();
};

#endif
