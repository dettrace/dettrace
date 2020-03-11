#ifndef STATE_H
#define STATE_H

#include <sys/ptrace.h>
#include <sys/reg.h>
#include <sys/select.h>
#include <sys/timerfd.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/vfs.h>
#include <memory>
#include <unordered_map>
#include <unordered_set>

#include "ValueMapper.hpp"
#include "directoryEntries.hpp"
#include "logicalclock.hpp"
#include "mappedMemory.hpp"
#include "ptracer.hpp"
#include "registerSaver.hpp"

using namespace std;

enum sighandler_type {
  SIGHANDLER_INVALID,
  SIGHANDLER_CUSTOM,
  SIGHANDLER_CUSTOM_1SHOT,
  SIGHANDLER_DEFAULT,
  SIGHANDLER_IGNORED
};

// for timerCreateTimers map
typedef uint64_t timerID_t;
class timerInfo {
public:
  /** whether to send a signal upon timer expiration */
  bool sendSignal = false;
  /** signal to deliver when timer expires */
  int signum = -1;
  /** data to pass to signal handler, only used by timer_create */
  void* signalHandlerData = nullptr;
};

/**
 * Keep track of file descriptor, whether it's blocking or non blocking.
 */
enum class descriptorType {
  blocking, /*< Set to block by user program (default) */
  nonBlocking, /*< User used system call pipe2 or fnctl to set as non blocking.
                */
};

// Needed to avoid recursive dependencies between classes.
class mappedMemory;

/**
 * Class to hold all state that we will need to update in between system calls
 * inside the tracer so far this includes:
 *  - Logical Clocks.
 */
class state {
private:
  /**
   * The current logical time. Ticks only on time related system calls where the
   * user can observe time since we want to present progress. See
   * [Github issue](https://github.com/dettrace/dettrace/issues/24) for more
   * information. The clock starts at this number to avoid seeing files "in the
   * future", if we were to start at zero.
   */
  logical_clock::time_point clock;

  /**
   * The duration to increment the clock by.
   */
  logical_clock::duration clock_step;

public:
  /**
   * Constructor.
   * Initialize traceePid and debugLevel to the provided values, and
   * clock is initialized to 0. Allocates memory for a  new shared pointer.
   * @param traceePid pid of tracee
   * @param debugLevel debug level to be used
   */
  explicit state(
      pid_t traceePid,
      int debugLevel,
      logical_clock::time_point clock,
      logical_clock::duration clock_step);

  /**
   * fork a new state when fork/vfork is called
   */
  state forked(pid_t childPid) const;

  /**
   * cloned a new state when clone is called
   */
  state cloned(pid_t childPid) const;

  /**
   * Keep track of file descriptor status for blocking descriptors, as set by
   the
   * user program. Irregardless of what we set it to. These are
   * set in either pipe (non blocking) or pipe2 (either), or duplicated through,
   * dup, dup2, or can be set through fnctl. Deleted through close(). We only
   support
   * pipes, should be extended with fifo's at some point.

   * When reading/writing we check this status to know whether to block this
   process,
   * and replay, or simply preempt as Runnable by the scheduler.
   */
  shared_ptr<unordered_map<int, descriptorType>> fdStatus;

  void setFdStatus(int fd, descriptorType dt);

  descriptorType getFdStatus(int fd);

  int countFdStatus(int fd);

  /**
   * Map from file descriptors to directory entries.
   */
  unordered_map<int, directoryEntries<linux_dirent>> dirEntries;

  /**
   * The pid of the process represented by this state.
   */
  pid_t traceePid;

  /**
   * Remember whether wait4 was originally blocking or not.
   */
  bool wait4Blocking = false;

  /*
   * Per process bool to know if this is the pre or post hook event as ptrace
   * does not track this for us. Only used for older kernel vesions.
   */
  bool onPreExitEvent = true;

  /*
   * Per process bool to know if we should go into the post hook.
   */
  bool callPostHook = false;

  /**
   * Signal to be delivered the next time this process runs. If 0, no signal
   * will be delivered. Otherwise the value represents the signal number.
   */
  int signalToDeliver = 0;

  /**
   * inode number to be deleted.
   * We need to delete inodes from our maps whenever the tracee calls unlink,
   * unlinkat, or rmdir, that is, any system call that removes files. This is
   * necessary since the filesystem may recycle this inode leading to
   * unreproducible behavior when: 1) Some file is given an inode say i1. 2) Our
   * inode map says i1 -> n1. 3) This file is deleted by a call to unlink,
   * unlinkat, rmdir. 4) Some new file comes around and _sometimes_ gets
   * assigned i1.
   *
   * This messes up our assumption that files get unique inodes for the lifetime
   * of the program. So we delete inodes when they're done and delete them from
   * our maps.
   *
   * We would like to do:
   * 1) See a call to unlink, unlinkat, or rmdir.
   * 2) On the post hook we inject a call to newfstatat to find what the inode
   * belonging to this file is. We use this inode as a key to delete that entry
   * from our inode map and mtime map.
   *
   * This doesn't work though, as the call to newfstatat fails since the file
   * has already been deleted at this point! So instead we do: 1) See a call to
   * unlink, unlinkat, or rmdir. If this is the first time we have seen this
   * syscall we cut if off early at the pre hook and do a call to newfstatat to
   *    find the correct inode, we populate inodeToDelete in the state class.
   * From newfstatat we replay the call to unlink, unlinkat, or rmdir
   * respectively. In the post hook of the original call we use inodeToDelete to
   * remove the correct entries.
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
   * Indicator to differentiate between a syscall we are injecting and one that
   * has already been replayed. Used since Ptrace cannot tell the difference.
   *
   * If true, system call is being injected for the first try.
   * If false, system call is being replayed.
   */
  bool firstTrySystemcall = true;

  /** Flag to let us know if the current system call was artifically injected by
   * us. */
  bool syscallInjected = false;

  /** Whether we have injected a noop system call. Return value of the noop
      (currently, getpid) needs to be fixed up so that tracee doesn't notice
      the noop. */
  bool noopSystemCall = false;

  /** Whether we've injected a signal for alarm/timer modeling. */
  bool signalInjected = false;

  /** What kind of signal handler this tracee has requested via
      signal/sigaction. The currentSignalHandlers map is updated iff the syscall
      completes successfully. */
  enum sighandler_type requestedSignalHandler = SIGHANDLER_INVALID;
  /** Which signal this tracee has requested handling of via
      signal/sigaction. The currentSignalHandlers map is updated iff the syscall
      completes successfully. */
  int requestedSignalToHandle = -1;

  /** Track, for each signal, what kind of handler this tracee currently has
   * registered. */
  shared_ptr<unordered_map<int, enum sighandler_type>> currentSignalHandlers;

  /** track timers created via timer_create */
  shared_ptr<unordered_map<timerID_t, timerInfo>> timerCreateTimers;

  bool rdfsNotNull = false; /**< Indicates whether rdfs is NULL. */
  bool wrfsNotNull = false; /**< Indicates whether wrfs is NULL. */
  bool exfsNotNull = false; /**< Indicates whether exfs is NULL. */
  fd_set origRdfs; /**< Original file descriptors set to watch for read
                      availability. */
  fd_set origWrfs; /**< Original file descriptors set to watch for write
                      availability. */
  fd_set
      origExfs; /**< Original file descriptors set to watch for exceptions. */

  /** Flag to differentiate between our injected timeout into a system call from
   * a user one. */
  bool userDefinedTimeout = false;

  /** Flag to tell us to setup cpuid interception via an injected prctl(). */
  bool CPUIDTrapSet = false;

  /** A register saver used to store the previous register state and retrieve at
   * a later stage */
  registerSaver regSaver;

  /** An instance of the mappedMemory class which encapsulates the
   * logic of ensuring the existance of a memory map.
   */
  mappedMemory mmapMemory;

  /**
   * Original register arguments before we modified them. We sometimes need to
   * restore them at the post-hook after modification.
   */
  uint64_t originalArg1 = 0; /**< original register arg 1 */
  uint64_t originalArg2 = 0; /**< original register arg 2 */
  uint64_t originalArg3 = 0; /**< original register arg 3 */
  uint64_t originalArg4 = 0; /**< original register arg 4 */
  uint64_t originalArg5 = 0; /**< original register arg 5 */
  uint64_t originalArg6 = 0; /**< original register arg 5 */

  /**
   * Debug level. Mainly used by the dettraceSytemCall classes to avoid doing
   * unnecesary work when logging data if not needed.
   */
  const int debugLevel;

  /**
   * Bytes to allocate for our directory entries. We use the standard size used
   * in glibc.
   */
  const size_t dirEntriesBytes = 32768;

  /**
   * Function to increase value of internal logical clock.
   */
  void incrementTime() { clock += clock_step; }

  /**
   * Function to get value of internal logical clock.
   */
  logical_clock::time_point getLogicalTime() const { return clock; }

  /**
   * We must keep track of file creation. For open and openat, we set this flag.
   * On the posthook, if the system call succeeded, we check if the file existed
   * to know if this is a newly created file.
   */
  bool fileExisted = false;

  /**
   * Keeps track of whether this process just exit_group-ed, we need to remember
   * this since there is no post-hook for exit group.
   */
  bool isExitGroup = false;

  /**
   * Keep track of places where it's okay to see a stuck thread versus where
   * it's not. We should only see a stuck thread after a pre-hook where we skip
   * the post-hook, or a post-hook, continuing to the next system call.
   */
  bool canGetStuck = false;

  /**
   * poll retry count
   * poll can choose a negative timeout for wait indefinitely
   * or a positive timeout (in mili-seconds) to wait only certain amount of time
   * we replay poll syscall for only `timeout` of times, by simply assume every
   * retry is roughly 1-milli-sec.
   */
  long poll_retry_count;

  /**
   * poll retry maximum
   */
  long poll_retry_maximum;

  /**
   * remote socket file descriptors, unix domain sockets excluded.
   */
  std::shared_ptr<std::unordered_set<int>> remote_sockfds;

  /**
   * check whether a file descriptor is a remote socket fd
   */
  bool fd_is_remote(int fd) const {
    return remote_sockfds->find(fd) != remote_sockfds->end();
  }

  /**
   * timerfds
   */
  std::shared_ptr<std::unordered_map<int, struct itimerspec>> timerfds;

  /**
   * check whether a file descriptor is a timerfd
   */
  bool fd_is_timerfd(int fd) const {
    return timerfds->find(fd) != timerfds->end();
  }

  /**
   * signalfds
   */
  std::shared_ptr<std::unordered_set<int>> signalfds;

  /**
   * check whether a file descriptor is a signalfd
   */
  bool fd_is_signalfd(int fd) const {
    return signalfds->find(fd) != signalfds->end();
  }
};

#endif
