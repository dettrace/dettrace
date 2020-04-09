#ifndef EXECUTION_H
#define EXECUTION_H

#include "ValueMapper.hpp"
#include "dettrace.hpp"
#include "dettraceSystemCall.hpp"
#include "globalState.hpp"
#include "logger.hpp"
#include "logicalclock.hpp"
#include "ptracer.hpp"
#include "scheduler.hpp"
#include "state.hpp"
#include "systemCallList.hpp"
#include "util.hpp"
#include "vdso.hpp"

#include <map>
#include <stack>

#define ARCH_GET_CPUID 0x1011
#define ARCH_SET_CPUID 0x1012

/**
 * Execution class.
 * This class handles the event driven loop that is a process execution. Events
 from
 * a running program are intercepted, and a handler is called for that event.
 * Events include: clone, execve, fork, vfork, signal received, and system
 calls.

 * This class replaces the original code which
 * was a while loop with a `Event e = getNextEvent(...);` with several cases to
 handle
 * different types of events. The control flow logic became complicated, with
 gotos,
 * breaks, continues. Just as bad, the code could not be refactored into
 functions as
 * there was too many variables in scope.

 * Hence we took all those variables and turned them into fields of this class.
 * Each function handles a certain type of event, with many many side effects.
 */
class execution {
private:
  /**
   * rdtsc minimal incrementals
   * some program might do rdtsc in a loop mainly for profiling purposes, keep
   * our counter increment a more realistic value to avoid application busy
   * reading rdtsc.
   */
  static const unsigned long RDTSC_STEPPING = 0x8000;

  /**
   * Using kernel version < 4.8 . Needed as semantics of ptrace + seccomp have
   * changed. See `man 2 ptrace`
   */
  bool kernelPre4_8;

  /** Main log.
   * For writing all messages.
   */
  logger log;
  /** Silent logger
   * Used for pidMapper since it expects a log to write to.
   */
  logger silentLogger;

  /**
   * Whether to print statistics to stdout or not.
   */
  bool printStatistics;

  /**
   * ptrace wrapper.
   * Class wrapping ptrace system call in a higher level API.
   */
  ptracer tracer;

  /**
   * System call state map.
   * State represents all state we wish to maintain between subsequent system
   * calls, e.g. logical time, etc. Since we may have multiple processes and
   * threads, we hold a state per pid.
   * TODO: do different threads have the same pid but different tid? I think so,
   * tid might be a better choice for keys.
   */
  map<pid_t, state> states;

  /**
   * Global inode mapper.
   * Ensures consistent state among all processes.
   */
  globalState myGlobalState;

  /**
   * Map of parent processes to children.
   * Keep track of our children. We can only ever exit once all our children
   * have exited. We map the parent's process id to children: 1 -> 2 1 -> 3 2 ->
   * 4 (Process 1 has two children: 2 and 3. Process 2 has one child: 4).
   * Threads are also counted as children of their thread group leader.
   */
  multimap<pid_t, pid_t> processTree;

  /**
   * Process scheduler.
   * Tells us which process to run next, keeps track of current processes.
   */
  scheduler myScheduler;
  /**
   * Debug level.
   * Range should be [1, 5]. Used to tell if we should always call the post hook
   * (to see return value of system call).
   */
  const int debugLevel;
  /**
   * Atomic counter for rdtsc instruction.
   * Emulates IA32_TSC MSR.
   */
  uint64_t tscCounter = 0;
  /**
   * Atomic counter for rdtscp instruction.
   * Emulates IA32_TSC_AUX MSR.
   */
  uint64_t tscpCounter = 0;

  // Statistic Counters start here!

  /**
   * Counter for keeping track of total number of system calls events
   * intercepted. this includes pre-hooks and post-hooks.
   */
  uint32_t systemCallsEvents = 0;

  /**
   * Counter for keeping track of total number of rdtsc instructions.
   */
  uint32_t rdtscEvents = 0;

  /**
   * Counter for keeping track of total number of rdtscp instructions.
   */
  uint32_t rdtscpEvents = 0;

  /**
   * Counter for keeping track process spawns: fork, vfork, clone.
   */
  uint32_t processSpawnEvents = 0;

  std::vector<VDSOSymbol> vdsoFuncs;

  void disableVdso(pid_t traceesPid);

  /**
   * starting epoch
   */
  logical_clock::time_point epoch;
  logical_clock::duration clock_step;

  int exit_code;

  unsigned prngSeed;

  SysEnter sys_enter_hook = nullptr;
  SysExit sys_exit_hook = nullptr;
  void* user_data;

public:
  /**
   * Constructor.
   * @param debugLevel debug paramater level (1-5)
   * @param startingPid pid of starting process
   * @param useColor Toggles color in logging process
   * @param Using kernel version < 4.8.
   * @param logFile file to write log messages to, if "" use stderr
   */

  execution(
      int debugLevel,
      pid_t startingPid,
      bool useColor,
      string logFile,
      bool printStatistics,
      VDSOSymbol* vdsoFuncs,
      int nbVdsoFuncs,
      unsigned prngSeed,
      bool allow_network,
      logical_clock::time_point epoch,
      logical_clock::duration clock_step,
      SysEnter sys_enter_hook,
      SysExit sys_exit_hook,
      void* user_data);

  /**
   * Handles exit from current process.
   * Processs is done. Remove it from our process scheduler stack and let parent
   * process run.
   * @param traceesPid the pid of the tracee
   * @return Exit status for runProgram
   * @see runProgram()
   */
  bool handleNonEventExit(const pid_t traceesPid);

  /**
   * Handles system call pre-hook.
   * Processs is done. Remove it from our process scheduler stack and let parent
   * process run.
   * @param traceesPid the pid of the tracee
   * @param currState State of current pid
   * REVIEW @return whether to go into post-interception hook
   * @see runProgram()
   */
  bool handlePreSystemCall(state& currState, const pid_t traceesPid);

  /**
   * Handles exit from current process.
   * Processs is done. Remove it from our process scheduler stack and let parent
   * process run.
   * @param currState State of current pid
   * @see runProgram()
   */
  void handlePostSystemCall(state& currState);

  /**
   * REVIEW this function does not seem to be implemented
   * This function call both handlePostSystemCall and handlePostSystemCall.
   */
  bool handleSystemCall();

  /**
   * Launch initial process.
   * A program is defined as a tree of processes.
   */
  int runProgram();

  /**
   * Handle the fork event part of @handleFork. Pushes parent to our process
   * hierarchy and creates state for child.
   * @param traceesPid the pid of the tracee
   * @see handleFork.
   */
  pid_t handleForkEvent(const pid_t traceesPid, bool isThread);

  /**
   * Handle signal event in trace.
   * @param signum signal number
   * @param traceesPid the pid of the tracee
   */
  void handleSignal(int signum, const pid_t traceesPid);

  /**
   * Handle the signal part of @handleFork.
   * @param traceesPid the pid of the tracee
   * @see handleFork.
   */
  void handleExecEvent(pid_t traceesPid);

  /**
   * Handle seccomp event.
   * This happens everytime we intercept a system call before the system call is
   * called.
   * @param traceesPid the pid of the tracee
   * @return Return value dictates whether the postHook should be called as
   * well.
   */
  bool handleSeccomp(const pid_t traceesPid);

  /**
   * Handle seccomp event.
   * This happens everytime we intercept a system call before the system call is
   * called. Return value dictates whether the postHook should be called as
   * well.
   */
  bool handleSeccomp();

  /**
   * Call system call handler based on system call number, if number is not a
   * system call an runtime_error will be thrown.
   * @param syscallNumber
   * @param syscallName
   */
  bool callPreHook(
      int syscallNumber,
      globalState& gs,
      state& s,
      ptracer& t,
      scheduler& sched);

  void callPostHook(
      int syscallNumber,
      globalState& gs,
      state& s,
      ptracer& t,
      scheduler& sched);

  /**
   * Catch next event from any process that we are tracing. Return the event
   * type as well as the pid for the process that created this event, also set
   * the status.
   * @param currentPid: the pid of the previously intercepted process. If this
   * is the first time calling, it is the original process to trace.
   * @param ptraceSyscall continue with a PTRACE_SYSCALL as the action, if
   * false, if do PTRACE_CONT instead.
   * @return tuple of info for intercepted process: event type, pid of the
   * process we just intercepted, and status retured by waitpid.
   */
  tuple<ptraceEvent, pid_t, int> getNextEvent(
      pid_t currentPid, bool ptraceSystemCall);

  /**
   * Gets PtraceEvent type.
   * @param status status number
   * @return ptrace event type
   */
  ptraceEvent getPtraceEvent(const int status);

  /**
   * Logic for unresponsive thread after exit group, basically, the kernel does
   * not guarantee this thread will respond to ptrace events, it may already
   * have exited we wait and see if it sends an exit message through wait.
   */
  ptraceEvent handleExitedThread(pid_t currentPid);

  // Core looping logic used by handleExitedThread.
  pair<bool, ptraceEvent> loopOnWaitpid(pid_t currentPid);

  void killAllProcesses() { myScheduler.killAllProcesses(); }
};

#endif
