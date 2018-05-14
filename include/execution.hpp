#ifndef EXECUTION_H
#define EXECUTION_H

#include "logger.hpp"
#include "systemCallList.hpp"
#include "systemCall.hpp"
#include "dettraceSystemCall.hpp"
#include "util.hpp"
#include "state.hpp"
#include "ptracer.hpp"
#include "scheduler.hpp"
#include "ValueMapper.hpp"
#include "globalState.hpp"

#include <stack>
#include <map>


/**
 * This class handles the event driven loop that is a process execution. Events from
 * a running program are intercepted, and a handler is called for that event.
 * Events include: clone, execve, fork, vfork, signal received, and system calls.

 * This class replaces the original code which
 * was a while loop with a `Event e = getNextEvent(...);` with several cases to handle
 * different types of events. The control flow logic became complicated, with gotos,
 * breaks, continues. Just as bad, the code could not be refactored into functions as
 * there was too many variables in scope.

 * Hence we took all those variables and turned them into fields of this class.
 * Each function handles a certain type of event, with many many side effects.
 */
class execution{

private:
  // Logger to write all messages to.
  logger log;

  // Class wrapping ptrace system call in a higher level API.
  ptracer tracer;

  // State represents all state we wish to maintain between subsequent system calls, e.g.
  // logical time, etc.
  // Since we may have multiple processes and threads, we hold a state per pid. TODO:
  // do different threads have the same pid but different tid? I think so, tid might
  // be a better choice for keys.
  map<pid_t, state> states;

  // Global inode mapper to ensure consistent state among all processes.
  globalState myGlobalState;

  /**
   * Keep track of our children. We can only ever exit once all our children have exited.
   * We map the parent's process id to children:
   * 1 -> 2
   * 1 -> 3
   * 2 -> 4
   * (Process 1 has two children: 2 and 3. Process 2 has one child: 4).
   */
  multimap<pid_t, pid_t> processTree;

  /**
   * Tells us which process to run next, keeps track of current processes.
   */
  scheduler myScheduler;

  // Debug level, should be [1, 5]. Used to tell if we should always call the post hook
  // (to see return value of system call).
  const int debugLevel;

public:
  execution(int debugLevel, pid_t startingPid);

  // Processs is done. Remove it from our processHier stack and let parent process run.
  bool handleExit(const pid_t traceesPid);

  bool handlePreSystemCall(state& currState, const pid_t traceesPid);

  void handlePostSystemCall(state& currState);

  // This function call both handlePostSystemCall and handlePostSystemCall.
  bool handleSystemCall();

  // Function to launch initial process. A program is defined as a tree of processes.
  void runProgram();

  /**
   *
   * Fork is super special. We get two events whenever a fork, vfork, or clone happens.
   * 1) A signal from the child.
   * 2) A fork event from the parent.
   * The problem is that the order of the events is unkown. Therefore we must be able
   * to receive the events in either order and correctly handle them.

   * This event also sets scheduling for process by setting nextPid to newChildPid.
   *
   */
  void handleFork(ptraceEvent event, const pid_t traceesPid);

  /**
   * Handle the fork event part of @handleFork. Pushes parent to our process hierarchy
   * and creates state for child.
   */
  pid_t handleForkEvent(const pid_t traceesPid);

  /**
   * Handle the signal part of @handleFork.
   */
  void handleForkSignal(const pid_t traceesPid);

  void handleClone(const pid_t traceesPid);

  void handleExecve(const pid_t traceesPid);

  void handleSignal(int signum, const pid_t traceesPid);

  /**
   * Handle seccomp event. This happens everytime we intercept a system call before the
   * system call is called.
   *
   * Return value dictates whether the postHook should be called as well.
   */
  bool handleSeccomp(const pid_t traceesPid);

  /**
   * Handle seccomp event. This happens everytime we intercept a system call before the
   * system call is called.
   *
   * Return value dictates whether the postHook should be called as well.
   */
  bool handleSeccomp();

  /**
   * Return the system call we currently caught from the tracer.
   * Notice we are forced to use a pointer to get virtual dispatch.
   */
  static unique_ptr<systemCall> getSystemCall(int syscallNumber, string syscallName);

  /**
   * Catch next event from any process that we are tracing. Return the event type as well
   * as the pid for the process that created this event, also set the status.
   * @param currentPid: the pid of the previously intercepted process. If this is the first
   * time calling, it is the original process to trace.
   * @param traceesPid[out]: pid of the process we just intercepted.
   * @param status[out]: status retured by waitpid.
   * @param ptraceSyscall[in]: continue with a PTRACE_SYSCALL as the action, if false,
   *        if do PTRACE_CONT instead.
   */
  tuple<ptraceEvent, pid_t, int> getNextEvent(pid_t currentPid, bool ptraceSystemCall);

  ptraceEvent getPtraceEvent(const int status);
};

#endif
