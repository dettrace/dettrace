#ifndef EXECUTION_H
#define EXECUTION_H

#include "logger.hpp"
#include "valueMapper.hpp"
#include "systemCallList.hpp"
#include "systemCall.hpp"
#include "dettraceSystemCall.hpp"
#include "util.hpp"
#include "state.hpp"
#include "ptracer.hpp"

#include <stack>

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

  // Tell ptrace which stopped process to continue running.
  pid_t nextPid;

  // Class wrapping ptrace system call in a higher level API.
  ptracer tracer;

  // State represents all state we wish to maintain between subsequent system calls, e.g.
  // logical time, etc.
  // Since we may have multiple processes and threads, we hold a state per pid. TODO:
  // do different threads have the same pid but different tid? I think so, tid might
  // be a better choice for keys.
  map<pid_t, state> states;

  // Global pidMap shared by entire process trees. This is global to maintain a consistent
  // view of virtual to real pid mappings accross all processes.
  valueMapper pidMap;

  // As we fork, we must let children process run, the child could itself fork. So we
  // require a stack to know who the parent was.
  // On fork => push current process, let child run.
  // On child exit => pop stack, let that process run.
  stack<pid_t> processHier;

  pid_t traceesPid;

  bool exitLoop = false;

public:

  execution(int debugLevel, pid_t startingPid);
  void handleExit();

  void handlePreSystemCall(state& currState);

  void handlePostSystemCall(state& currState);

  void handleSystemCall();

  void runProgram();

  void handleFork(ptraceEvent event);

  pid_t handleForkEvent();

  void handleForkSignal();

  void handleClone();

  void handleExecve();

  void handleSignal(int status);

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
   */
  static ptraceEvent getNextEvent(pid_t currentPid, pid_t& traceesPid, int& status);
};

#endif
