#ifndef SYSTEM_CALL_H
#define SYSTEM_CALL_H

#include <stdexcept>
#include "state.hpp"
#include "globalState.hpp"
#include "ptracer.hpp"
#include "scheduler.hpp"

using namespace std;

// Needed to avoid recursive dependencies between classes.
class state;
class scheduler;

/**
 * Class to handle system call deterministically. You should derive from this class
 * and override either hadleDetPre(), handleDetPost(), or both, (sometimes, none :))
 */
class systemCall{
public:
  /**
   * Constructor.
   * Initialize syscallNumber and syscallName to the values provided.
   * @param syscallNumber the syscall number
   * @param syscallName the string representing the syscall name
   */
  systemCall(long syscallNumber, string syscallName);

  /**
   * Function called by tracer before the system call is executed by the tracer.
   * By default, we return true. Override function to set behavior to false.
   * @return trapOnPost: If true, tracer will also trap on the post hook.
   *                     If false, tracer will not trap on the post hook. This is
   *                               slightly faster.
   * @see handleDetPost
   */
  virtual bool handleDetPre(globalState& gl, state& s, ptracer& t, scheduler& sched);

  /**
   * Function called in tracer after the system call has executed. This is a good chance
   * to change arguments or return values before returning to tracee. By default does
   * not do anything. This function is only called when @handleDetPre returned true.
   * @see handleDetPre
   */
  virtual void handleDetPost(globalState& gl, state& s, ptracer& t, scheduler& sched);

  const long syscallNumber; /**< syscall number */
  const string syscallName; /**< syscall name */
};

#endif
