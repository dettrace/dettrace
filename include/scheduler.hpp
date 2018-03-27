#ifndef SCHEDULER_H
#define SCHEDULER_H

#include "logger.hpp"
#include "state.hpp"

#include <deque>
#include <optional>

enum class processState{ runnable, blocked };

/**
 * Information that we need to know per process. Keeps track whether process is
 * runnable or blocked. This way we don't try to run blocked processes. Epoch is
 * a logical timestamp that tells us whether state is valid. Everytime a process is
 * scheduled and runs, the epoch is increase, this ensures
 */
struct process{
  process(pid_t pid);
  pid_t pid;
  // By default all processes start as runnable.
  processState state = processState::runnable;
  // Always starts at zero.
  int epoch = 0;
};

/**
 * Stateful class to keep track of all currently running processes in our process tree.
 * Returns which process should run next based on our scheduling policy. Keeps track
 * of blocked/runnable processes.

 * Detects deadlocks in program and throws error, if this ever happens.

 * We never really need the user to pass in the process to remove or preempt. It should
 * only ever be currently running process. But this adds an extra safety check. Throws
 * error if it ever doesn't match.

 * Current Scheduling policy: current process continues running until it forks/clones.
 * Then, child runs. If current process blocks, let newest process run, this process
 * is now the current process.
 */
class scheduler{
public:
  scheduler(pid_t startingPid, logger& log);

  /**
   * Get pid of process that ptrace should run next.
   * Throws exception if empty.
   */
  pid_t getNext();

  /**
   * Current process is blocked! Mark for blocking, and get pid of process that ptrace
   * should run next. Throws exception if empty.
   */
  void preemptAndScheduleNext(pid_t process);

  void updateEpoch();

  /**
   * Adds new process to scheduler! This new process will be scheduled to run next.
   */
  void addAndScheduleNext(pid_t newProcess);

  /**
   * Removes specified process and schedule new process to run.
   * @param empty: return true if we're all done!
   */
  bool removeAndScheduleNext(pid_t terminatedProcess);

private:
  logger& log;

  /**
   * Pid for next process to run.
   */
  pid_t nextPid = -1;


  /**
   * Epoch keeps track of last time a process was verified to be blocked. Once any
   * process makes progress, we optimistically assume it may no longer be blocked,
   * we increase the epoch, and the epoch field in the process class is invalidated.
   */
  int epoch = 0;

  /**
   * Double ended queue to keep track of which process to schedule next.
   */
  deque<process> processQueue;

};

#endif
