#ifndef SCHEDULER_H
#define SCHEDULER_H

#include "logger.hpp"
#include "state.hpp"

#include <deque>
#include <unordered_map>

using namespace std;

/**
 *
 * runnable:      We know for a fact ths process is able to make progress.
 * maybeRunnable: Another process has just finished making progress, we were blocked.
 *                now we might be able to make progress, maybe not?
 * blocked:       We cannot make progress.
 * finished:      This process has finished. This process will not receive a "nonEventExit"
 *                from ptrace until all the children are done first. This might take a while
 *                we keep the process around until it's ready to leave this world.
 * polling:       This is a process with a timeout to a system call, e.g. futex with the
 *                timeout field set to not-null, mark the process as polling.
 *                Polling processes run last in the scheduler.
 */
enum class processState{ runnable, maybeRunnable, blocked, finished };

/**
 * Options for process being preempted. Sometimes we want to mark it as blocked,
 * sometimes we want to continue to let it run.
 *
 */
enum class preemptOptions { runnable, markAsBlocked };

string to_string(processState p);

/**
 * Stateful class to keep track of all currently running processes in our process tree.
 * Returns which process should run next based on our scheduling policy. Keeps track
 * of blocked/runnable processes.

 * Detects deadlocks in program and throws error, if this ever happens.

 * We never really need the user to pass in the process to remove or preempt. It should
 * only ever be the currently running process. But this adds an extra safety check. Throws
 * error if it ever doesn't match.

 * Current Scheduling policy: Round Robin.
 */
class scheduler{
public:
  scheduler(pid_t startingPid, logger& log, ValueMapper<pid_t, pid_t>& pidMap);

  /*
   * Virtual pid mapper useful for logging deterministic pids even though we use
   * real pids for scheduling.
   */
  ValueMapper<pid_t, pid_t>& pidMap;

  /**
   * Check if this process has been marked as finished.
   */
  bool isFinished(pid_t process);

  /**
   * Mark this process as exited. Let other's run. We need our children to run
   * and finish before we get a ptrace nonEventExit. We actually remove the process
   * when our last child has itself ended.
   */
  void markFinishedAndScheduleNext(pid_t process);

  /**
   * Get pid of process that ptrace should run next.
   * Throws exception if empty.
   */
  pid_t getNext();

  /**
   * Preempt current process and get pid of process that ptrace should run next. Throws
   * exception if empty.
   * @param p: Options for process we're preempting.
   */
  void preemptAndScheduleNext(pid_t process, preemptOptions p);

  /**
   * Adds new process to scheduler! This new process will be scheduled to run next.
   */
  void addAndScheduleNext(pid_t newProcess);

  /**
   * Removes specified process and schedule new process to run.
   * @param empty: return true if we're all done with all processes in the scheduler.
   * this marks the end of the program.
   */
  bool removeAndScheduleNext(pid_t terminatedProcess);

  /**
   * Removes specified process, let our parent run to completion.
   * Should only be called by the last child of parent, when parent has already
   * been marked as finished.
   */
  void removeAndScheduleParent(pid_t terminatedProcess, pid_t parent);

  /**
   * In order to differenitate between the case where a maybeRunnable proces made progress
   * vs. no progress. We must report progress (change our status to runnable).
   */
  void reportProgress(pid_t process);
private:
  logger& log;

  /**
   * Pid for next process to run.
   */
  pid_t nextPid = -1;

  // We report progess due to several events. It would be expensive to iterate through
  // all our scheduled process' and mark all as maybeBlocked everytime. So instead, we
  // check if current process was set to runnable, this marks that we made progress.
  bool madeProgress;

  /**
   * Double ended queue to keep track of which process to schedule next. The ordering
   * of the queue defines our priority. That is, we try to run processes at the front
   * first. Notice we also push processes to the front. We believe newer childs are
   * more likely to finish before older processes.
   */
  deque<pid_t> processQueue;

  /**
   * Fast access hastable for updating states. This must be fast as unfortunately we
   * must update the process state using reportProgress after every blocking system call.
   */
  unordered_map<pid_t, processState> processStateMap;

  // Remove process from scheduler. Calls @deleteProcess, used to share code between
  // removeAndScheduleNext and removeAndScheduleParent.
  void remove(pid_t terminatedProcess);

  // Get next process based on which is runnable/maybeRunnable in order of our deque.
  // @param currentProcess: Process that just got preempted. This is needed to avoid
  // repicking ourselves.
  pid_t scheduleNextProcess(pid_t currentProcess);

  // Iterate through all blocked process' and change their status to maybeBlocked.
  // This is needed as we consider both maybeRunnable processes for running, but never
  // blocked.
  void changeToMaybeRunnable();


  // Debug function to print all data about processes.
  void printProcesses();
};

#endif
