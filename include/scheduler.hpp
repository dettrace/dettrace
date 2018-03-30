#ifndef SCHEDULER_H
#define SCHEDULER_H

#include "logger.hpp"
#include "state.hpp"

#include <deque>
#include <optional>
#include <unordered_map>

using namespace std;

/**
 *
 * runnable: We know for a fact ths process is able to make progress.
 * maybeRunnable: Another process has just finished making progress, we were blocked.
 *                now we might be able to make progress, maybe not?
 * blocked: We cannot make progress.
 */
enum class processState{ runnable, maybeRunnable, blocked };

string to_string(processState p);

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

  /**
   * Adds new process to scheduler! This new process will be scheduled to run next.
   */
  void addAndScheduleNext(pid_t newProcess);

  /**
   * Removes specified process and schedule new process to run.
   * @param empty: return true if we're all done!
   */
  bool removeAndScheduleNext(pid_t terminatedProcess);

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


  // Find and delete process.
  void deleteProcess(pid_t terminatedProcess);

  // Get next process based on which is runnable/maybeRunnable in order of our deque.
  // @param currentProcess: Process that just got preempted. This is needed to avoid
  // repicking ourselves.
  pid_t scheduleNextProcess(pid_t currentProcess);

  // Iterate through all blocked process' and change their status to maybeBlocked.
  // This is needed as we consider both maybeRunnable processes for running, but never
  // blocked.
  void toMaybeProgress();


  // Debug function to print all data about processes.
  void printProcesses();
};

#endif
