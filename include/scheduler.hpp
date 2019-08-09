#ifndef SCHEDULER_H
#define SCHEDULER_H

#include "logger.hpp"
#include "state.hpp"

#include <queue>
#include <set>
#include <map>

using namespace std;

/**
 * Scheduler class for hybrid scheduling policy.
 * All processes run in parallel unless doing system calls.
 *
 * parallelProcesses: parallel process set that contains all processes currently 
 * running in parallel.
 *
 * runnableQueue: queue of pids that want to do a syscall and aren't blocked on it.
 *
 * blockedQueue: queue of pids that are blocked on their syscall (it would have failed).
 * 
 * Start with all pids in the runnableQueue. 
 * Then swap the blockedQueue with the runnableQueue, so that next time,
 * the blocked ones are tried first.
 * Then do a wait(-1). Rinse and repeat.
 * Whichever pid is at the front has highest priority 
 * to do a system call. If it is successful, it is removed from
 * its queue and put back into the parallelProcesses set. If it fails, 
 * it is moved to the back of the blockedQueue.
 */

class scheduler{
public:
  scheduler(pid_t startingPid, logger& log);

  /**
   * @return pid of root process in tracee.
   */
  pid_t getStartingPid();

  /**
   * Returns true if the pid is in the parallelProcesses set.
   * @param process to check.
   */
  bool isInParallel(pid_t process);

  /**
   * Returns true if the pid is in the finishedProcesses set.
   * @param process to check.
   */
  bool isFinished(pid_t process);

  /**
   * @return true if parallelProcesses, runnableQueue,
   * and blockedQueue are empty.
   */
  bool emptyScheduler();

  /**
   * @return the number of pids in the blockedQueue.
   */
  int numberBlocked();

  /**
   * @return the number of pids in the runnableQueue.
   */
  int numberRunnable();

  /**
   * @return next runnable pid that needs to do a syscall.
   * (Return the front of the runnableQueue)
   */
  pid_t getNextRunnable();

  /**
   * @return next blocked pid that needs to do a syscall.
   * (Return the front of the blockedQueue)
   */
  pid_t getNextBlocked();

  /**
   * Move pid from the front of the blockedQueue to the back.
   * @param pid to move.
   */
  void resumeRetry(pid_t pid);

  /**
   * The syscall would have failed. 
   * Pop the pid from the front of the 
   * runnableQueue and move it to the end of the blockedQueue.
   * @param pid to preempt.
   */
  void preemptSyscall(pid_t pid);

  /**
   * The syscall succeeded. 
   * Remove the pid from runnableQueue or blockedQueue.
   * Add it back to parallelProcesses.
   * @param pid to be resumed.
   * @param true if pid is on the blockedQueue currently.
   */
  void resumeParallel(pid_t pid, bool pidIsBlocked);

  /**
   * Adds new process to parallelProcesses.
   * @param newProcess to add to
   * parallelProcesses.
   */
  void addToParallelSet(pid_t newProcess);

  /**
   * Run the process sequentially for the duration of a 
   * system call.
   * Add process to the runnableQueue to start.
   * Remove the pid from parallelProcesses.
   * @param pid to move to runnableQueue.
   */
  void addToRunnableQueue(pid_t pid);

  /**
   * Process is completely done. Remove it from 
   * parallelProcesses. I believe this is where it should
   * always be, because syscalls are not the last thing a
   * process does before exiting.
   * @param pid to remove from scheduler
   */
  void removeFromScheduler(pid_t pid);

  // Keep track of how many times scheduleNextStopped was called:
  uint32_t callsToScheduleNextStopped = 0;

  // A function to kill all processes.
  // It also clears parallelProcesses, runnableQueue, and
  // blockedQueue.
  // Have to iterate through all because pids can only
  // be in one of the three at any given time.
  void killAllProcesses() {
    for(auto proc : parallelProcesses) {
      kill(proc, SIGKILL);
    }
    parallelProcesses.clear();

    while(!runnableQueue.empty()){ 
      pid_t pid = runnableQueue.front();
      kill(pid, SIGKILL);
      runnableQueue.pop();
    }

    while(!blockedQueue.empty()){ 
      pid_t pid = blockedQueue.front();
      kill(pid, SIGKILL);
      blockedQueue.pop();
    }
  }

private:
  logger& log; /**< log file wrapper */

  /**
   * Pid for next process to run.
   */
  pid_t startingPid = -1;

  set<pid_t> parallelProcesses;
  set<pid_t> finishedProcesses;
  queue<pid_t> runnableQueue;
  queue<pid_t> blockedQueue;

  /**< Debug function to print all data about processes. */
  void printProcesses();
};

#endif
