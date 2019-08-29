#ifndef SCHEDULER_H
#define SCHEDULER_H

#include "logger.hpp"
#include "state.hpp"

#include <queue>
#include <map>

using namespace std;

/**
 * Scheduler class for hybrid scheduling policy.
 * All processes run in parallel unless doing system calls.
 *
 * processQueue: queue of all pids currently running. 
 *
 * Processes can be in one of 4 states: 
 * - blocked (on a syscall)
 * - running (in parallel)
 * - waiting (to do a syscall)
 * - finished (has exited)
 *
 * Start with all pids in the runnableQueue. 
 * Then swap the blockedQueue with the runnableQueue, so that next time,
 * the blocked ones are tried first.
 *
 * Go through queue. Try all waiting pids and blocked pids.
 * Then do a wait(-1). Rinse and repeat.
 * Whichever pid is at the front has highest priority 
 * to do a system call. If it is successful or if it would block on
 * the syscall, it is moved to the end of the processQueue. Basically,
 * when a pid gets to the front of the queue, it stays there until it
 * successfully does a syscall or would block from one.
 */

enum class processState{
  running,
  blocked,
  waiting,
  finished
};

class scheduler{
public:
  scheduler(pid_t startingPid, logger& log);

  /**
   * @return pid of root process in tracee.
   */
  pid_t getStartingPid();

  /**
   * @return pid at the given position in the processQueue.
   * @param position in processQueue.
   */
  pid_t getPidAt(int pos);

  /**
   * Returns true if pid is still in the scheduler.
   */
  bool isAlive(pid_t pid);

  /**
   * Returns the number of processes currently alive in the 
   * scheduler.
   * @return number of processes.
   */
  int processCount();

  /**
   * Creates new process struct (default state
   * "running") and adds it to the end of the 
   * processQueue.
   * @param newProcess to add to
   * processQueue.
   */
  void addToQueue(pid_t pid);
  //void addToParallelSet(pid_t newProcess);

  /**
   * Moves process from wherever it is in the queue
   * to the end of it.
   * @param pid to move to the end of the queue.
   */
  void moveToEnd(pid_t pid);

  /**
   * Changes process state.
   * @param pid to change.
   * @enum processState newState for the pid.
   */
  void changeProcessState(pid_t pid, processState newState);

  /**
   * Get process state.
   * @param pid.
   * @return pid's state (enum value).
   */
  enum processState getProcessState(pid_t pid);

  /**
   * Process is completely done. Remove it from 
   * processQueue. Change its state to "finished" in the
   * procStateMap.
   * @param pid to remove from scheduler.
   */
  void removeFromScheduler(pid_t pid);

  // Keep track of how many times scheduleNextStopped was called:
  uint32_t callsToScheduleNextStopped = 0;

  // A function to kill all processes.
  // It also clears the processQueue.
  void killAllProcesses() {
    while(!processQueue.empty()){ 
      pid_t pid = processQueue.front();
      if(procStateMap[pid] != processState::finished){
        kill(pid, SIGKILL);
      }
      processQueue.pop_front();
    }
  }

private:
  logger& log; /**< log file wrapper */

  /**
   * Pid for next process to run.
   */
  pid_t startingPid = -1;

  deque<pid_t> processQueue;
  unordered_map<pid_t, processState> procStateMap;

public:
  /**< Debug function to print all data about processes. */
  // Prints pids and their current state (either blocked, running,
  // or waiting to do a syscall)
  void printProcesses();
};

#endif
