#include "scheduler.hpp"
#include "dettraceSystemCall.hpp"
#include "logger.hpp"
#include "ptracer.hpp"
#include "state.hpp"
#include "systemCallList.hpp"
#include "util.hpp"

//#include <deque>
#include <queue>
#include <set>
#include <vector>

bool removeElementFromHeap(priority_queue<pid_t>& heap, pid_t element);

scheduler::scheduler(pid_t startingPid, logger& log)
    : log(log), nextPid(startingPid) {
  // Processes are always spawned as runnable.
  runnableHeap.push(startingPid);
}

pid_t scheduler::getNext() { return nextPid; }

void scheduler::removeAndScheduleParent(pid_t child, pid_t parent) {
  // Error if the parent of the proces has not finished.
  // Else, remove the process, and schedule its parent to run next.
  if (!isFinished(parent)) {
    runtimeError(
        "dettrace runtime exception: scheduleThisProcess: Parent : " +
        to_string(parent) + " was not marked as finished!");
  }

  remove(child);
  auto msg =
      log.makeTextColored(Color::blue, "Parent [%d] scheduled for exit.\n");
  log.writeToLog(Importance::info, msg, parent);

  nextPid = parent;
}

bool scheduler::isFinished(pid_t process) {
  const bool finished =
      finishedProcesses.find(process) != finishedProcesses.end();
  return finished;
}

// CHECK
void scheduler::markFinishedAndScheduleNext(pid_t process) {
  auto msg =
      log.makeTextColored(Color::blue, "Process [%d] marked as finished!\n");
  log.writeToLog(Importance::info, msg, process);

  auto str =
      "Process moved to finished set (deleted from runnable/blocked heaps)\n";
  log.writeToLog(Importance::info, str);

  // Remove process from our regular set of runnable!
  remove(process);
  // Add the process to the set of finished processes.
  finishedProcesses.insert(process);

  nextPid = scheduleNextProcess();
}

// CHECK
void scheduler::preemptAndScheduleNext() {
  pid_t curr = runnableHeap.top();
  auto msg = log.makeTextColored(Color::blue, "Preempting process: [%d]\n");
  log.writeToLog(Importance::info, msg, curr);

  // We're now blocked.
  runnableHeap.pop();
  blockedHeap.push(curr);
  log.writeToLog(Importance::extra, "Process marked as blocked.\n", curr);

  nextPid = scheduleNextProcess();
}

// CHECK
void scheduler::addAndScheduleNext(pid_t newProcess) {
  auto msg = log.makeTextColored(
      Color::blue, "New process added to scheduler: [%d]\n");
  log.writeToLog(Importance::info, msg, newProcess);

  msg = log.makeTextColored(Color::blue, "[%d] scheduled as next.\n");
  log.writeToLog(Importance::info, msg, newProcess);

  // Add the process to the runnableHeap, and set nextPid ourselves.
  // (This is because the new process is always capable of running.)
  runnableHeap.push(newProcess);
  nextPid = newProcess;

  // We still want to count this scheduling event :)
  callsToScheduleNextProcess++;
  return;
}

// CHECK
void scheduler::remove(pid_t process) {
  auto msg = log.makeTextColored(
      Color::blue, "Removing process runnable|blocked heaps: [%d]\n");
  log.writeToLog(Importance::info, msg, process);

  // Sanity check that there is at least one process available.
  if (runnableHeap.empty() && blockedHeap.empty()) {
    string err = "scheduler::remove: No such element to delete from scheduler.";
    runtimeError(err);
  }

  if (!removeElementFromHeap(runnableHeap, process)) {
    if (!removeElementFromHeap(blockedHeap, process)) {
      string err =
          "scheduler::remove: No such element to delete from scheduler.";
      runtimeError(err);
    }
  }

  return;
}

// CHECK
bool scheduler::removeAndScheduleNext(pid_t process) {
  // This process was removed from the heaps a while ago, it only lives in the
  // finished set now. Note not all processes are marked as finished, only
  // processes that had children alive at their time of exit. This may seem more
  // complicated, but it keeps finihsed processes out of the runnable/blocked
  // queues.
  if (isFinished(process)) {
    log.writeToLog(
        Importance::info,
        "Removing markedAsFinished process from finish set.\n");
    finishedProcesses.erase(process);
  } else {
    // Remove the process forever. If both heaps are empty, we are done.
    // Otherwise, schedule the next process to run.
    remove(process);
  }

  if (runnableHeap.empty() && blockedHeap.empty()) {
    return true;
  } else {
    nextPid = scheduleNextProcess();
    return false;
  }
}

// CHECK
pid_t scheduler::scheduleNextProcess() {
  printProcesses();
  callsToScheduleNextProcess++;

  if (!runnableHeap.empty()) {
    pid_t nextProcess = runnableHeap.top();
    return nextProcess;
  } else {
    if (blockedHeap.empty()) {
      runtimeError("No processes left to run!\n");
    }
    priority_queue<pid_t> temp = runnableHeap;
    runnableHeap = blockedHeap;
    blockedHeap = temp;

    pid_t nextProcess = runnableHeap.top();
    return nextProcess;
  }
}

// CHECK
void scheduler::printProcesses() {
  log.writeToLog(Importance::extra, "Printing runnable processes\n");
  // Print the runnableHeap.
  priority_queue<pid_t> runnableCopy = runnableHeap;
  while (!runnableCopy.empty()) {
    pid_t curr = runnableCopy.top();
    runnableCopy.pop();
    log.writeToLog(Importance::extra, "Pid [%d], runnable\n", curr);
  }

  log.writeToLog(Importance::extra, "Printing blocked processes\n");
  // Print the blockedHeap.
  priority_queue<pid_t> blockedCopy = blockedHeap;
  while (!blockedCopy.empty()) {
    pid_t curr = blockedCopy.top();
    blockedCopy.pop();
    log.writeToLog(Importance::extra, "Pid [%d], blocked\n", curr);
  }
  return;
}

// CHECK
bool removeElementFromHeap(priority_queue<pid_t>& heap, pid_t element) {
  vector<pid_t> elements;
  bool foundElement = false;

  // Go through heap, try to find the element.
  while (!heap.empty()) {
    pid_t p = heap.top();
    heap.pop();
    if (element == p) {
      foundElement = true;
    } else {
      elements.push_back(p);
    }
  }

  // Take all elements that we popped off and put them back in the heap.
  for (auto e : elements) {
    heap.push(e);
  }

  return foundElement;
}
