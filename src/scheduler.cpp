#include "logger.hpp"
#include "systemCallList.hpp"
#include "dettraceSystemCall.hpp"
#include "util.hpp"
#include "state.hpp"
#include "ptracer.hpp"
#include "scheduler.hpp"

//#include <deque>
#include <queue>
#include <set>
#include <vector>

bool removeElementFromHeap(priority_queue<pid_t>& heap, pid_t element);

scheduler::scheduler(pid_t startingPid, logger& log):
  log(log),
  nextPid(startingPid){
  // Processes are always spawned as runnable.
  runnableHeap.push(startingPid);
}

pid_t scheduler::getNext(){
  return nextPid;
}


void scheduler::preemptAndScheduleNext(preemptOptions p){
  pid_t curr = runnableHeap.top();
  auto msg = log.makeTextColored(Color::blue, "Preempting process: [%d]\n");
  log.writeToLog(Importance::info, msg, curr);

  // We're now blocked.
  if(p == preemptOptions::markAsBlocked){
    runnableHeap.pop();
    blockedHeap.push(curr);
    log.writeToLog(Importance::extra, "Process marked as blocked.\n", curr);
  }else if(p == preemptOptions::runnable){
    // If the process is still runnable we don't need to do anything.
    log.writeToLog(Importance::extra, "Process still runnable.\n", curr);
  }else{
    throw runtime_error("dettrace runtime exception: Unknown preemptOption!\n");
  }

  nextPid = scheduleNextProcess();
}


void scheduler::addAndScheduleNext(pid_t newProcess){
  auto msg = log.makeTextColored(Color::blue, "New process added to scheduler: [%d]\n");
  log.writeToLog(Importance::info, msg , newProcess);

  msg = log.makeTextColored(Color::blue, "[%d] scheduled as next.\n");
  log.writeToLog(Importance::info, msg , newProcess);

  // Add the process to the runnableHeap, and set nextPid ourselves.
  // (This is because the new process is always capable of running.)
  runnableHeap.push(newProcess);
  nextPid = newProcess;

  // We still want to count this scheduling event :)
  callsToScheduleNextProcess++;
  return;
}

void scheduler::remove(pid_t process){
  auto msg =
    log.makeTextColored(Color::blue,"Removing process from scheduler: [%d]\n");
  log.writeToLog(Importance::info, msg, process);

  // Sanity check that there is at least one process available.
  if (runnableHeap.empty() && blockedHeap.empty()){
    string err = "scheduler::remove: No such element to delete from scheduler.";
    throw runtime_error("dettrace runtime exception: " + err);
  }

  if (!removeElementFromHeap(runnableHeap, process)) {
    if(!removeElementFromHeap(blockedHeap, process)){
        string err = "scheduler::remove: No such element to delete from scheduler.";
        throw runtime_error("dettrace runtime exception: " + err);
    }
  }

  return;
}

bool scheduler::removeAndScheduleNext(pid_t process){
  // Remove the process. If both heaps are empty, we are done.
  // Otherwise, schedule the next process to run.
  remove(process);
  if(runnableHeap.empty() && blockedHeap.empty()){
    return true;
  }else{
    nextPid = scheduleNextProcess();
    // auto msg = log.makeTextColored(Color::blue, "Next process scheduled: [%d]\n");
    // log.writeToLog(Importance::info, msg, nextPid);
    return false;
  }
}

pid_t scheduler::scheduleNextProcess(){
  printProcesses();
  callsToScheduleNextProcess++;

  if(!runnableHeap.empty()){
    pid_t nextProcess = runnableHeap.top();
    return nextProcess;
  }else{
    if (blockedHeap.empty()) {
      throw runtime_error("No processes left to run!\n");
    }
    priority_queue<pid_t> temp = runnableHeap;
    runnableHeap = blockedHeap;
    blockedHeap = temp;

    pid_t nextProcess = runnableHeap.top();
    return nextProcess;
  }
}

void scheduler::printProcesses(){
  log.writeToLog(Importance::extra, "Printing runnable processes\n");
  // Print the runnableHeap.
  priority_queue<pid_t> runnableCopy = runnableHeap;
  while(!runnableCopy.empty()){
    pid_t curr = runnableCopy.top();
    runnableCopy.pop();
    log.writeToLog(Importance::extra, "Pid [%d], runnable\n", curr);
  }

  log.writeToLog(Importance::extra, "Printing blocked processes\n");
  // Print the blockedHeap.
  priority_queue<pid_t> blockedCopy = blockedHeap;
  while(!blockedCopy.empty()){
    pid_t curr = blockedCopy.top();
    blockedCopy.pop();
    log.writeToLog(Importance::extra, "Pid [%d], blocked\n", curr);
  }
  return;
}

bool removeElementFromHeap(priority_queue<pid_t>& heap, pid_t element) {
  vector<pid_t> elements;
  bool foundElement = false;

  // Go through heap, try to find the element.
  while(!heap.empty()){
    pid_t p = heap.top();
    heap.pop();
    if(element == p){
      foundElement = true;
    }else{
      elements.push_back(p);
    }
  }

  // Take all elements that we popped off and put them back in the heap.
  for(auto e: elements){
    heap.push(e);
  }

  return foundElement;
}
