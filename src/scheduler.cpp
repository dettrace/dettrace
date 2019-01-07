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

scheduler::scheduler(pid_t startingPid, logger& log):
  log(log),
  nextPid(startingPid){
  // Processes are always spawned as runnable.
  runnableHeap.push(startingPid);
}

pid_t scheduler::getNext(){
  return nextPid;
}

void scheduler::removeAndScheduleParent(pid_t parent){
  if(! isFinished(parent)){
    throw runtime_error("dettrace runtime exception: scheduleThisProcess: Parent : " + to_string(parent) +
                        " was not marked as finished!");
  }

  auto msg = log.makeTextColored(Color::blue, "Parent [%d] scheduled for exit.\n");
  log.writeToLog(Importance::info, msg, parent);
  remove();
  nextPid = parent;
}

bool scheduler::isFinished(pid_t process){
  const bool finished = finishedProcesses.find(process) != finishedProcesses.end();
  return finished;
}

void scheduler::markFinishedAndScheduleNext(pid_t process){
  auto msg = log.makeTextColored(Color::blue, "Process [%d] marked as finished!\n");
  log.writeToLog(Importance::info, msg , process);
  
  // Add the process to the set of finished processes.
  finishedProcesses.insert(process);
  nextPid = scheduleNextProcess();
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

void scheduler::remove(){
  // Pop the top element of the runnableHeap.
  // Then, add the element to the finishedProcesses set.
  
  // Sanity check that there is at least one process available.
  if (runnableHeap.empty() && blockedHeap.empty()){
    string err = "scheduler::remove: No such element to delete from scheduler.";
    throw runtime_error("dettrace runtime exception: " + err);
  }

  pid_t terminatedProcess = runnableHeap.top();
  runnableHeap.pop();
  finishedProcesses.insert(terminatedProcess);
  auto msg =
    log.makeTextColored(Color::blue,"Removing process from scheduler: [%d]\n");
  log.writeToLog(Importance::info, msg, terminatedProcess);
  return;
}

bool scheduler::removeAndScheduleNext(){
  // Remove the process. If both heaps are empty, we are done.
  // Otherwise, schedule the next process to run.
  remove();
  if(runnableHeap.empty() && blockedHeap.empty()){
    return true;
  }else{
    nextPid = scheduleNextProcess();
    auto msg = log.makeTextColored(Color::blue, "Next process scheduled: [%d]\n");
    log.writeToLog(Importance::info, msg, nextPid);
    return false;
  }
}

pid_t scheduler::scheduleNextProcess(){
  callsToScheduleNextProcess++;
  // We try all processes in the runnable heap. If there are none in the runnable
  // heap, we try those in the blocked heap.
  if (!runnableHeap.empty()){ 
    pid_t p = runnableHeap.top();      
    auto msg = log.makeTextColored(Color::blue, "[%d] chosen to run next from runnable heap. \n");
    log.writeToLog(Importance::info, msg, p);
    return p;
  }else{
    priority_queue<pid_t> temp = runnableHeap;
    runnableHeap = blockedHeap;
    blockedHeap = temp;
    if (runnableHeap.size() > 0){
      pid_t p = runnableHeap.top();
      auto msg = log.makeTextColored(Color::blue, "[%d] chosen to run next. Heaps were swapped. \n");
      log.writeToLog(Importance::info, msg, p);
      return p;
    }
  }

  // Went through all processes and none were ready. This is a dead lock.
  throw runtime_error("dettrace runtime exception: No runnable processes left in scheduler!\n");
}

void scheduler::printProcesses(){
  log.writeToLog(Importance::extra, "Printing runnable processes");
  // Print the runnableHeap.
  priority_queue<pid_t> runnableCopy = runnableHeap;
  while(!runnableCopy.empty()){
    pid_t curr = runnableCopy.top();
    runnableCopy.pop();
    log.writeToLog(Importance::extra, "Pid [%d], runnable", curr);
  }
 
  log.writeToLog(Importance::extra, "Printing blocked processes");
  // Print the blockedHeap.
  priority_queue<pid_t> blockedCopy = blockedHeap;
  while(!blockedCopy.empty()){
    pid_t curr = blockedCopy.top();
    blockedCopy.pop();
    log.writeToLog(Importance::extra, "Pid [%d], blocked", curr);
  }
  return;
}
