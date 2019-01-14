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
  auto pair = make_pair(curr, nextPid);
  preemptMap.insert(pair);
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
  // Remove dependencies in the scheduler's dependency tree.
  removeDependencies(); 
  
  // Sanity check that there is at least one process available.
  if (runnableHeap.empty() && blockedHeap.empty()){
    string err = "scheduler::remove: No such element to delete from scheduler.";
    throw runtime_error("dettrace runtime exception: " + err);
  }

  // If the process to be removed is from the runnableHeap:
  // Pop the top element of the runnableHeap.
  // Then, add the element to the finishedProcesses set.
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

pid_t scheduler::findNextNotWaiting(bool swapped){
  vector<pid_t> processes;
  pid_t p = 0;  
  bool waiting = false; 
  bool done = false;
  // We find a process that is not waiting on a child by iterating through the
  // priority queue and checking the scheduler's process tree.
  while(!runnableHeap.empty()){
    p = runnableHeap.top();
    waiting = schedulerTree.find(p) != schedulerTree.end();
    done = isFinished(p);
    if(!waiting && !done){
      break;
    }else{
      processes.push_back(p);
      runnableHeap.pop();
    }
  }
  for(int i = 0; i < processes.size(); i++){
    runnableHeap.push(processes[i]);
  }
  processes.clear();
  if(waiting && !done){
    // We went through the entire given heap and could not find a process not waiting on a child.
    // So we just schedule the top of the heap to run, because it is okay to run because
    // it has not finished yet.
    // (Example: The child is waiting for the parent to write to a pipe.)
    p = runnableHeap.top();
    if(!swapped){
      auto msg = log.makeTextColored(Color::blue, "[%d] chosen to run next from runnable heap. \n");
      log.writeToLog(Importance::info, msg, p);
    }else{
      auto msg = log.makeTextColored(Color::blue, "[%d] chosen to run next. Heaps were swapped. \n");
      log.writeToLog(Importance::info, msg, p);
    }
    return p;
  }else if(waiting && done){
    // We went through the runnable heap and could not find a process not waiting on a child
    // that is also not finished. So we must look to the blocked heap for a process to schedule.
    if(!blockedHeap.empty()){
      p = blockedHeap.top();
      bool topDone = isFinished(p);
      if(!topDone){
        auto msg = log.makeTextColored(Color::blue, "[%d] chosen to run next from blocked heap, moved to runnableHeap. \n");
        log.writeToLog(Importance::info, msg, p);
        blockedHeap.pop();
        runnableHeap.push(p);
        return p;
      }
    }
  }
  // We found a process not waiting on a child.
  // Process was set to "p" in the above while loop.
  // We schedule this process next.
  if(!swapped){
    auto msg = log.makeTextColored(Color::blue, "[%d] chosen to run next from runnable heap. \n");
    log.writeToLog(Importance::info, msg, p);
  }else{
    auto msg = log.makeTextColored(Color::blue, "[%d] chosen to run next. Heaps were swapped. \n");
    log.writeToLog(Importance::info, msg, p);
  }
  return p;
  
}

pid_t scheduler::scheduleNextProcess(){
  callsToScheduleNextProcess++;
  bool swapped = false;
  // We try all processes in the runnable heap. If there are none in the runnable
  // heap, we try those in the blocked heap.
  // We call findNextNotWaiting() to find the next process not waiting on a child
  // to schedule next.
 
  bool deadlock = false;
  if(!runnableHeap.empty() && !blockedHeap.empty()){
    deadlock = circularDependency();
  }

  if(deadlock){
    throw runtime_error("dettrace runtime exception: No runnable processes left in scheduler!\n");
  }else if(!runnableHeap.empty()){ 
    pid_t nextProcess = findNextNotWaiting(swapped);
    return nextProcess;
  }else{
    priority_queue<pid_t> temp = runnableHeap;
    runnableHeap = blockedHeap;
    blockedHeap = temp;
    swapped = true;
    pid_t nextProcess = findNextNotWaiting(swapped);
    return nextProcess;
  }

  // Went through all processes and none were ready. This is a dead lock.
  throw runtime_error("dettrace runtime exception: No runnable processes left in scheduler!\n");
}

bool scheduler::circularDependency(){
  pid_t blockedTop = blockedHeap.top();
  pid_t runnableTop = runnableHeap.top();
  bool firstDep = false;
  bool secondDep = false;
  for(auto iter = preemptMap.begin(); iter != preemptMap.end(); iter++){
    if((iter->first == blockedTop) && (iter->second == runnableTop)){
      firstDep = true;
    }else if((iter->first == runnableTop) && (iter->second == blockedTop)){
      secondDep = true;
    }else if(firstDep && secondDep){
      break;
    }
  }
  return firstDep && secondDep;
}

void scheduler::removeDependencies(){
  pid_t finishedProcess = runnableHeap.top();
  for(auto iter = preemptMap.begin(); iter != preemptMap.end(); iter++){
    if(iter->first == finishedProcess){
      preemptMap.erase(iter);
    }else if(iter->second == finishedProcess){
      preemptMap.erase(iter);
    }
  }
}

void scheduler::eraseSchedChild(pid_t process){
  for(auto iter = schedulerTree.begin(); iter != schedulerTree.end(); iter++){
    if(iter->second == process){
      schedulerTree.erase(iter);
      break;
    } 
  }
}

void scheduler::insertSchedChild(pid_t parent, pid_t child){
  auto pair = make_pair(parent, child);
  schedulerTree.insert(pair);
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
