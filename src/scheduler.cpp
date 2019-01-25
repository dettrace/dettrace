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

void scheduler::removeAndScheduleParent(pid_t child, pid_t parent){
  // Error if the parent of the proces has not finished.
  // Else, remove the process, and schedule its parent to run next.
  if(! isFinished(parent)){
    throw runtime_error("dettrace runtime exception: scheduleThisProcess: Parent : " + to_string(parent) +
                        " was not marked as finished!");
  }

  auto msg = log.makeTextColored(Color::blue, "Parent [%d] scheduled for exit.\n");
  log.writeToLog(Importance::info, msg, parent);
  remove(child);
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

void scheduler::removeNotTop(pid_t process){
  vector<pid_t> runnableProcesses;
  vector<pid_t> blockedProcesses;
  pid_t p = 0;
  bool foundInRunnable = false;

  // Go through the runnableHeap, try to find the process.
  // If found, remove it, and break out of the loop.
  while(!runnableHeap.empty()){
    p = runnableHeap.top();
    if(process == p){
      runnableHeap.pop();
      finishedProcesses.insert(p);
      foundInRunnable = true;
      break;
    }else{
      runnableProcesses.push_back(p);
      runnableHeap.pop();
    }
  }

  if(foundInRunnable){
    // We found our process in the runnable heap.
    // Just re-add processes to the runnable heap,
    // clear the vector, and return.
    for(int i = 0; i < runnableProcesses.size(); i++){
      runnableHeap.push(runnableProcesses[i]);
    }
    runnableProcesses.clear();
    return;
  }else{
    // We have to look in the blocked heap for the process
    // we want to remove.
    // Find it and remove it.
    while(!blockedHeap.empty()){
      p = blockedHeap.top();
      if(process == p){
        blockedHeap.pop();
        finishedProcesses.insert(p);
        break;
      }else{
        blockedProcesses.push_back(p);
        blockedHeap.pop();
      }
    }
    
    // Then re-add the processes we examined to the blocked heap.
    for(int j = 0; j < blockedProcesses.size(); j++){
      blockedHeap.push(blockedProcesses[j]);
    }
    blockedProcesses.clear();
    return;
  }
}

void scheduler::remove(pid_t process){
  // Remove dependencies in the scheduler's dependency tree.
  removeDependencies(); 

  // Sanity check that there is at least one process available.
  if (runnableHeap.empty() && blockedHeap.empty()){
    string err = "scheduler::remove: No such element to delete from scheduler.";
    throw runtime_error("dettrace runtime exception: " + err);
  }

  // Sanity check: can't call top() on a priority queue
  // unless its nonempty (on an empty one it will error). 
  pid_t runnableTop = -1;
  pid_t blockedTop = -1;
  if(runnableHeap.size() > 0){
    runnableTop = runnableHeap.top();
  } 
  if(blockedHeap.size() > 0){
    blockedTop = blockedHeap.top();
  }

  if(process == runnableTop){
    // Easy case: the process we want to remove is at the top of the runnable heap.
    // Pop the top of the runnableHeap, and insert it into the list of finished processes.
    runnableHeap.pop();
    finishedProcesses.insert(runnableTop);
  }else if(process == blockedTop){
    // Easy case: process is at the top of the blocked heap.
    // Pop the top of the blockedHeap, and insert it into the list of finished processes.
    blockedHeap.pop();
    finishedProcesses.insert(blockedTop);
  }else{
    // Harder case: the process we want to remove is not at the top of the runnable
    // heap or the blocked heap.
    // Logic to remove a process that is not at the top of the heap is handled 
    // by the removeNotTop() function.
    removeNotTop(process);
  }
  
  auto msg =
    log.makeTextColored(Color::blue,"Removing process from scheduler: [%d]\n");
  log.writeToLog(Importance::info, msg, process);
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
    throw runtime_error("dettrace runtime exception: Deadlock detected!\n");
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

void scheduler::eraseThread(pid_t thread){
  for(auto iter = threadTree.begin(); iter != threadTree.end(); iter++){
    if(iter->second == thread){
      threadTree.erase(iter);
      break;
    }
  }
}

int scheduler::countThreads(pid_t parent){
  return threadTree.count(parent);
}
void scheduler::insertSchedChild(pid_t parent, pid_t child){
  auto pair = make_pair(parent, child);
  schedulerTree.insert(pair);
}

void scheduler::insertThreadTree(pid_t parent, pid_t thread){
  auto pair = make_pair(parent, thread);
  threadTree.insert(pair);
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
