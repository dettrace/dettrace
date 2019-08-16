#include "logger.hpp"
#include "systemCallList.hpp"
#include "dettraceSystemCall.hpp"
#include "util.hpp"
#include "state.hpp"
#include "ptracer.hpp"
#include "scheduler.hpp"

#include <queue>
#include <set>

scheduler::scheduler(pid_t startingPid, logger& log):
  log(log),
  startingPid(startingPid){
  parallelProcesses.insert(startingPid);
}

pid_t scheduler::getStartingPid(){
  return startingPid;
}

bool scheduler::isInParallel(pid_t process){
  const bool parallel = parallelProcesses.find(process) != parallelProcesses.end();
  return parallel;
}

bool scheduler::isFinished(pid_t process){
  const bool finished = finishedProcesses.find(process) != finishedProcesses.end();
  return finished;
}

bool scheduler::emptyScheduler(){
  return runnableQueue.empty() && blockedQueue.empty() && parallelProcesses.empty();
}

int scheduler::numberBlocked(){
  return blockedQueue.size();
}

int scheduler::numberRunnable(){
  return runnableQueue.size();
}

pid_t scheduler::getNextRunnable(){
  if(!runnableQueue.empty()){
    return runnableQueue.front();
  }
  return -1;
}

pid_t scheduler::getNextBlocked(){
  if(!blockedQueue.empty()){
    return blockedQueue.front();
  }
  return -1;
}

void scheduler::resumeRetry(pid_t pid){
  if(blockedQueue.front() != pid){
    throw runtime_error("trying to resume retry with wrong pid");
  }
  blockedQueue.pop_front();
  blockedQueue.push_front(pid);
}

void scheduler::removeFromScheduler(pid_t pid){
  bool found = false;
  if(parallelProcesses.find(pid) != parallelProcesses.end()){
    auto msg = 
      log.makeTextColored(Color::blue, "Process [%d] removed from parallelProcesses\n");
    log.writeToLog(Importance::info, msg, pid);
    parallelProcesses.erase(pid);
    found = true;
  }
  deque<pid_t> blockedTemp;
  deque<pid_t> runnableTemp;

  // If the process was not in parallelProcesses, have to check the 
  // blockedQueue and the runnableQueue. Throw an error if we don't find it.
  while(!blockedQueue.empty()){
    pid_t frontPid = blockedQueue.front();
    blockedQueue.pop_front();
    if(frontPid == pid){
      auto msg = 
        log.makeTextColored(Color::blue, "Process [%d] removed from blockedQueue\n");
      log.writeToLog(Importance::info, msg, pid);
      break;
    }else{
      blockedTemp.push_front(frontPid);
    }
  }

  while(!blockedQueue.empty()){
    pid_t frontPid = blockedQueue.front();
    blockedTemp.push_front(frontPid);
    blockedQueue.pop_front();
  }
  blockedQueue = blockedTemp;

  // We may need to look at the runnableQueue as well.    
  while(!runnableQueue.empty()){
    pid_t frontPid = runnableQueue.front();
    runnableQueue.pop_front();
    if(frontPid == pid){
      auto msg = 
        log.makeTextColored(Color::blue, "Process [%d] removed from runnableQueue\n");
      log.writeToLog(Importance::info, msg, pid);
      break;
    }else{
      runnableTemp.push_front(frontPid);
    }
  }

  while(!runnableQueue.empty()){
    pid_t frontPid = runnableQueue.front();
    runnableTemp.push_front(frontPid);
    runnableQueue.pop_front();
  }
  runnableQueue = runnableTemp;

  finishedProcesses.insert(pid);
}

void scheduler::preemptSyscall(pid_t pid){
  pid_t frontPid = runnableQueue.front();
  if(frontPid != pid){
    throw runtime_error("trying to preempt wrong pid!");
  }
  runnableQueue.pop_front();
  blockedQueue.push_front(pid); 
}

void scheduler::resumeParallel(pid_t pid){
  pid_t frontBlocked = blockedQueue.front();
  pid_t frontRunnable = runnableQueue.front();
  if(frontBlocked == pid){
    blockedQueue.pop_front();
  }else if(frontRunnable == pid){
    runnableQueue.pop_front();
  }else{
    throw runtime_error("trying to resume pid that is not front of either queue");
  }
  parallelProcesses.insert(pid); 
}

void scheduler::addToParallelSet(pid_t newProcess){
  parallelProcesses.insert(newProcess); 
}

void scheduler::addToRunnableQueue(pid_t pid){
  // Remove the pid from parallelProcesses.
  // Push it to the runnableQueue.
  parallelProcesses.erase(pid);
  runnableQueue.push_front(pid);
}

void scheduler::printProcesses(){
  log.writeToLog(Importance::extra, "Printing parallelProcesses set\n");
  // Print the parallelProcesses set.
  for(auto pid : parallelProcesses){ 
    log.writeToLog(Importance::extra, "Pid [%d]\n", pid);
  }

  log.writeToLog(Importance::extra, "Printing runnableQueue\n");
  // Print the runnableQueue. Their ordering is their current priority.
  for (auto pid: runnableQueue) {
    log.writeToLog(Importance::extra, "Pid [%d]\n", pid);
  }

  log.writeToLog(Importance::extra, "Printing blockedQueue\n");
  // Print the blockedQueue. Their ordering is their current priority. 
  for (auto pid: blockedQueue) {
    log.writeToLog(Importance::extra, "Pid [%d]\n", pid);
  }

  return;
}
