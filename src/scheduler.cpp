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
  blockedQueue.pop();
  blockedQueue.push(pid);
}

// Should only have to remove from parallelProcesses.
void scheduler::removeFromScheduler(pid_t pid){
  if(parallelProcesses.find(pid) != parallelProcesses.end()){
    auto msg = 
      log.makeTextColored(Color::blue, "Process [%d] removed from parallelProcesses\n");
    log.writeToLog(Importance::info, msg, pid);
    parallelProcesses.erase(pid);
  }else{
    // TODO: handle removing from blockedQueue 
    // or runnableQueue if needed. 
  }

  finishedProcesses.insert(pid);
}

void scheduler::preemptSyscall(pid_t pid){
  pid_t frontPid = runnableQueue.front();
  if(frontPid != pid){
    throw runtime_error("trying to preempt wrong pid!");
  }
  runnableQueue.pop();
  blockedQueue.push(pid); 
}

void scheduler::resumeParallel(pid_t pid, bool pidIsBlocked){
  if(pidIsBlocked){
    pid_t frontPid = blockedQueue.front();
    if(frontPid != pid){
      throw runtime_error("trying to resume wrong pid from blockedQueue!");
    }
    blockedQueue.pop();
  }else{
    pid_t frontPid = runnableQueue.front();
    cout << "front pid on runnable queue is: " << frontPid << endl;
    cout << "param pid is: " << pid << endl; 
    if(frontPid != pid){
      throw runtime_error("trying to resume wrong pid from runnableQueue!");
    }
    runnableQueue.pop();
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
  runnableQueue.push(pid);
}

void scheduler::printProcesses(){
  log.writeToLog(Importance::extra, "Printing parallelProcesses set\n");
  // Print the parallelProcesses set.
  for(auto pid : parallelProcesses){ 
    log.writeToLog(Importance::extra, "Pid [%d]\n", pid);
  }

  log.writeToLog(Importance::extra, "Printing runnableQueue\n");
  // Print the runnableQueue. Their ordering is their current priority. 
  queue<pid_t> runnableCopy = runnableQueue;  
  while(!runnableCopy.empty()){
    pid_t pid = runnableCopy.front();
    log.writeToLog(Importance::extra, "Pid [%d]\n", pid);
    runnableCopy.pop();
  }


  log.writeToLog(Importance::extra, "Printing blockedQueue\n");
  // Print the blockedQueue. Their ordering is their current priority. 
  queue<pid_t> blockedCopy = blockedQueue;  
  while(!blockedCopy.empty()){
    pid_t pid = blockedCopy.front();
    log.writeToLog(Importance::extra, "Pid [%d]\n", pid);
    blockedCopy.pop();
  }
  return;
}
