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
  nextPid(startingPid){
  parallelProcesses.insert(startingPid);
}

bool scheduler::isInParallel(pid_t process){
  const bool parallel = parallelProcesses.find(process) != parallelProcesses.end();
  return parallel;
}

// Should only have to remove from parallelProcesses.
void scheduler::removeFromScheduler(pid_t pid){
  if(parallelProcesses.find(pid) != parallelProcesses.end()){
    auto msg = 
      log.makeTextColored(Color::blue, "Process [%d] removed from parallelProcesses\n");
    log.writeToLog(Importance::info, msg, pid);
    parallelProcesses.erase(pid);
  }else{
    throw runtime_error("Process not found in parallelProcesses when trying to remove");
  }
}

void scheduler::preemptSyscall(pid_t pid){
  // Pop the pid from the front of the 
  // runnableQueue or blockedQueue (depending where it happens to be)
  // and move it to the end of the blockedQueue.
  pid_t firstRunnable = runnableQueue.front();
  pid_t firstBlocked = blockedQueue.front();
  if(pid == firstRunnable){
    auto msg = 
      log.makeTextColored(Color::blue, "Process [%d] popped from runnableQueue\n");
    log.writeToLog(Importance::info, msg, pid);
    runnableQueue.pop();
  }else if(pid == firstBlocked){
    auto msg = 
      log.makeTextColored(Color::blue, "Process [%d] popped from blockedQueue\n");
    log.writeToLog(Importance::info, msg, pid);
    blockedQueue.pop();
  }
  blockedQueue.push(pid); 
}

void scheduler::resumeParallel(pid_t pid){
  // Remove the pid from the proper queue.
  pid_t firstRunnable = runnableQueue.front();
  pid_t firstBlocked = blockedQueue.front();
  if(pid == firstRunnable){
    auto msg = 
      log.makeTextColored(Color::blue, "Process [%d] popped from runnableQueue\n");
    log.writeToLog(Importance::info, msg, pid);
    runnableQueue.pop();
  }else if(pid == firstBlocked){
    auto msg = 
      log.makeTextColored(Color::blue, "Process [%d] popped from blockedQueue\n");
    log.writeToLog(Importance::info, msg, pid);
    blockedQueue.pop();
  }else{
    throw runtime_error("Process not found in either queue, trying to resume");
  }

  // Add the process to the parallelProcesses set. 
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
