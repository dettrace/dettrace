#include "logger.hpp"
#include "systemCallList.hpp"
#include "dettraceSystemCall.hpp"
#include "util.hpp"
#include "state.hpp"
#include "ptracer.hpp"
#include "scheduler.hpp"

#include <deque>
#include <cassert>

scheduler::scheduler(pid_t startingPid, logger& log):
  log(log),
  startingPid(startingPid){
  processQueue.push_back(startingPid);
  procStateMap.insert(pair<pid_t, processState>(startingPid, processState::running));
}

pid_t scheduler::getStartingPid(){
  return startingPid;
}

pid_t scheduler::getPidAt(int pos){
  if(pos >= processQueue.size() ||
     pos < 0){
    throw runtime_error("accessing invalid index in processQueue");
  }

  return processQueue[pos];
}

int scheduler::processCount(){
  return processQueue.size();
}

void scheduler::addToQueue(pid_t pid){
  processQueue.push_back(pid);
  auto p = make_pair(pid, processState::running);
  procStateMap.insert(p);
}

void scheduler::moveToEnd(pid_t proc){
  assert(!processQueue.empty());
 
  bool found = false;
  deque<pid_t> tempQueue;
  while(!processQueue.empty()){
    pid_t frontPid = processQueue.front();
    processQueue.pop_front();
    if(frontPid == proc){
      // we found it!
      found = true;
      break;
    }else{
      tempQueue.push_front(frontPid); 
    }
  }

  if(!found){
    throw runtime_error("Could not find proc to move to end of processQueue");
  }

  while(!tempQueue.empty()){
    pid_t frontPid = tempQueue.front();
    tempQueue.pop_front();
    processQueue.push_front(frontPid);
  }

  processQueue.push_back(proc);
}

void scheduler::changeProcessState(pid_t pid, processState newState){
  if(procStateMap.find(pid) == procStateMap.end()){
    throw runtime_error("cannot change state of nonexistent pid");
  }
  procStateMap[pid] = newState;
}

enum processState scheduler::getProcessState(pid_t pid){
  if(procStateMap.find(pid) == procStateMap.end()){
    throw runtime_error("cannot get state of nonexistent pid");
  }

  return procStateMap[pid];
}

bool scheduler::isAlive(pid_t pid){
  bool found = false;
  deque<pid_t> tempQueue;

  while(!processQueue.empty()){
    pid_t frontPid = processQueue.front();
    if(frontPid == pid){
      auto msg = 
        log.makeTextColored(Color::blue, "Process [%d] is in processQueue\n");
      log.writeToLog(Importance::info, msg, pid);
      found = true;
      break;
    }else{
      assert(!processQueue.empty());
      processQueue.pop_front();
      tempQueue.push_back(frontPid);
    }
  }

  while(!processQueue.empty()){
    pid_t frontPid = processQueue.front();
    tempQueue.push_back(frontPid);
    processQueue.pop_front();
  }
  processQueue = tempQueue;
  
  return found;
}

void scheduler::removeFromScheduler(pid_t pid){
  deque<pid_t> tempQueue;

  // Remove the pid from the processQueue.
  while(!processQueue.empty()){
    pid_t frontPid = processQueue.front();
    processQueue.pop_front();
    if(frontPid == pid){
      auto msg = 
        log.makeTextColored(Color::blue, "Process [%d] removed from processQueue\n");
      log.writeToLog(Importance::info, msg, pid);
      break;
    }else{
      tempQueue.push_back(frontPid);
    }
  }

  while(!processQueue.empty()){
    pid_t frontProc = processQueue.front();
    tempQueue.push_back(frontProc);
    processQueue.pop_front();
  }
  processQueue = tempQueue;

  // Remove from state map as well.
  unordered_map<pid_t, processState>::iterator it = procStateMap.find(pid);
  if(it != procStateMap.end()){
    it->second = processState::finished;
  }else{
    throw runtime_error("tried to remove nonexistent pid from procStateMap");
  }

}

void scheduler::printProcesses(){
  log.writeToLog(Importance::extra, "Printing processQueue\n");
  // Print the processQueue. Their ordering is their current priority. 
  for (int i = 0; i < processQueue.size(); i++) {
    pid_t pid = processQueue[i];
    enum processState s = procStateMap[pid];
    log.writeToLog(Importance::extra, "Pid [%d]\n", pid);
    if(s == processState::running){
      log.writeToLog(Importance::extra, "State: Running\n");
    }else if(s == processState::blocked){
      log.writeToLog(Importance::extra, "State: Blocked\n");
    }else{
      log.writeToLog(Importance::extra, "State: Waiting\n");
    }
  }
  return;
}
