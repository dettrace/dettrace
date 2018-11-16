#include "logger.hpp"
#include "systemCallList.hpp"
#include "systemCall.hpp"
#include "dettraceSystemCall.hpp"
#include "util.hpp"
#include "state.hpp"
#include "ptracer.hpp"
#include "scheduler.hpp"

#include <deque>

scheduler::scheduler(pid_t startingPid, logger& log):
  log(log),
  nextPid(startingPid){
  processQueue.push_front(startingPid);
  // Processes are always spawned as runnable.
  processStateMap[startingPid] = processState::runnable;
}

pid_t scheduler::getNext(){
  return nextPid;
}

void scheduler::removeAndScheduleParent(pid_t terminatedProcess, pid_t parent){
  if(! isFinished(parent)){
    throw runtime_error("dettrace runtime exception: scheduleThisProcess: Parent : " + to_string(parent) +
                        " was not marked as finished!");
  }

  auto msg = log.makeTextColored(Color::blue, "Parent [%d] scheduled for exit.\n");
  log.writeToLog(Importance::info, msg, parent);

  remove(terminatedProcess);
  nextPid = parent;
}

bool scheduler::isFinished(pid_t process){
  return processStateMap[process] == processState::finished;
}

void scheduler::markFinishedAndScheduleNext(pid_t process){
  auto msg = log.makeTextColored(Color::blue, "Process [%d] marked as finished!\n");
  log.writeToLog(Importance::info, msg , process);

  changeToMaybeRunnable();

  processStateMap[process] = processState::finished;
  nextPid = scheduleNextProcess(process);
}

void scheduler::reportProgress(pid_t process){
  auto msg = log.makeTextColored(Color::blue, "Process [%d] made progress!\n");
  log.writeToLog(Importance::info, msg , process);
  madeProgress = true;
}

void scheduler::preemptAndScheduleNext(pid_t process, preemptOptions p){
  auto msg = log.makeTextColored(Color::blue, "Preempting process: [%d]\n");
  log.writeToLog(Importance::info, msg , process);

  changeToMaybeRunnable();

  // We're now blocked.
  if(p == preemptOptions::markAsBlocked){
    processStateMap[process] = processState::blocked;
    log.writeToLog(Importance::extra, "Process marked as blocked.\n" , process);
  }else if(p == preemptOptions::runnable){
    log.writeToLog(Importance::extra, "Process still runnable.\n" , process);
    processStateMap[process] = processState::runnable;
  }else{
    throw runtime_error("dettrace runtime exception: Uknown preemptOption!\n");
  }

  nextPid = scheduleNextProcess(process);
}


void scheduler::addAndScheduleNext(pid_t newProcess){
  auto msg = log.makeTextColored(Color::blue, "New process added to scheduler: [%d]\n");
  log.writeToLog(Importance::info, msg , newProcess);

  msg = log.makeTextColored(Color::blue, "[%d] scheduled as next.\n");
  log.writeToLog(Importance::info, msg , newProcess);

  // New process always capable of running, and should! Save the work of calling
  // scheduleNextProcess by putting this process in the back and setting nextPid ourselves.
  processQueue.push_back(newProcess);
  processStateMap[newProcess] = processState::runnable;
  nextPid = newProcess;
  // printProcesses();

  // We still want to count this scheduling event :)
  callsToScheduleNextProcess++;
  return;
}

void scheduler::remove(pid_t terminatedProcess){
  auto msg =
    log.makeTextColored(Color::blue,"Removing process from scheduler: [%d]\n");
  log.writeToLog(Importance::info, msg, terminatedProcess);

    // After loop, i will hold index of process to delete from deque.
  size_t indexOfProc = 0;
  // Find index of our process based on their pid.
  for(auto currProcess : processQueue){
    if(currProcess == terminatedProcess){
      break;
    }
    indexOfProc++;
  }

  if(indexOfProc == processQueue.size()){
    string err = "scheduler::removeAndSchedulNext:"
      " No such element to delete from scheduler.";
    throw runtime_error("dettrace runtime exception: " + err);
  }

  msg = log.makeTextColored(Color::blue, "Process found at index [%d]. Deleting...\n");
  log.writeToLog(Importance::info, msg, indexOfProc);

  processQueue.erase(processQueue.begin() + indexOfProc);
  processStateMap.erase(terminatedProcess);
  return;
}

bool scheduler::removeAndScheduleNext(pid_t terminatedProcess){
  changeToMaybeRunnable();
  remove(terminatedProcess);

  if(processQueue.empty()){
    return true;
  }else{
    nextPid = scheduleNextProcess(terminatedProcess);

    auto msg = log.makeTextColored(Color::blue, "Next process scheduled: [%d]\n");
    log.writeToLog(Importance::info, msg, nextPid);

    return false;
  }

}

pid_t scheduler::scheduleNextProcess(pid_t currentProcess){
  callsToScheduleNextProcess++;
  // printProcesses();
  int numberOfProcesses = processQueue.size();

  for(int i = 0; i < numberOfProcesses; i++){
    // pop element and stick in back.
    pid_t p = processQueue.front();
    processQueue.pop_front();
    processQueue.push_back(p);

    if(processStateMap[p] == processState::runnable ||
       processStateMap[p] == processState::maybeRunnable){

      auto msg = log.makeTextColored(Color::blue, "[%d] chosen to run next.\n");
      log.writeToLog(Importance::info, msg, p);
      return p;
    }
  }

  // Went through all processes and none were ready. This is a dead lock.
  throw runtime_error("dettrace runtime exception: No runnable processes left in scheduler!\n");
}

void scheduler::changeToMaybeRunnable(){
  // No progress was made, if were blocked before, we still are.
  if(! madeProgress){
    return;
  }

  madeProgress = false;

  for(auto curr : processStateMap){
    auto proc = curr.first;
    auto status = curr.second;
    if(status == processState::blocked){
      processStateMap[proc] = processState::maybeRunnable;
    }
  }
  return;
}

void scheduler::printProcesses(){
  for(auto curr : processQueue){
    auto status = processStateMap.at(curr);
    log.writeToLog(Importance::extra, "Pid [%d], Status %s\n", curr,
		   to_string(status).c_str());
  }
  return;
}

string to_string(processState p){
  string str = "uknown";
  switch(p){
  case processState::runnable:
    str = "runnable";
    break;
  case processState::maybeRunnable:
    str = "maybeRunnable";
    break;
  case processState::blocked:
    str = "blocked";
    break;
  case processState::finished:
    str = "finished";
    break;
  }

  return str;
}
