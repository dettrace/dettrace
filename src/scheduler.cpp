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
    throw runtime_error("scheduleThisProcess: Parent : " + to_string(parent) +
                        " was not marked as finished!");
  }

  auto msg = logger::makeTextColored(Color::blue, "Parent %d scheduled for exit.\n");
  log.writeToLog(Importance::info, msg, parent);

  remove(terminatedProcess);
  nextPid = parent;
}

bool scheduler::isFinished(pid_t process){
  return processStateMap[process] == processState::finished;
}



void scheduler::markFinishedAndScheduleNext(pid_t process){
  auto msg = logger::makeTextColored(Color::blue, "Process %d marked as finished!\n");
  log.writeToLog(Importance::info, msg , process);

  if(madeProgress){
    madeProgress = false;
    toMaybeProgress();
  }

  processStateMap[process] = processState::finished;
  nextPid = scheduleNextProcess(process);
}

void scheduler::reportProgress(pid_t process){
  auto msg = logger::makeTextColored(Color::blue, "Process %d made progress!\n");
  log.writeToLog(Importance::info, msg , process);
  madeProgress = true;
}

void scheduler::preemptAndScheduleNext(pid_t process){
  auto msg = logger::makeTextColored(Color::blue, "Preempting process: %d\n");
  log.writeToLog(Importance::info, msg, process);

  if(madeProgress){
    madeProgress = false;
    toMaybeProgress();
  }

  // We're now blocked.
  processStateMap[process] = processState::blocked;
  nextPid = scheduleNextProcess(process);
}


void scheduler::addAndScheduleNext(pid_t newProcess){
  // logging :O
  auto msg = logger::makeTextColored(Color::blue, "New process added to scheduler: %d\n");
  log.writeToLog(Importance::info, msg, newProcess);
  msg = logger::makeTextColored(Color::blue, "%d scheduled as next.\n");
  log.writeToLog(Importance::info, msg, newProcess);

  // New process always capable of running, and should!
  processQueue.push_front(newProcess);
  processStateMap[newProcess] = processState::runnable;
  nextPid = newProcess;
  return;
}

void scheduler::remove(pid_t terminatedProcess){
 auto msg =
    logger::makeTextColored(Color::blue,"Removing process from scheduler: %d\n");
  log.writeToLog(Importance::info, msg, terminatedProcess);

  deleteProcess(terminatedProcess);
}

bool scheduler::removeAndScheduleNext(pid_t terminatedProcess){
  if(madeProgress){
    madeProgress = false;
    toMaybeProgress();
  }

  remove(terminatedProcess);

  if(processQueue.empty()){
    return true;
  }else{
    nextPid = scheduleNextProcess(terminatedProcess);

    auto msg = logger::makeTextColored(Color::blue, "Next process scheduled: %d\n");
    log.writeToLog(Importance::info, msg, nextPid);

    return false;
  }

}

void scheduler::deleteProcess(pid_t terminatedProcess){
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
    auto err = "scheduler::removeAndSchedulNext:"
      " No such element to delete from scheduler.";
    throw runtime_error(err);
  }

  auto msg = logger::makeTextColored(Color::blue, "Process found at index %d. Deleting...\n");
  log.writeToLog(Importance::info, msg, indexOfProc);

  processQueue.erase(processQueue.begin() + indexOfProc);
  processStateMap.erase(terminatedProcess);
  return;
}

pid_t scheduler::scheduleNextProcess(pid_t currentProcess){
  for(auto currProcess : processQueue){
    // Make sure not to include ourselves.
    if(currProcess != currentProcess &&
       // Make sure we don't pick blocked or finished.
       (processStateMap[currProcess] == processState::runnable ||
       processStateMap[currProcess] == processState::maybeRunnable)){
      auto msg = logger::makeTextColored(Color::blue, "%d chosen to run next.\n");
      log.writeToLog(Importance::info, msg, currProcess);
      return currProcess;
    }
  }

  throw runtime_error("No runnable processes left in scheduler!\n");
}

void scheduler::toMaybeProgress(){
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
  for(auto curr : processStateMap){
    auto proc = curr.first;
    auto status = curr.second;
    log.writeToLog(Importance::info, "Pid %d, Status %s\n", proc,
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
