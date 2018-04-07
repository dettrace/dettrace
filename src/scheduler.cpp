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

void scheduler::reportProgress(pid_t process){
  auto msg = logger::makeTextColored(Color::blue, "Process %d made progress!\n");
  log.writeToLog(Importance::extra, msg , process);
  processStateMap[process] = processState::runnable;
}

void scheduler::preemptAndScheduleNext(pid_t process){
  auto msg = logger::makeTextColored(Color::blue, "Preempting process: %d\n");
  log.writeToLog(Importance::info, msg, process);

  // This process was runnable and eventually preempted due to a blocking system call.
  // This is progress!
  if(processStateMap[process] == processState::runnable){
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

bool scheduler::removeAndScheduleNext(pid_t terminatedProcess){
  auto msg =
    logger::makeTextColored(Color::blue,"Removing process from scheduler: %d\n");
  log.writeToLog(Importance::info, msg, terminatedProcess);

  deleteProcess(terminatedProcess);

  // Progress was made.
  // Update all our other process' status from blocked to maybeRunnable.
  toMaybeProgress();

  if(processQueue.empty()){
    return true;
  }else{
    nextPid = scheduleNextProcess(terminatedProcess);

    msg = logger::makeTextColored(Color::blue, "Next process scheduled: %d\n");
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
       processStateMap[currProcess] != processState::blocked){
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
    log.writeToLog(Importance::extra, "Pid %d, Status %s\n", proc,
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
  }

  return str;
}
