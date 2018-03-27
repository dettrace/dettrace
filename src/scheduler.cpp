#include "logger.hpp"
#include "systemCallList.hpp"
#include "systemCall.hpp"
#include "dettraceSystemCall.hpp"
#include "util.hpp"
#include "state.hpp"
#include "ptracer.hpp"
#include "scheduler.hpp"

#include <deque>
#include <optional>

process::process(pid_t pid):
  pid(pid){
}


scheduler::scheduler(pid_t startingPid, logger& log):
  log(log),
  nextPid(startingPid){
  processQueue.push_front(process {startingPid});
}

pid_t scheduler::getNext(){
  return nextPid;
}


void scheduler::preemptAndScheduleNext(pid_t process){
  auto msg = logger::makeTextColored(Color::blue, "Preempting process: %d\n");
  log.writeToLog(Importance::info, msg, process);

  for(auto currProcess : processQueue){
    // Make sure not to include ourselves.
    if(currProcess.pid != process){
      nextPid = currProcess.pid;

      auto msg = logger::makeTextColored(Color::blue, "%d chosen to run next.\n");
      log.writeToLog(Importance::info, msg, nextPid);
      return;
    }
  }
  throw runtime_error("No runnable processes left in scheduler!\n");
}


void scheduler::addAndScheduleNext(pid_t newProcess){
  // logging :O
  auto msg = logger::makeTextColored(Color::blue, "New process added to scheduler: %d\n");
  log.writeToLog(Importance::info, msg, newProcess);
  msg = logger::makeTextColored(Color::blue, "%d scheduled as next.\n");
  log.writeToLog(Importance::info, msg, newProcess);


  processQueue.push_front(process {newProcess});
  nextPid = newProcess;
  return;
}

bool scheduler::removeAndScheduleNext(pid_t terminatedProcess){
  auto msg =
    logger::makeTextColored(Color::blue,"Removing process from scheduler: %d\n");
  log.writeToLog(Importance::info, msg, terminatedProcess);


  // After loop, i will hold index of process to delete from deque.
  size_t indexOfProc = 0;
  // Find index of our process based on their pid.
  for(auto currProcess : processQueue){
    if(currProcess.pid == terminatedProcess){
      break;
    }
    indexOfProc++;
  }

  if(indexOfProc == processQueue.size()){
    auto err = "scheduler::removeAndSchedulNext:"
      " No such element to delete from scheduler.";
    throw runtime_error(err);
  }


  msg = logger::makeTextColored(Color::blue, "Process found at index %d. Deleting...\n");
  log.writeToLog(Importance::info, msg, indexOfProc);


  processQueue.erase(processQueue.begin() + indexOfProc);
  if(processQueue.empty()){
    return true;
  }else{
    nextPid = processQueue.front().pid;


    msg = logger::makeTextColored(Color::blue, "Next process scheduled: %d\n");
    log.writeToLog(Importance::info, msg, nextPid);

    return false;
  }

}
