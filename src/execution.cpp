#include "logger.hpp"
#include "valueMapper.hpp"
#include "systemCallList.hpp"
#include "systemCall.hpp"
#include "dettraceSystemCall.hpp"
#include "util.hpp"
#include "state.hpp"
#include "ptracer.hpp"
#include "execution.hpp"

#include <stack>
// =======================================================================================
execution::execution(int debugLevel, pid_t startingPid):
  log {stderr, debugLevel},
  nextPid {startingPid},
  // Waits for first process to be ready! Probably not good to have this kind of
  // dependency of a initialization list?
  tracer{startingPid}{
    // Set state for first process.
    states.emplace(startingPid, state {log, startingPid});

    // First process is special and we must set
    // the options ourselves. Thereafter, ptracer::setOptions will handle this for new
    // processes.
    ptracer::setOptions(startingPid);
  }
// =======================================================================================
void execution::handleExit(){
  log.writeToLog(Importance::inter,
		 logger::makeTextColored(Color::blue, "Process [%d] has finished.\n"),
		 traceesPid);
  if(processHier.empty()){
    // We're done. Exit
    exitLoop = true;
    return;
  }
  // Pop entry from map.
  states.erase(traceesPid);
  // Set next pid to our parent.
  nextPid = processHier.top();
  processHier.pop();

  log.unsetPadding();
  return;
}
// =======================================================================================
void execution::handlePreSystemCall(state& currState){
  currState.syscallStopState = syscallState::post;

  int syscallNum = tracer.getSystemCallNumber();
  currState.systemcall = getSystemCall(syscallNum, systemCallMappings[syscallNum]);

  // No idea what this system call is! error out.
  if(syscallNum > 0 && syscallNum > SYSTEM_CALL_COUNT){
    throw runtime_error("Unkown system call number: " + to_string(syscallNum));
  }

  // Print!
  string systemCall = currState.systemcall->syscallName;
  string redColoredSyscall = logger::makeTextColored(Color::red, systemCall);
  log.writeToLog(Importance::inter,"[Time %d][Pid %d] Intercepted %s (#%d)\n",
		 currState.clock, traceesPid, redColoredSyscall.c_str(), syscallNum);

  // Tick clock once per syscall pre-post pair. Notice we don't tick on every event
  // as signals are asynchronous events.
  currState.clock++;

  log.setPadding();

  currState.doSystemcall = currState.systemcall->handleDetPre(currState, tracer);

  if(systemCall == "fork" || systemCall == "vfork" || systemCall == "clone"){
    int status;
    // This event is known to be either a fork/vfork event or a signal.
    ptraceEvent e = execution::getNextEvent(traceesPid, traceesPid, status);
    handleFork(e);
  }
  return;
}
// =======================================================================================
void execution::handlePostSystemCall(state& currState){
  currState.syscallStopState = syscallState::pre;

  log.writeToLog(Importance::info,"%s value before post-interception: %d\n",
		 currState.systemcall->syscallName.c_str(),
		 tracer.getReturnValue());

  currState.systemcall->handleDetPost(currState, tracer);

  // System call was done in the last iteration.
  log.writeToLog(Importance::info,"%s returned with value: %d\n",
		 currState.systemcall->syscallName.c_str(),
		 tracer.getReturnValue());

  log.unsetPadding();
  return;
}
// =======================================================================================
void execution::handleSystemCall(){
  state& currState = states.at(traceesPid);
  // Update register information. TODO: Right now we update this information on every
  // exit and entrance, as an optimization we might not want to...

  // This is necessary for all "pre system calls" to get the correct sys call number.
  tracer.updateState(traceesPid);


  if(currState.syscallStopState == syscallState::pre){
    handlePreSystemCall(currState);
  }else{
    handlePostSystemCall(currState);
  }

  return;
}
// =======================================================================================
void execution::runProgram(){
  // Iterate over entire process' and all subprocess' execution.
  while(! exitLoop){
    int status;

    ptraceEvent ret = execution::getNextEvent(nextPid, traceesPid, status);
    nextPid = traceesPid;

    // We have never seen this pid before. Add it to our table of states.
    // This might happen even before we get a fork event, as we might get a signal
    // from the child telling us that it has been stopped. These two events are
    // non deterministic.
    if(states.count(traceesPid) == 0){
      log.writeToLog(Importance::info,
		     logger::makeTextColored(Color::blue, "Setting options for: %d\n"),
		     nextPid);
      // First time seeing this process set ptrace options.
      ptracer::setOptions(traceesPid);
      // DO NOT CONTINUE! Fall down to the correct case.
    }

    // Current process is done.
    if(ret == ptraceEvent::exit){
      handleExit();
      continue;
    }

    if(ret == ptraceEvent::syscall){
      handleSystemCall();
      continue;
    }

    // We have encountered a call to fork, vfork, clone.
    if(ret == ptraceEvent::fork || ret == ptraceEvent::vfork){
      // Nothing to do, instead we handle it when we see the system call pre exit.
      // Since this is the easiest time to tell a fork even happened. It's not trivial
      // to check the event as we might get a signal first from the child process.
      // See:
      // https://stackoverflow.com/questions/29997244/
      // occasionally-missing-ptrace-event-vfork-when-running-ptrace
      continue;
    }

    if(ret == ptraceEvent::clone){
      handleClone();
      continue;
    }

    if(ret == ptraceEvent::exec){
      handleExecve();
      continue;
    }

    if(ret == ptraceEvent::signal){
      handleSignal(status);
      continue;
    }

    throw runtime_error(to_string(traceesPid) +
			"Uknown return value for ptracer::getNextEvent()\n");
  }
}
// =======================================================================================
void execution::handleFork(ptraceEvent event){
  pid_t newChildPid;

  if(event == ptraceEvent::fork || event == ptraceEvent::vfork){
    // Fork event came first.
    newChildPid = handleForkEvent();

    // Wait for child to be ready.
    log.writeToLog(Importance::info,
		   logger::makeTextColored(Color::blue,
		     "Waiting for child to be ready for tracing...\n"));
    int status;

    int retPid = waitpid(newChildPid, &status, 0);
    if(retPid == -1){
      throw runtime_error("waitpid failed:" + string { strerror(errno) });
    }

    // This should never happen.
    if(retPid != newChildPid){
      throw runtime_error("wait call return pid does not match new child's pid.");
    }
    log.writeToLog(Importance::info,
		   logger::makeTextColored(Color::blue, "Child ready: %d\n"),
		   retPid);
  }else{
    if(event != ptraceEvent::signal){
      throw runtime_error("Expected signal after fork/vfork event!");
    }
    // Signal event came first.
    handleForkSignal();
    newChildPid = handleForkEvent();
  }

  // Set child to run as next event.
  nextPid = newChildPid;
}
// =======================================================================================
pid_t execution::handleForkEvent(){
  log.writeToLog(Importance::inter,
		 logger::makeTextColored(Color::blue,
		   "[%d] Fork event came before signal!\n"),
		 traceesPid);
  // Current scheduling policy: Let child run to completion.
  pid_t newChildPid = tracer.getEventMessage();
  pid_t parentsPid = traceesPid;
  // Push parent id to process stack.
  processHier.push(parentsPid);

  // Add this new process to our states.
  log.writeToLog(Importance::info,
 		 logger::makeTextColored(Color::blue,"Added process [%d] to states map.\n"),
		 newChildPid);
  states.emplace(newChildPid, state {log, newChildPid} );

  return newChildPid;
}
// =======================================================================================
void execution::handleForkSignal(){
  log.writeToLog(Importance::info,
		 logger::makeTextColored(Color::blue,
                   "[%d] Child fork signal-stop came before fork event.\n"),
		 traceesPid);
  int status;
  // Intercept any system call.
  // This should really be the parents pid. which we don't have readily avaliable.
  traceesPid = waitpid(-1, &status, 0);
  if(traceesPid == -1){
    throw runtime_error("waitpid failed:" + string { strerror(errno) });
  }

  if(! ptracer::isPtraceEvent(status, PTRACE_EVENT_FORK) &&
     ! ptracer::isPtraceEvent(status, PTRACE_EVENT_VFORK)){
    throw runtime_error("Expected fork or vfork event!\n");
  }
  return;
}
// =======================================================================================
void execution::handleClone(){
  // Nothing to do for now...
  log.writeToLog(Importance::inter,
		 logger::makeTextColored(Color::blue, "[%d] caught clone event!\n"),
		 traceesPid);
  return;
}
// =======================================================================================
void execution::handleExecve(){
  // Nothing to do for now... New process is already automatically ptraced by
  // our tracer.
  log.writeToLog(Importance::inter,
		 logger::makeTextColored(Color::blue, "[%d] Caught execve!\n"),
		 traceesPid);
  return;
}
// =======================================================================================
void execution::handleSignal(int status){
  // Nothing for now. Kelly's code will go here.
  log.writeToLog(Importance::inter,
		 logger::makeTextColored(Color::blue, "[%d] tracer: Received signal: %d\n"),
		 traceesPid, WSTOPSIG(status));
  return;
}
// =======================================================================================
unique_ptr<systemCall>
execution::getSystemCall(int syscallNumber, string syscallName){
    switch(syscallNumber){
    case SYS_access:
      return make_unique<accessSystemCall>(syscallNumber, syscallName);
    case SYS_arch_prctl:
      return make_unique<arch_prctlSystemCall>(syscallNumber, syscallName);
    case SYS_brk:
      return make_unique<brkSystemCall>(syscallNumber, syscallName);
    case SYS_chmod:
      return make_unique<chmodSystemCall>(syscallNumber, syscallName);
    case SYS_clone:
      return make_unique<cloneSystemCall>(syscallNumber, syscallName);
    case SYS_close:
      return make_unique<closeSystemCall>(syscallNumber, syscallName);
    case SYS_connect:
      return make_unique<connectSystemCall>(syscallNumber, syscallName);
    case SYS_dup:
      return make_unique<dupSystemCall>(syscallNumber, syscallName);
    case SYS_dup2:
      return make_unique<dup2SystemCall>(syscallNumber, syscallName);
    case SYS_execve:
      return make_unique<execveSystemCall>(syscallNumber, syscallName);
    case SYS_exit_group:
      return make_unique<exit_groupSystemCall>(syscallNumber, syscallName);
    case SYS_fcntl:
      return make_unique<fcntlSystemCall>(syscallNumber, syscallName);
    case SYS_fstat:
      return make_unique<fstatSystemCall>(syscallNumber, syscallName);
    case SYS_fstatfs:
      return make_unique<fstatfsSystemCall>(syscallNumber, syscallName);
    case SYS_futex:
      return make_unique<futexSystemCall>(syscallNumber, syscallName);
    case SYS_getcwd:
      return make_unique<getcwdSystemCall>(syscallNumber, syscallName);
    case SYS_getdents:
      return make_unique<getdentsSystemCall>(syscallNumber, syscallName);
    case SYS_getpid:
      return make_unique<getpidSystemCall>(syscallNumber, syscallName);
    case SYS_getppid:
      return make_unique<getppidSystemCall>(syscallNumber, syscallName);
    case SYS_getrlimit:
      return make_unique<getrlimitSystemCall>(syscallNumber, syscallName);
    case SYS_getrusage:
      return make_unique<getrusageSystemCall>(syscallNumber, syscallName);
    case SYS_getuid:
      return make_unique<getuidSystemCall>(syscallNumber, syscallName);
    case SYS_getxattr:
      return make_unique<getxattrSystemCall>(syscallNumber, syscallName);
    case SYS_ioctl:
      return make_unique<ioctlSystemCall>(syscallNumber, syscallName);
    case SYS_lgetxattr:
      return make_unique<lgetxattrSystemCall>(syscallNumber, syscallName);
    case SYS_munmap:
      return make_unique<munmapSystemCall>(syscallNumber, syscallName);
    case SYS_mmap:
      return make_unique<mmapSystemCall>(syscallNumber, syscallName);
    case SYS_mprotect:
      return make_unique<mprotectSystemCall>(syscallNumber, syscallName);
    case SYS_nanosleep:
      return make_unique<nanosleepSystemCall>(syscallNumber, syscallName);
    case SYS_lseek:
      return make_unique<lseekSystemCall>(syscallNumber, syscallName);
    case SYS_lstat:
      return make_unique<lstatSystemCall>(syscallNumber, syscallName);
    case SYS_open:
      return make_unique<openSystemCall>(syscallNumber, syscallName);
    case SYS_openat:
      return make_unique<openatSystemCall>(syscallNumber, syscallName);
    case SYS_poll:
      return make_unique<pollSystemCall>(syscallNumber, syscallName);
    case SYS_prlimit64:
      return make_unique<prlimit64SystemCall>(syscallNumber, syscallName);
    case SYS_read:
      return make_unique<readSystemCall>(syscallNumber, syscallName);
    case SYS_readlink:
      return make_unique<readlinkSystemCall>(syscallNumber, syscallName);
    case SYS_readv:
      return make_unique<readvSystemCall>(syscallNumber, syscallName);
    case SYS_recvmsg:
      return make_unique<recvmsgSystemCall>(syscallNumber, syscallName);
    case SYS_rt_sigprocmask:
      return make_unique<rt_sigprocmaskSystemCall>(syscallNumber, syscallName);
    case SYS_rt_sigaction:
      return make_unique<rt_sigactionSystemCall>(syscallNumber, syscallName);
    case SYS_sendto:
      return make_unique<sendtoSystemCall>(syscallNumber, syscallName);
    case SYS_set_robust_list:
      return make_unique<set_robust_listSystemCall>(syscallNumber, syscallName);
    case SYS_set_tid_address:
      return make_unique<set_tid_addressSystemCall>(syscallNumber, syscallName);
    case SYS_sigaltstack:
      return make_unique<sigaltstackSystemCall>(syscallNumber, syscallName);
    case SYS_socket:
      return make_unique<socketSystemCall>(syscallNumber, syscallName);
    case SYS_statfs:
      return make_unique<statfsSystemCall>(syscallNumber, syscallName);
    case SYS_stat:
      return make_unique<statSystemCall>(syscallNumber, syscallName);
    case SYS_sysinfo:
      return make_unique<sysinfoSystemCall>(syscallNumber, syscallName);
    case SYS_time:
      return make_unique<timeSystemCall>(syscallNumber, syscallName);
    case SYS_umask:
      return make_unique<umaskSystemCall>(syscallNumber, syscallName);
    case SYS_uname:
      return make_unique<unameSystemCall>(syscallNumber, syscallName);
    case SYS_unlink:
      return make_unique<unlinkSystemCall>(syscallNumber, syscallName);
    case SYS_utimensat:
      return make_unique<utimensatSystemCall>(syscallNumber, syscallName);
    case SYS_vfork:
      return make_unique<vforkSystemCall>(syscallNumber, syscallName);
    case SYS_wait4:
      return make_unique<wait4SystemCall>(syscallNumber, syscallName);
    case SYS_write:
      return make_unique<writeSystemCall>(syscallNumber, syscallName);
    }

    // Generic system call. Throws error.
    return make_unique<systemCall>(syscallNumber, syscallName);
  }
// =======================================================================================
ptraceEvent execution::getNextEvent(pid_t currentPid, pid_t& traceesPid, int& status){
  // Tell the process that we just intercepted an event for to continue, with us tracking
  // it's system calls. If this is the first time this function is called, it will be the
  // starting process. Which we expect to be in a waiting state.
  ptracer::doPtrace(PTRACE_SYSCALL, currentPid, 0, 0);

  // Intercept any system call.
  traceesPid = waitpid(-1, &status, 0);
  if(traceesPid == -1){
    throw runtime_error("waitpid failed:" + string { strerror(errno) });
  }

  // Check if tracee has exited.
  if (WIFEXITED(status)){
    return ptraceEvent::exit;
  }

  // Condition for PTRACE_O_TRACEEXEC
  if( ptracer::isPtraceEvent(status, PTRACE_EVENT_EXEC) ){
    return ptraceEvent::exec;
  }

  // Condition for PTRACE_O_TRACECLONE
  if( ptracer::isPtraceEvent(status, PTRACE_EVENT_CLONE) ){
    return ptraceEvent::clone;
  }

  // Condition for PTRACE_O_TRACEVFORK
  if( ptracer::isPtraceEvent(status, PTRACE_EVENT_VFORK) ){
    return ptraceEvent::vfork;
  }

  // Even though fork() is clone under the hood, any time that clone is used with
  // SIGCHLD, ptrace calls that event a fork *sigh*.
  // Also requires PTRACE_O_FORK flag.
  if( ptracer::isPtraceEvent(status, PTRACE_EVENT_FORK) ){
    return ptraceEvent::fork;
  }

  // This is a stop caused by a system call exit-pre/exit-post.
  // Check if WIFSTOPPED return true,
  // if yes, compare signal number to SIGTRAP | 0x80 (see ptrace(2)).
  if(WIFSTOPPED(status) && (WSTOPSIG(status) == (SIGTRAP | 0x80)) ){
    return ptraceEvent::syscall;
  }

  if(WIFSTOPPED(status)){
    return ptraceEvent::signal;
  }

  throw runtime_error("Uknown event on dettrace::getNextEvent()");
}
// =======================================================================================
