#include "logger.hpp"
#include "systemCallList.hpp"
#include "systemCall.hpp"
#include "dettraceSystemCall.hpp"
#include "util.hpp"
#include "state.hpp"
#include "ptracer.hpp"
#include "execution.hpp"
#include "scheduler.hpp"

#include <stack>


pid_t eraseChildEntry(multimap<pid_t, pid_t>& map, pid_t process);
// =======================================================================================
execution::execution(int debugLevel, pid_t startingPid, bool useColor, bool oldKernel):
  oldKernel {oldKernel},
  log {stderr, debugLevel, useColor},
  silentLogger {stderr, 0},
  // Waits for first process to be ready!
  tracer{startingPid},
  // Create our global state once, share across class.
  myGlobalState{
    log,
    ValueMapper<ino_t, ino_t> {log, "inode map", 1},
    ValueMapper<ino_t, time_t> {log, "mtime map", 1}
  },
  pidMap {silentLogger, "pid map", 1},
  myScheduler {startingPid, log, pidMap},
  debugLevel {debugLevel}{
    // Set state for first process.
    pidMap.addRealValue(startingPid);
    states.emplace(startingPid, state {startingPid, debugLevel});

    // First process is special and we must set the options ourselves.
    // This is done everytime a new process is spawned.
    ptracer::setOptions(startingPid);
  }
// =======================================================================================
// We only call this function on a ptrace::nonEventExit. We only receive this event once
// all the process' children have finished.
bool execution::handleExit(const pid_t traceesPid){
  auto msg = log.makeTextColored(Color::blue, "Process [%d] has completely  finished."
                                     " (ptrace nonEventExit).\n");
  log.writeToLog(Importance::inter, msg, pidMap.getVirtualValue(traceesPid));

  // We are done. Erase ourselves from our parent's list of children.
  pid_t parent = eraseChildEntry(processTree, traceesPid);

  if(parent != -1                   &&       // We have no parent, we're root.
     myScheduler.isFinished(parent) &&       // Check if our parent is marked as finished.
     processTree.count(parent) == 0){        // Parent has no children left.

    myScheduler.removeAndScheduleParent(traceesPid, parent);
    return false;
  }
  // Generic case, should happen most of the time.
  else{
    // Process done, schedule next process to run.
    bool empty = myScheduler.removeAndScheduleNext(traceesPid);
    if(empty){
      // All processes have finished! We're done
      return true;
    }
    log.unsetPadding();
    return false;
  }
}
// =======================================================================================
// Despite what the name will imply, this function is actually called during a
// ptrace seccomp event. Not a pre-system call event. In newer kernel version there is no
// need to deal with ptrace pre system call events. So the only reason we refer to it here
// is for backward compatibility reasons.
bool execution::handlePreSystemCall(state& currState, const pid_t traceesPid){
  int syscallNum = tracer.getSystemCallNumber();
  currState.systemcall = getSystemCall(syscallNum, systemCallMappings[syscallNum]);

  if(syscallNum < 0 || syscallNum > SYSTEM_CALL_COUNT){
    throw runtime_error("Unkown system call number: " + to_string(syscallNum));
  }

  // Print!
  string systemCall = currState.systemcall->syscallName;
  string redColoredSyscall = log.makeTextColored(Color::red, systemCall);
  auto virtualPid = pidMap.getVirtualValue(traceesPid);
  log.writeToLog(Importance::inter,"[Pid %d] Intercepted %s\n", virtualPid,
                 redColoredSyscall.c_str());
  log.setPadding();

  bool callPostHook =
    currState.systemcall->handleDetPre(myGlobalState, currState, tracer, myScheduler);

  if(oldKernel){
    // Next event will be a sytem call pre-exit event as older kernels make us catch the
    // seccomp event and the ptrace pre-system call event.
    currState.onPreExitEvent = true;
  }

  // This is the easiest time to tell a fork even happened. It's not trivial
  // to check the event as we might get a signal first from the child process.
  // See:
  // https://stackoverflow.com/questions/29997244/
  // occasionally-missing-ptrace-event-vfork-when-running-ptrace
  if(systemCall == "fork" || systemCall == "vfork" || systemCall == "clone"){
    int status;
    ptraceEvent e;
    pid_t newPid;

    if(oldKernel){
      // fork/vfork/clone pre system call.
      // On older version of the kernel, we would need to catch the pre-system call
      // event to forking system calls. This is event needs to be taken off the ptrace
      // queue so we do that here and simply ignore the event.
      tie(e, newPid, status) = getNextEvent(traceesPid, true);
      if(e != ptraceEvent::syscall){
        throw runtime_error("Expected pre-system call event after fork.");
      }
      // That was the pre-exit event, make sure we set onPreExitEvent to false.
      currState.onPreExitEvent = false;
    }

    // This event is known to be either a clone/fork/vfork event or a signal. We check
    // this in handleFork.
    tie(e, newPid, status) = getNextEvent(traceesPid, false);
    handleFork(e, newPid);

    // This was a fork, vfork, or clone. No need to go into the post-interception hook.
    return false;
  }

  if(oldKernel){
    // This is the seccomp event where we do the work for the pre-system call hook.
    // In older versions of seccomp, we must also do the pre-exit ptrace event, as we
    // have to. This is dictated by this variable.
    return true;
  }

  // If debugging we let system call go to post hook so we can see return values.
  // Notice we must still return false in the fork case. So we should not move this
  // expression "higher up" in the call chain.
  return debugLevel >= 4 ? true : callPostHook;
}
// =======================================================================================
void execution::handlePostSystemCall(state& currState){
  // Sometimes, we change the system call midway. That is, at the prehook of a system call
  // we insert a new system call. So we must fetch the system call object again.
  int syscallNum = tracer.getSystemCallNumber();
  currState.systemcall = getSystemCall(syscallNum, systemCallMappings[syscallNum]);

  // No idea what this system call is! error out.
  if(syscallNum < 0 || syscallNum > SYSTEM_CALL_COUNT){
    throw runtime_error("Unkown system call number: " + to_string(syscallNum));
  }

  log.writeToLog(Importance::info,"%s value before post-hook: %d\n",
                 currState.systemcall->syscallName.c_str(),
                 tracer.getReturnValue());

  currState.systemcall->
    handleDetPost(myGlobalState, currState, tracer, myScheduler);

  log.writeToLog(Importance::info,"%s returned with value: %d\n",
                 currState.systemcall->syscallName.c_str(),
                 tracer.getReturnValue());

  log.unsetPadding();
  return;
}
// =======================================================================================
void execution::runProgram(){
  // When using seccomp, we run with PTRACE_CONT, but seccomp only reports pre-hook
  // events. To get post hook events we must call ptrace with PTRACE_SYSCALL intead.
  // This happens in @getNextEvent.

  // Whether we will skip to the next system call or get a ptrace event at the post hook.
  // This is set by the return value of a pre-hook function call.
  bool callPostHook = false;

  // Once all process' have ended. We exit.
  bool exitLoop = false;

  // Iterate over entire process' and all subprocess' execution.
  while(! exitLoop){
    int status;
    pid_t traceesPid;
    ptraceEvent ret;
    tie(ret, traceesPid, status) = getNextEvent(myScheduler.getNext(), callPostHook);
    auto virtualPid = pidMap.getVirtualValue(traceesPid);

    // Most common event. We handle the pre-hook for system calls here.
    if(ret == ptraceEvent::seccomp){
      callPostHook = handleSeccomp(traceesPid);
      continue;
    }

    // We still need this case even though we use seccomp + bpf. Since we do post-hook
    // interception of system calls through PTRACE_SYSCALL. Only post system call
    // events come here.
    if(ret == ptraceEvent::syscall){
      // For older kernels, we see a system call event and we also see a handle seccomp
      // event. I chose to always handle the pre-system call on the ptracer seccomp event.
      // So we skip the pre-system call event here on older kernels.
      state& currentState = states.at(traceesPid);

      // old-kernel-only ptrace system call event for pre exit hook.
      if(oldKernel && currentState.onPreExitEvent){
          callPostHook = true;
          currentState.onPreExitEvent = false;
      }else{
        tracer.updateState(traceesPid);
        handlePostSystemCall( currentState );
        // set callPostHook to default value for next iteration.
        callPostHook = false;
      }

      continue;
    }

    // Current process was ended by signal.
    if(ret == ptraceEvent::terminatedBySignal){
      // TODO: A Process terminated by signal might break some of the assumptions I make
      // in handleExit (see function definition above) so we do not support it for now.
      // throw runtime_error("Process terminated by signal. We currently do not support this.");
      auto msg =
        log.makeTextColored(Color::blue, "Process [%d] ended by signal %d.\n");
      log.writeToLog(Importance::inter, msg, virtualPid, WTERMSIG(status));
      exitLoop = handleExit(traceesPid);
      continue;
    }

    /**
       A process needs to do two things before dying:
       1) eventExit through ptrace. This process is not truly done, it is stopped
       until we let it continue and all it's children have also finished.
       2) A nonEventExit at this point the process is done and can no longer be
       peeked or poked.

       If the process has remaining children, we will get an eventExit but the
       nonEventExit will never arrive. Therefore we set process as exited.
       Only when all children have exited do we get a the nonEvent exit.

       Therefore we keep track of the process hierarchy and only wait for the
       evenExit when our children have exited.
    */
    if(ret == ptraceEvent::eventExit){
      auto msg = log.makeTextColored(Color::blue, "Process [%d] has finished. "
                                         "With ptrace exit event.\n");
      log.writeToLog(Importance::inter, msg, virtualPid);
      callPostHook = false;

      // We get only get an exit if we made progress, report this. This covers the case
      // where we had no blocking system calls in our execution path.
      myScheduler.reportProgress(traceesPid);

      // We have children still, we cannot exit.
      if(processTree.count(traceesPid) != 0){
        myScheduler.markFinishedAndScheduleNext(traceesPid);
      }
      continue;
    }

    // Current process is finally truly done (unlike eventExit).
    if(ret == ptraceEvent::nonEventExit){
      callPostHook = false;
      exitLoop = handleExit(traceesPid);
      continue;
    }

    // We have encountered a call to fork, vfork, clone.
    if(ret == ptraceEvent::fork){
      // Nothing to do, instead we handle it when we see the system call pre exit.
      // Since this is the easiest time to tell a fork even happened. It's not trivial
      // to check the event as we might get a signal first from the child process.
      // See:
      // https://stackoverflow.com/questions/29997244/
      // occasionally-missing-ptrace-event-vfork-when-running-ptrace
      continue;
    }

    if(ret == ptraceEvent::clone){
      log.writeToLog(Importance::inter,
                     log.makeTextColored(Color::blue, "[%d] caught clone event!\n"),
                     pidMap.getVirtualValue(traceesPid));
      continue;
    }

    if(ret == ptraceEvent::exec){
      log.writeToLog(Importance::inter,
                     log.makeTextColored(Color::blue, "[%d] Caught execve event!\n"),
                     pidMap.getVirtualValue(traceesPid));
      continue;
    }

    if(ret == ptraceEvent::signal){
      int signalNum = WSTOPSIG(status);
      handleSignal(signalNum, traceesPid);
      myScheduler.reportProgress(traceesPid);
      continue;
    }

    throw runtime_error(to_string(traceesPid) +
                        " Uknown return value for ptracer::getNextEvent()\n");
  }

  auto msg =
    log.makeTextColored(Color::blue, "All processes done. Finished successfully!\n");
  log.writeToLog(Importance::info, msg);
}
// =======================================================================================
void execution::handleFork(ptraceEvent event, const pid_t traceesPid){
  // Notice in both cases, we catch one of the two events and ignore the other.
  if(event == ptraceEvent::fork || event == ptraceEvent::vfork ||
     event == ptraceEvent::clone){
    // Fork event came first.
    handleForkEvent(traceesPid);

    // Wait for child to be ready.
    log.writeToLog(Importance::info, log.makeTextColored(Color::blue,
                   "Waiting for child to be ready for tracing...\n"));
    int status;
    int newChildPid = myScheduler.getNext();
    int retPid = doWithCheck(waitpid(-1, &status, 0), "waitpid");

    // This should never happen.
    if(retPid != newChildPid){
      throw runtime_error("wait call return pid does not match new child's pid.");
    }
    log.writeToLog(Importance::info,
                   log.makeTextColored(Color::blue, "Child ready!\n"));
  }else{
    if(event != ptraceEvent::signal){
      throw runtime_error("Expected signal after fork/vfork event!");
    }
    // Signal event came first.
    handleForkSignal(traceesPid);
    handleForkEvent(traceesPid);
  }

  return;
}
// =======================================================================================
pid_t execution::handleForkEvent(const pid_t traceesPid){
  log.writeToLog(Importance::inter, log.makeTextColored(Color::blue,
                 "Fork event came before signal!\n"));

  pid_t newChildPid = tracer.getEventMessage();

  // Add this new process to our states.
  auto virtualPid = pidMap.addRealValue(newChildPid);
  states.emplace(newChildPid, state {newChildPid, debugLevel} );
  log.writeToLog(Importance::info,
                 log.makeTextColored(Color::blue,"Added process [%d] to states map.\n"),
                 virtualPid);

  // Tracee just had a child! It's a parent!
  myScheduler.addAndScheduleNext(newChildPid);

  // This is where we add new children to our process tree.
  auto pair = make_pair(traceesPid, newChildPid);
  processTree.insert(pair);

  return newChildPid;
}
// =======================================================================================
void execution::handleForkSignal(const pid_t traceesPid){
  log.writeToLog(Importance::info, log.makeTextColored(Color::blue,
                 "Child fork signal-stop came before fork event.\n"));

  int status;
  // Intercept any system call.
  // This should really be the parents pid. which we don't have readily avaliable.
  doWithCheck(waitpid(-1, &status, 0), "waitpid");

  if(! ptracer::isPtraceEvent(status, PTRACE_EVENT_FORK) &&
     ! ptracer::isPtraceEvent(status, PTRACE_EVENT_VFORK)){
    throw runtime_error("Expected fork or vfork event!\n");
  }
  return;
}
// =======================================================================================
bool execution::handleSeccomp(const pid_t traceesPid){
  long syscallNum;
  ptracer::doPtrace(PTRACE_GETEVENTMSG, traceesPid, nullptr, &syscallNum);

  // INT16_MAX is sent by seccomp by convention as for system calls with no rules.
  if(syscallNum == INT16_MAX){
    // Fetch real system call from register.
    tracer.updateState(traceesPid);
    syscallNum = tracer.getSystemCallNumber();
    throw runtime_error("No filter rule for system call: " +
                        systemCallMappings[syscallNum]);
  }

  // TODO: Right now we update this information on every exit and entrance, as a
  // small optimization we might not want to...
  // Get registers from tracee.
  tracer.updateState(traceesPid);

  // ensure mapping exists
  // we need to update the tracrer since mappedMemory::ensureExistanceOfMapping checks intercepted call
  states.at(traceesPid).mmapMemory.ensureExistanceOfMapping(myGlobalState, states.at(traceesPid), tracer);

  auto callPostHook = handlePreSystemCall( states.at(traceesPid), traceesPid );
  return callPostHook;
}
// =======================================================================================
void execution::handleSignal(int sigNum, const pid_t traceesPid){
  if(sigNum == SIGALRM){
    throw runtime_error("SIGALRM found, currently not supported.");
  }
  // Remember to deliver this signal to the tracee for next event! Happens in
  // getNextEvent.
  states.at(traceesPid).signalToDeliver = sigNum;
  auto msg = "[%d] Tracer: Received signal: %d. Forwading signal to tracee.\n";
  auto coloredMsg = log.makeTextColored(Color::blue, msg);
  auto virtualPid = pidMap.getVirtualValue(traceesPid);
  log.writeToLog(Importance::inter, coloredMsg, virtualPid, sigNum);
  return;
}
// =======================================================================================
unique_ptr<systemCall>
execution::getSystemCall(int syscallNumber, string syscallName){
  switch(syscallNumber){
  case SYS_access:
    return make_unique<accessSystemCall>(syscallNumber, syscallName);
  case SYS_alarm:
    return make_unique<alarmSystemCall>(syscallNumber, syscallName);
  case SYS_chdir:
    return make_unique<chdirSystemCall>(syscallNumber, syscallName);
  case SYS_chown:
    return make_unique<chownSystemCall>(syscallNumber, syscallName);
  case SYS_chmod:
    return make_unique<chmodSystemCall>(syscallNumber, syscallName);
  case SYS_clock_gettime:
    return make_unique<clock_gettimeSystemCall>(syscallNumber, syscallName);
  case SYS_close:
    return make_unique<closeSystemCall>(syscallNumber, syscallName);
  case SYS_clone:
    return make_unique<cloneSystemCall>(syscallNumber, syscallName);
  case SYS_connect:
    return make_unique<connectSystemCall>(syscallNumber, syscallName);
  case SYS_creat:
    return make_unique<creatSystemCall>(syscallNumber, syscallName);
  case SYS_execve:
    return make_unique<execveSystemCall>(syscallNumber, syscallName);
  case SYS_faccessat:
    return make_unique<faccessatSystemCall>(syscallNumber, syscallName);
  case SYS_fgetxattr:
    return make_unique<fgetxattrSystemCall>(syscallNumber, syscallName);
  case SYS_flistxattr:
    return make_unique<flistxattrSystemCall>(syscallNumber, syscallName);
  case SYS_fchownat:
    return make_unique<fchownatSystemCall>(syscallNumber, syscallName);
  case SYS_fstat:
    return make_unique<fstatSystemCall>(syscallNumber, syscallName);
  case SYS_newfstatat:
    return make_unique<newfstatatSystemCall>(syscallNumber, syscallName);
  case SYS_fstatfs:
    return make_unique<fstatfsSystemCall>(syscallNumber, syscallName);
  case SYS_futex:
    return make_unique<futexSystemCall>(syscallNumber, syscallName);
  case SYS_getcwd:
    return make_unique<getcwdSystemCall>(syscallNumber, syscallName);
  case SYS_getdents:
    return make_unique<getdentsSystemCall>(syscallNumber, syscallName);
  case SYS_getdents64:
    return make_unique<getdents64SystemCall>(syscallNumber, syscallName);
  case SYS_getpeername:
    return make_unique<getpeernameSystemCall>(syscallNumber, syscallName);
    // Some older systems do not have this  system call.
#ifdef SYS_getrandom
  case SYS_getrandom:
    return make_unique<getrandomSystemCall>(syscallNumber, syscallName);
#endif
  case SYS_getrlimit:
    return make_unique<getrlimitSystemCall>(syscallNumber, syscallName);
  case SYS_getrusage:
    return make_unique<getrusageSystemCall>(syscallNumber, syscallName);
  case SYS_gettimeofday:
    return make_unique<gettimeofdaySystemCall>(syscallNumber, syscallName);
  case SYS_ioctl:
    return make_unique<ioctlSystemCall>(syscallNumber, syscallName);
  case SYS_llistxattr:
    return make_unique<llistxattrSystemCall>(syscallNumber, syscallName);
  case SYS_lgetxattr:
    return make_unique<lgetxattrSystemCall>(syscallNumber, syscallName);
  case SYS_nanosleep:
    return make_unique<nanosleepSystemCall>(syscallNumber, syscallName);
  case SYS_mkdir:
    return make_unique<mkdirSystemCall>(syscallNumber, syscallName);
  case SYS_mkdirat:
    return make_unique<mkdiratSystemCall>(syscallNumber, syscallName);
  case SYS_lstat:
    return make_unique<lstatSystemCall>(syscallNumber, syscallName);
  case SYS_link:
      return make_unique<linkSystemCall>(syscallNumber, syscallName);
  case SYS_linkat:
    return make_unique<linkatSystemCall>(syscallNumber, syscallName);
  case SYS_mmap:
    return make_unique<mmapSystemCall>(syscallNumber, syscallName);
  case SYS_open:
    return make_unique<openSystemCall>(syscallNumber, syscallName);
  case SYS_openat:
    return make_unique<openatSystemCall>(syscallNumber, syscallName);
  case SYS_pipe:
    return make_unique<pipeSystemCall>(syscallNumber, syscallName);
  case SYS_pipe2:
    return make_unique<pipe2SystemCall>(syscallNumber, syscallName);
  case SYS_pselect6:
    return make_unique<pselect6SystemCall>(syscallNumber, syscallName);
  case SYS_poll:
    return make_unique<pollSystemCall>(syscallNumber, syscallName);
  case SYS_prlimit64:
    return make_unique<prlimit64SystemCall>(syscallNumber, syscallName);
  case SYS_read:
    return make_unique<readSystemCall>(syscallNumber, syscallName);
  case SYS_readlink:
    return make_unique<readlinkSystemCall>(syscallNumber, syscallName);
  case SYS_readlinkat:
    return make_unique<readlinkatSystemCall>(syscallNumber, syscallName);
  case SYS_recvmsg:
    return make_unique<recvmsgSystemCall>(syscallNumber, syscallName);
  case SYS_rename:
    return make_unique<renameSystemCall>(syscallNumber, syscallName);
  case SYS_renameat:
    return make_unique<renameatSystemCall>(syscallNumber, syscallName);
  case SYS_renameat2:
    return make_unique<renameat2SystemCall>(syscallNumber, syscallName);
  case SYS_rmdir:
    return make_unique<rmdirSystemCall>(syscallNumber, syscallName);
  case SYS_sendto:
    return make_unique<sendtoSystemCall>(syscallNumber, syscallName);
  case SYS_select:
    return make_unique<selectSystemCall>(syscallNumber, syscallName);
  case SYS_set_robust_list:
    return make_unique<set_robust_listSystemCall>(syscallNumber, syscallName);
  case SYS_statfs:
    return make_unique<statfsSystemCall>(syscallNumber, syscallName);
  case SYS_stat:
    return make_unique<statSystemCall>(syscallNumber, syscallName);
  case SYS_sysinfo:
    return make_unique<sysinfoSystemCall>(syscallNumber, syscallName);
  case SYS_symlink:
    return make_unique<symlinkSystemCall>(syscallNumber, syscallName);
  case SYS_tgkill:
    return make_unique<tgkillSystemCall>(syscallNumber, syscallName);
  case SYS_time:
    return make_unique<timeSystemCall>(syscallNumber, syscallName);
  case SYS_times:
    return make_unique<timesSystemCall>(syscallNumber, syscallName);
  case SYS_uname:
    return make_unique<unameSystemCall>(syscallNumber, syscallName);
  case SYS_unlink:
    return make_unique<unlinkSystemCall>(syscallNumber, syscallName);
  case SYS_unlinkat:
    return make_unique<unlinkatSystemCall>(syscallNumber, syscallName);
  case SYS_utime:
      return make_unique<utimeSystemCall>(syscallNumber, syscallName);
  case SYS_utimes:
    return make_unique<utimesSystemCall>(syscallNumber, syscallName);
  case SYS_utimensat:
    return make_unique<utimensatSystemCall>(syscallNumber, syscallName);
  case SYS_vfork:
    return make_unique<vforkSystemCall>(syscallNumber, syscallName);
  case SYS_wait4:
    return make_unique<wait4SystemCall>(syscallNumber, syscallName);
  case SYS_write:
    return make_unique<writeSystemCall>(syscallNumber, syscallName);
  case SYS_writev:
    return make_unique<writevSystemCall>(syscallNumber, syscallName);
  }

  // Generic system call. Throws error.
  throw runtime_error("Missing case for system call: " + syscallName
                      + " this is a bug!");
}
// =======================================================================================
tuple<ptraceEvent, pid_t, int>
execution::getNextEvent(pid_t pidToContinue, bool ptraceSystemcall){
  // fprintf(stderr, "Getting next event for pid %d\n", pidToContinue);
  // 3rd return value of this function. Holds the status after waitpid call.
  int status;
  // Pid of the process whose event we just intercepted through ptrace.
  pid_t traceesPid;

  // At every doPtrace we have the choice to deliver a signal. We must deliver a signal
  // when an actual signal was returned (ptraceEvent::signal), otherwise the signal is
  // never delivered to the tracee! This field is updated in @handleSignal
  //
  // 64 bit value to avoid warning when casting to void* below.
  int64_t signalToDeliver = states.at(pidToContinue).signalToDeliver;

  // Reset signal field after for next event.
  states.at(pidToContinue).signalToDeliver = 0;

  // Usually we use PTRACE_CONT below because we are letting seccomp + bpf handle the
  // events. So unlike standard ptrace, we do not rely on system call events. Instead,
  // we wait for seccomp events. Note that seccomp + bpf only sends us (the tracer)
  // a ptrace event on pre-system call events. Sometimes we need the system call to be
  // called and then we change it's arguments. So we call PTRACE_SYSCALL instead.
  if(ptraceSystemcall){
    ptracer::doPtrace(PTRACE_SYSCALL, pidToContinue, 0, (void*) signalToDeliver);
  }else{
    // Tell the process that we just intercepted an event for to continue, with us tracking
    // it's system calls. If this is the first time this function is called, it will be the
    // starting process. Which we expect to be in a waiting state.
    ptracer::doPtrace(PTRACE_CONT, pidToContinue, 0, (void*) signalToDeliver);
  }

  // Wait for next event to intercept.
  traceesPid = doWithCheck(waitpid(pidToContinue, &status, 0), "waitpid");
  // printf("Tracees pid: %d\n", traceesPid);
  return make_tuple(getPtraceEvent(status), traceesPid, status);
}
// =======================================================================================
ptraceEvent execution::getPtraceEvent(const int status){
  // Check if tracee has exited.
  if (WIFEXITED(status)){
    // log.writeToLog(Importance::extra, "nonEventExit\n");
    return ptraceEvent::nonEventExit;
  }

  // Condition for PTRACE_O_TRACEEXEC
  if( ptracer::isPtraceEvent(status, PTRACE_EVENT_EXEC) ){
    // log.writeToLog(Importance::extra, "exec\n");
    return ptraceEvent::exec;
  }

  // Condition for PTRACE_O_TRACECLONE
  if( ptracer::isPtraceEvent(status, PTRACE_EVENT_CLONE) ){
    // log.writeToLog(Importance::extra, "clone\n");
    return ptraceEvent::clone;
  }

  // Condition for PTRACE_O_TRACEVFORK
  if( ptracer::isPtraceEvent(status, PTRACE_EVENT_VFORK) ){
    // log.writeToLog(Importance::extra, "vfork\n");
    return ptraceEvent::vfork;
  }

  // Even though fork() is clone under the hood, any time that clone is used with
  // SIGCHLD, ptrace calls that event a fork *sigh*.
  // Also requires PTRACE_O_FORK flag.
  if( ptracer::isPtraceEvent(status, PTRACE_EVENT_FORK) ){
    // log.writeToLog(Importance::extra, "fork\n");
    return ptraceEvent::fork;
  }

#ifdef PTRACE_EVENT_STOP
  if( ptracer::isPtraceEvent(status, PTRACE_EVENT_STOP) ){
    // log.writeToLog(Importance::extra, "event stop\n");
    throw runtime_error("Ptrace event stop.\n");
  }
#endif

  if( ptracer::isPtraceEvent(status, PTRACE_EVENT_EXIT) ){
    // log.writeToLog(Importance::extra, "event exit\n");
    return ptraceEvent::eventExit;
  }

  if( ptracer::isPtraceEvent(status, PTRACE_EVENT_SECCOMP) ){
    // log.writeToLog(Importance::extra, "event seccomp\n");
    return ptraceEvent::seccomp;
  }

  if( ptracer::isPtraceEvent(status, PTRACE_EVENT_SECCOMP) ){
    return ptraceEvent::seccomp;
  }

  // This is a stop caused by a system call exit-pre/exit-post.
  // Check if WIFSTOPPED return true,
  // if yes, compare signal number to SIGTRAP | 0x80 (see ptrace(2)).
  if(WIFSTOPPED(status) && (WSTOPSIG(status) == (SIGTRAP | 0x80)) ){
    // log.writeToLog(Importance::extra, "event syscall\n");
    return ptraceEvent::syscall;
  }

  // Check if we intercepted a signal before it was delivered to the child.
  // TODO: Currently this is working as a sink for all signals.
  if(WIFSTOPPED(status)){
    // log.writeToLog(Importance::extra, "event signal\n");
    return ptraceEvent::signal;
  }

  // Check if the child was terminated by a signal. This can happen after when we,
  //the tracer, intercept a signal of the tracee and deliver it.
  if(WIFSIGNALED(status)){
    // log.writeToLog(Importance::extra, "terminated by signal\n");
    return ptraceEvent::terminatedBySignal;
  }

  throw runtime_error("Uknown event on dettrace::getNextEvent()");
}
// =======================================================================================
/**
 * Find and erase process from map. Returns parent (if any). Otherwise, -1.
 */
pid_t eraseChildEntry(multimap<pid_t, pid_t>& map, pid_t process){
  pid_t parent = -1;
  for(auto iter = map.begin(); iter != map.end(); iter++){
    if(iter->second == process){
      parent = iter->first;
      map.erase(iter);
      break;
    }
  }

  return parent;
}
// =======================================================================================
