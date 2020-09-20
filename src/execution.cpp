#include "execution.hpp"
#include "dettrace.hpp"
#include "dettraceSystemCall.hpp"
#include "logger.hpp"
#include "ptracer.hpp"
#include "rnr_loader.hpp"
#include "scheduler.hpp"
#include "state.hpp"
#include "systemCallList.hpp"
#include "util.hpp"
#include "vdso.hpp"

#include <sys/utsname.h>
#include <stack>
#include <tuple>

#define MAKE_KERNEL_VERSION(x, y, z) ((x) << 16 | (y) << 8 | (z))

void deleteMultimapEntry(
    unordered_multimap<pid_t, pid_t>& mymap, pid_t key, pid_t value);
pid_t eraseChildEntry(multimap<pid_t, pid_t>& map, pid_t process);
bool kernelCheck(int a, int b, int c);
void trapCPUID(globalState& gs, state& s, ptracer& t);

bool kernelCheck(int a, int b, int c) {
  struct utsname utsname = {};
  long x, y, z;
  char *r = NULL, *rp = NULL;

  doWithCheck(uname(&utsname), "uname");

  r = utsname.release;
  x = strtoul(r, &rp, 10);
  if (rp == r) {
    runtimeError("Problem parsing uname results.\n");
  }
  r = 1 + rp;
  y = strtoul(r, &rp, 10);
  if (rp == r) {
    runtimeError("Problem parsing uname results.\n");
  }
  r = 1 + rp;
  z = strtoul(r, &rp, 10);

  return (
      MAKE_KERNEL_VERSION(x, y, z) < MAKE_KERNEL_VERSION(a, b, c) ? true
                                                                  : false);
}

// =======================================================================================
execution::execution(
    int debugLevel,
    pid_t startingPid,
    bool useColor,
    string logFile,
    bool printStatistics,
    VDSOSymbol* vdsoFuncs,
    int nbVdsoFuncs,
    unsigned prngSeed,
    bool allow_network,
    logical_clock::time_point epoch,
    logical_clock::duration clock_step,
    SysEnter sys_enter_hook,
    SysExit sys_exit_hook,
    void* user_data)
    : kernelPre4_8{kernelCheck(4, 8, 0)},
      log{logFile, debugLevel, useColor},
      silentLogger{"", 0},
      printStatistics{printStatistics},
      // Waits for first process to be ready!
      tracer{startingPid},
      // Create our global state once, share across class.
      myGlobalState{
          log,          ValueMapper<ino_t, ino_t>{log, "inode map", 1},
          ModTimeMap{}, kernelCheck(4, 12, 0),
          prngSeed,     epoch,
          allow_network},
      myScheduler{startingPid, log},
      debugLevel{debugLevel},
      vdsoFuncs(vdsoFuncs, vdsoFuncs + nbVdsoFuncs),
      epoch(epoch),
      clock_step(clock_step),
      prngSeed(prngSeed),
      sys_enter_hook(sys_enter_hook),
      sys_exit_hook(sys_exit_hook),
      user_data(user_data) {
  // Set state for first process.
  states.emplace(
      startingPid, state{startingPid, debugLevel, epoch, clock_step});
  myGlobalState.threadGroups.insert({startingPid, startingPid});
  myGlobalState.threadGroupNumber.insert({startingPid, startingPid});

  // First process is special and we must set the options ourselves.
  // This is done everytime a new process is spawned.
  ptracer::setOptions(startingPid);
}
// =======================================================================================
// We only call this function on a ptrace::nonEventExit.

// Notice it's the last-child-alive's job to schedule a finished parent to exit.
// If this is the  last-child-alive, but the parent is not marked as finished,
// that's fine, it still has more code to run, eventually it will spawn more
// children, or exit.

// This is the base case. You may, be wondering what happens if the
// currentProcess itself has children and got here, this can't happen. A process
// with live children will never get a nonEventExit.
bool execution::handleNonEventExit(const pid_t traceesPid) {
  // We are done. Erase ourselves from our parent's list of children.
  pid_t parent = eraseChildEntry(processTree, traceesPid);
  auto tgNumber = myGlobalState.threadGroupNumber.at(traceesPid);

  // Erase tracee from our state.
  if (states.erase(traceesPid) != 1) {
    runtimeError("Not such tracee to delete: " + to_string(traceesPid));
  }

  // if this is a thread, clean up the thread specific state that we save.
  if (myGlobalState.liveThreads.count(traceesPid) != 0) {
    if (myGlobalState.liveThreads.erase(traceesPid) != 1) {
      runtimeError(
          "Not such thread to delete from liveThreads: " +
          to_string(traceesPid));
    }
    if (myGlobalState.threadGroupNumber.erase(traceesPid) != 1) {
      runtimeError(
          "Not such thread to delete from threadGroupNumber: " +
          to_string(traceesPid));
    }
  }

  // If thread, we should always be able to delete this entry.
  // If process, then it should have their own thread group as well.
  deleteMultimapEntry(myGlobalState.threadGroups, tgNumber, traceesPid);

  // Parent has no childrent left, and want's to exit! Schedule for exit as it
  // is no longer in our scheduler's heaps.
  if (parent != -1 && // We have no parent, we're root.
      myScheduler.isFinished(
          parent) && // Check if our parent is marked as finished.
      processTree.count(parent) == 0) { // Parent has no children left.
    log.writeToLog(
        Importance::info,
        "All children of finished parent %d have exited"
        ", scheduling parent for exiting.\n",
        parent);
    myScheduler.removeAndScheduleParent(traceesPid, parent);
    return false;
  }
  // This is the base case for any process, we have no children, and no parent
  // that we need to help exit.
  else {
    // Process done, schedule next process to run.
    bool empty = myScheduler.removeAndScheduleNext(traceesPid);
    if (empty) {
      // All processes have finished! We're done
      return true;
    }
    log.unsetPadding();
    return false;
  }
}
// =======================================================================================
// Despite what the name will imply, this function is actually called during a
// ptrace seccomp event. Not a pre-system call event. In newer kernel version
// there is no need to deal with ptrace pre-system call events. So the only
// reason we refer to it here is for backward compatibility reasons.
bool execution::handlePreSystemCall(state& currState, const pid_t traceesPid) {
  int syscallNum = tracer.getSystemCallNumber();

  if (syscallNum < 0 || syscallNum > SYSTEM_CALL_COUNT) {
    runtimeError("Unkown system call number: " + to_string(syscallNum));
  }

  // Print!
  string systemCall = systemCallMappings[syscallNum];
  string redColoredSyscall = log.makeTextColored(Color::red, systemCall);
  log.writeToLog(
      Importance::inter, "[Pid %d] Intercepted %s\n", traceesPid,
      redColoredSyscall.c_str());
  log.setPadding();

  bool callPostHook =
      callPreHook(syscallNum, myGlobalState, currState, tracer, myScheduler);

  if (sys_enter_hook && syscallNum != SYS_arch_prctl &&
      !currState.syscallInjected) {
    rnr::callPreHook(
        user_data, sys_enter_hook, syscallNum, myGlobalState, currState, tracer,
        myScheduler);
  }

  if (kernelPre4_8) {
    // Next event will be a sytem call pre-exit event as older kernels make us
    // catch the seccomp event and the ptrace pre-system call event.
    currState.onPreExitEvent = true;
  }

  // This is the easiest time to tell a fork even happened. It's not trivial
  // to check the event as we might get a signal first from the child process.
  // See:
  // https://stackoverflow.com/questions/29997244/
  // occasionally-missing-ptrace-event-vfork-when-running-ptrace
  if (systemCall == "fork" || systemCall == "vfork" || systemCall == "clone") {
    processSpawnEvents++;
    int status;
    ptraceEvent e;
    pid_t newPid;

    if (kernelPre4_8) {
      // fork/vfork/clone pre system call.
      // On older version of the kernel, we would need to catch the pre-system
      // call event to forking system calls. This is event needs to be taken off
      // the ptrace queue so we do that here and simply ignore the event.
      tie(e, newPid, status) = getNextEvent(traceesPid, true);
      if (e != ptraceEvent::syscall) {
        runtimeError("Expected pre-system call event after fork.");
      }
      // That was the pre-exit event, make sure we set onPreExitEvent to false.
      currState.onPreExitEvent = false;
    }
  }

  if (kernelPre4_8) {
    // This is the seccomp event where we do the work for the pre-system call
    // hook. In older versions of seccomp, we must also do the pre-exit ptrace
    // event, as we have to. This is dictated by this variable.
    return true;
  }

  return callPostHook;
}
// =======================================================================================
void execution::handlePostSystemCall(state& currState) {
  int syscallNum = tracer.getSystemCallNumber();

  // No idea what this system call is! error out.
  if (syscallNum < 0 || syscallNum > SYSTEM_CALL_COUNT) {
    runtimeError("Unkown system call number: " + to_string(syscallNum));
  }

  string syscallName = systemCallMappings[syscallNum];
  log.writeToLog(
      Importance::info, "Calling post hook for: " + syscallName + "\n");

  if (SYS_times == syscallNum || SYS_time == syscallNum) {
    // for syscalls with a nondet return value, print it at Importance::extra
    log.writeToLog(
        Importance::extra, "(nondet) Value before handler: %d\n",
        tracer.getReturnValue());
  } else {
    log.writeToLog(
        Importance::info, "Value before handler: %d\n",
        tracer.getReturnValue());
  }

  callPostHook(syscallNum, myGlobalState, currState, tracer, myScheduler);

  if (sys_exit_hook && syscallNum != SYS_arch_prctl &&
      !currState.syscallInjected) {
    rnr::callPostHook(
        user_data, sys_exit_hook, syscallNum, myGlobalState, currState, tracer,
        myScheduler);
  }

  log.writeToLog(
      Importance::info, "Value after handler: %d\n", tracer.getReturnValue());

  log.unsetPadding();
  return;
}

// =======================================================================================
int execution::runProgram() {
  // When using seccomp, we run with PTRACE_CONT, but seccomp only reports
  // pre-hook events. To get post hook events we must call ptrace with
  // PTRACE_SYSCALL intead. This happens in @getNextEvent.

  log.writeToLog(Importance::inter, "dettrace starting up\n");

  // Once all process' have ended. We exit.
  bool exitLoop = false;

  // Iterate over entire process' and all subprocess' execution.
  while (!exitLoop) {
    int status;
    pid_t traceesPid;
    ptraceEvent ret;

    pid_t nextPid = myScheduler.getNext();
    bool post = states.at(nextPid).callPostHook;
    tie(ret, traceesPid, status) = getNextEvent(nextPid, post);

    // Most common event. We handle the pre-hook for system calls here.
    if (ret == ptraceEvent::seccomp) {
      log.writeToLog(Importance::extra, "Is seccomp event!\n");
      systemCallsEvents++;
      states.at(traceesPid).callPostHook = handleSeccomp(traceesPid);
      continue;
    }

    // We still need this case even though we use seccomp + bpf. Since we do
    // post-hook interception of system calls through PTRACE_SYSCALL. Only post
    // system call events come here.
    if (ret == ptraceEvent::syscall) {
      // For older kernels, we see a system call event and we also see a handle
      // seccomp event. I chose to always handle the pre-system call on the
      // ptracer seccomp event. So we skip the pre-system call event here on
      // older kernels.
      state& currentState = states.at(traceesPid);

      // old-kernel-only ptrace system call event for pre exit hook.
      if (kernelPre4_8 && currentState.onPreExitEvent) {
        states.at(traceesPid).callPostHook = true;
        currentState.onPreExitEvent = false;
      } else {
        // Only count here due to comment above (we see this event twice in
        // older kernels).
        systemCallsEvents++;
        tracer.updateState(traceesPid);
        handlePostSystemCall(currentState);
        // set callPostHook to default value for next iteration.
        states.at(traceesPid).callPostHook = false;
      }

      continue;
    }

    // Current process was ended by signal.
    if (ret == ptraceEvent::terminatedBySignal) {
      auto msg = log.makeTextColored(
          Color::blue, "Process [%d] ended by signal %d.\n");
      log.writeToLog(Importance::inter, msg, traceesPid, WTERMSIG(status));
      exitLoop = handleNonEventExit(traceesPid);
      continue;
    }

    /**
       A process needs to do two things before dying:
       1) eventExit through ptrace. This process is not truly done, it is
       stopped until we let it continue and all it's children have also
       finished. 2) A nonEventExit at this point the process is done and can no
       longer be peeked or poked.

       If the process has remaining children, we will get an eventExit but the
       nonEventExit will never arrive. Therefore we set process as exited.
       Only when all children have exited do we get a the nonEvent exit.

       Therefore we keep track of the process hierarchy and only wait for the
       evenExit when our children have exited.
    */
    if (ret == ptraceEvent::eventExit) {
      auto msg = log.makeTextColored(
          Color::blue,
          "Process [%d] has finished. "
          "With ptraceEventExit, exit_code: %d.");
      log.writeToLog(Importance::inter, msg, traceesPid, exit_code);
      states.at(traceesPid).callPostHook = false;

      bool isExitGroup = states.at(traceesPid).isExitGroup;
      pid_t threadGroup = myGlobalState.threadGroupNumber.at(traceesPid);

      // there is two reasons this is necessary
      // 1) case where a thread called exit group: this process goes on to
      // exit like a normal non-threaded non-exit grouped process would, and we
      // don't want the check in ptraceEvent::nonEventExit to kill it.
      // 2) in the event where this process is the only process in the process
      // group, it will do the same as #1. Only when we have a non-main thread
      // call exit group, do we not need to set this flag, and that's only
      // because this flag is per process/thread!
      states.at(traceesPid).isExitGroup = false;
      // We state that the main process in a thread group was killed by an exit
      // group, this way, the main process ever stops responding, we know why.
      // This is needed as this process may get stuck in getNextEvent
      // otherwise... states.at(threadGroup).killedByExitGroup = true;

      // Iterate through all threads in this exit group exiting them.
      // Only go in here for exit groups where there is threads. By default,
      // there is at least 1 (the process)
      log.writeToLog(
          Importance::info, "thread group #%d\n",
          myGlobalState.threadGroups.count(threadGroup));

      if (isExitGroup && myGlobalState.threadGroups.count(threadGroup) != 1) {
        auto msg =
            "Caught exit group! Ending all thread in our process group %d.\n";
        log.writeToLog(Importance::info, msg, threadGroup);

        // Mark as finished so that handleNonEventExit function takes care of
        // eventually deleting parent process.
        myScheduler.markFinishedAndScheduleNext(threadGroup);

        // Make a copy to avoid deleting entries in original (done in
        // handleTraceeExit) while iterating through it.
        auto copyThreadGroups = myGlobalState.threadGroups;
        auto iterpair = copyThreadGroups.equal_range(threadGroup);
        auto it = iterpair.first;

        for (; it != iterpair.second; ++it) {
          pid_t thread = it->second;

          if (threadGroup == thread) {
            // This is not a thread! This is the thread group leader (process),
            // skip.
            continue;
          }

          auto msg = "Manually exiting thread %d after exit_group.\n";
          log.writeToLog(Importance::info, msg, thread);

          ptraceEvent event;
          int ret = ptrace(PTRACE_CONT, thread, 0, 0);

          if (ret == -1 && errno == ESRCH) {
            event = handleExitedThread(thread);
          } else if (ret == -1) {
            runtimeError("Unexpected error from ptrace(CONT) on thread exit.");
            exit(1); // we will never get here.
          } else {
            // Great, thread is still responding, let if continue to it's
            // nonEventExit.
            doWithCheck(
                waitpid(thread, &status, 0),
                "waitpid for nonEventExit failed.");
            event = getPtraceEvent(status);
          }

          if (event != ptraceEvent::nonEventExit) {
            runtimeError(
                "Unexpected ptrace event!" + to_string(int(event)) + "\n");
          }
          // We have allowed to process to exit through the OS. Now, clean up
          // our state for this thread.
          handleNonEventExit(thread);
        }
        continue;
      }

      // We have children still, we cannot exit.
      if (processTree.count(traceesPid) != 0) {
        myScheduler.markFinishedAndScheduleNext(traceesPid);
      } else {
        // We have no more children, nothing stops us from exiting, we continue
        // to the next event, which we expect to be a nonEventExit
      }
      continue;
    }

    // Current process is finally truly done (unlike eventExit).
    if (ret == ptraceEvent::nonEventExit) {
      if (states.at(traceesPid).isExitGroup) {
        // never seen this, don't know how to handle.
        runtimeError(
            "We should not see nonEventExit from a exitGroup event.\n");
      }

      auto msg = log.makeTextColored(
          Color::blue,
          "Process [%d] has finished. "
          "With ptraceNonEventExit.\n");
      log.writeToLog(Importance::inter, msg, traceesPid);

      states.at(traceesPid).callPostHook = false;
      if (processTree.count(traceesPid) != 0) {
        runtimeError(
            "We receieved a nonEventExit with children left."
            "This should be impossible!");
      } else {
        exitLoop = handleNonEventExit(traceesPid);
      }
      continue;
    }

    // We have encountered a call to fork, vfork, clone.
    if (ret == ptraceEvent::fork || ret == ptraceEvent::vfork ||
        ret == ptraceEvent::clone) {
      tracer.updateState(traceesPid);
      int syscallNumber = (int)tracer.getSystemCallNumber();
      string msg = "none";
      bool isThread = false;

      // Per ptrace man page: we cannot reliably tell a clone syscall from it's
      // event, so we check explicitly.
      switch (syscallNumber) {
      case SYS_fork:
        msg = "fork";
        break;
      case SYS_vfork:
        msg = "vfork";
        break;
      case SYS_clone: {
        msg = "clone";
        unsigned long flags = (unsigned long)tracer.arg1();
        isThread = (flags & CLONE_THREAD) != 0;
        // if((flags & CLONE_FILES) != 0){
        // runtimeError("We do not support CLONE_FILES\n");
        // }
        break;
      }
      default:
        runtimeError(
            "Uknown syscall number from fork/clone event: " +
            to_string(syscallNumber));
      }

      log.writeToLog(
          Importance::inter,
          log.makeTextColored(Color::blue, "[%d] caught %s event!\n"),
          traceesPid, msg.c_str());

      handleForkEvent(traceesPid, isThread);
      states.at(traceesPid).callPostHook = false;
      continue;
    }

    if (ret == ptraceEvent::exec) {
      log.writeToLog(
          Importance::inter,
          log.makeTextColored(Color::blue, "[%d] Caught execve event!\n"),
          traceesPid);
      // reset CPUID trap flag
      states.at(traceesPid).CPUIDTrapSet = false;

      handleExecEvent(traceesPid);
      continue;
    }

    if (ret == ptraceEvent::signal) {
      int signalNum = WSTOPSIG(status);
      handleSignal(signalNum, traceesPid);
      continue;
    }

    runtimeError(
        to_string(traceesPid) +
        " Uknown return value for ptracer::getNextEvent()\n");
  }

  auto msg = log.makeTextColored(
      Color::blue, "All processes done. Finished successfully!\n");
  log.writeToLog(Importance::info, msg);

  if (printStatistics) {
    auto printStat = [&](string type, uint32_t value) {
      string preStr = "dettrace Statistic. ";
      cerr << preStr + type + to_string(value) << endl;
    };

    cerr << endl;
    printStat("System Call Events: ", systemCallsEvents);
    printStat("rdtsc instructions: ", rdtscEvents);
    printStat("rdtscp instructions: ", rdtscpEvents);
    printStat("read retries: ", myGlobalState.readRetryEvents);
    printStat("write retries: ", myGlobalState.writeRetryEvents);
    printStat("getRandom() calls: ", myGlobalState.getRandomCalls);
    printStat("/dev/urandom opens: ", myGlobalState.devUrandomOpens);
    printStat("/dev/random opens: ", myGlobalState.devRandomOpens);
    printStat("Time Related Sytem Calls: ", myGlobalState.timeCalls);
    printStat("Process spawn events: ", processSpawnEvents);
    printStat(
        "Calls for scheduling next process: ",
        myScheduler.callsToScheduleNextProcess);
    printStat(
        "Replays due to blocking system call: ",
        myGlobalState.replayDueToBlocking);
    printStat("Total replays: ", myGlobalState.totalReplays);
    printStat("ptrace peeks: ", tracer.ptracePeeks);
    printStat("process_vm_reads: ", tracer.readVmCalls);
    printStat("process_vm_writes: ", tracer.writeVmCalls);
  }

  if (!myGlobalState.liveThreads.empty()) {
    cerr << "Live thread set is not empty! We miss counted the threads "
            "somewhere..."
         << endl;
    exit(1);
  }

  if (!myGlobalState.threadGroups.empty()) {
    cerr
        << "threadGroups is not empty! We miss counted the threads somewhere..."
        << endl;
    exit(1);
  }

  return exit_code;
  // Add a check for states.empty(). Not adding it now since I don't want a
  // bunch of packages. to fail over this :b
}
// =======================================================================================
pid_t execution::handleForkEvent(const pid_t traceesPid, bool isThread) {
  processSpawnEvents++;

  pid_t newChildPid = ptracer::getEventMessage(traceesPid);
  auto threadGroup = myGlobalState.threadGroupNumber.at(traceesPid);

  if (isThread) {
    myGlobalState.liveThreads.insert(newChildPid);
    auto msg = log.makeTextColored(
        Color::blue, "Adding thread %d to thread group %d\n");
    log.writeToLog(Importance::info, msg, newChildPid, threadGroup);

    // Careful here, the thread group is not necessarily traceesPid, as
    // traceesPid may be a thread, fetch the actual threadGroup by querying our
    // (traceesPid) thread group number.
    myGlobalState.threadGroups.insert({threadGroup, newChildPid});
    myGlobalState.threadGroupNumber.insert({newChildPid, threadGroup});
  } else {
    auto msg =
        log.makeTextColored(Color::blue, "Creating new thread group: %d\n");
    log.writeToLog(Importance::info, msg, newChildPid);

    // This should not happen! (Pid recycling?)
    if (myGlobalState.threadGroups.count(newChildPid) != 0) {
      runtimeError("Thread group already existed.\n");
    }

    // This is a process it owns it's own process group, create it.
    myGlobalState.threadGroups.insert({newChildPid, newChildPid});
    myGlobalState.threadGroupNumber.insert({newChildPid, newChildPid});
  }

  // If a thread T1 spawns thread T2, then T1 is NOT the parent of T2. The
  // parent is always the process (the thread group leader) that T1 belongs to.
  // This is where we add new children to the thread group leader.
  processTree.insert(make_pair(threadGroup, newChildPid));

  state& parent_state = states.at(traceesPid);
  // Share fdStatus. Processes get their own, threads share with thread group.
  if (isThread) {
    states.emplace(newChildPid, parent_state.cloned(newChildPid));
  } else {
    // Deep Copy!
    states.emplace(newChildPid, parent_state.forked(newChildPid));
  }
  // Add this new process to our states.

  log.writeToLog(
      Importance::info,
      log.makeTextColored(Color::blue, "Added process [%d] to states map.\n"),
      newChildPid);

  // Let child run instead of the parent, inform scheduler of new process.
  myScheduler.addAndScheduleNext(newChildPid);

  // during fork, the parent's mmaped memory are COWed, as we set the mapping
  // attributes to MAP_PRIVATE. new child's `mmapMemory` hence must be inherited
  // from parent process, to be consistent with fork() semantic.
  // TODO for threads we may not need to do this?!
  // states.at(newChildPid).mmapMemory.doesExist = true;
  // states.at(newChildPid).mmapMemory.setAddr(states.at(traceesPid).mmapMemory.getAddr());

  // Wait for child to be ready.
  log.writeToLog(
      Importance::info,
      log.makeTextColored(
          Color::blue, "Waiting for child to be ready for tracing...\n"));
  int status;
  int retPid = doWithCheck(waitpid(newChildPid, &status, 0), "waitpid");
  // This should never happen.
  if (retPid != newChildPid) {
    runtimeError("wait call return pid does not match new child's pid.");
  }
  log.writeToLog(
      Importance::info, log.makeTextColored(Color::blue, "Child ready!\n"));
  return newChildPid;
}

static inline unsigned long alignUp(unsigned long size, int align) {
  return (size + align - 1) & ~(align - 1);
}

void execution::disableVdso(pid_t pid) {
  struct ProcMapEntry vdsoMap, vvarMap;

  memset(&vdsoMap, 0, sizeof(vdsoMap));
  memset(&vvarMap, 0, sizeof(vvarMap));

  if (proc_get_vdso_vvar(pid, &vdsoMap, &vvarMap) < 0) {
    // found no [vdso] / [vvar], Nothing to do..
    return;
  }

  // vdso is enabled by kernel command line.
  if (vdsoMap.procMapBase != 0) {
    for (auto func : vdsoFuncs) {
      const auto& sym = func;
      unsigned long target = vdsoMap.procMapBase + sym.offset;
      unsigned long nbUpper = alignUp(sym.size, sym.alignment);
      unsigned long nb = alignUp(sym.code_size, sym.alignment);
      VERIFY(nb <= nbUpper);

      for (auto i = 0; i < nb / sizeof(long); i++) {
        uint64_t val;
        const unsigned char* z = func.code;
        unsigned long to = target + 8 * i;
        memcpy(&val, &z[8 * i], sizeof(val));
        ptracer::doPtrace(PTRACE_POKETEXT, pid, (void*)to, (void*)val);
      }

      unsigned long off = target + nb;
      unsigned long val = 0xccccccccccccccccUL;
      while (nb < nbUpper) {
        ptracer::doPtrace(PTRACE_POKETEXT, pid, (void*)off, (void*)val);
        off += sizeof(long);
        nb += sizeof(long);
      }
      VERIFY(nb == nbUpper);
    }
  }

  if (vvarMap.procMapBase != 0) {
    struct user_regs_struct regs;
    ptracer::doPtrace(PTRACE_GETREGS, pid, 0, &regs);
    auto oldRegs = regs;

    regs.orig_rax = SYS_mprotect;
    regs.rax = SYS_mprotect;
    regs.rdi = vvarMap.procMapBase;
    regs.rsi = vvarMap.procMapSize;
    regs.rdx = PROT_NONE;
    regs.r10 = 0;
    regs.r8 = 0;
    regs.r9 = 0;
    regs.rip += 1; /* 0xcc; syscall(0x0f05); 0xcc */

    int status;

    ptracer::doPtrace(PTRACE_SETREGS, pid, 0, &regs);
    ptracer::doPtrace(PTRACE_CONT, pid, 0, 0);
    VERIFY(waitpid(pid, &status, 0) == pid);
    VERIFY(WIFSTOPPED(status) && WSTOPSIG(status) == SIGTRAP);
    ptracer::doPtrace(PTRACE_GETREGS, pid, 0, &regs);
    if ((long)regs.rax < 0) {
      string err = "unable to inject mprotect, error: \n";
      runtimeError(err + strerror((long)-regs.rax));
    }
    ptracer::doPtrace(PTRACE_SETREGS, pid, 0, &oldRegs);
  }
}

static unsigned long traceePreinitMmap(pid_t pid, ptracer& t) {
  struct user_regs_struct regs;
  unsigned long ret;

  ptracer::doPtrace(PTRACE_GETREGS, pid, 0, &regs);
  auto oldRegs = regs;

  regs.orig_rax = SYS_mmap;
  regs.rax = SYS_mmap;
  regs.rdi = 0;
  regs.rsi = 0x10000;
  regs.rdx = PROT_READ | PROT_WRITE | PROT_EXEC;
  regs.r10 = MAP_PRIVATE | MAP_ANONYMOUS;
  regs.r8 = -1;
  regs.r9 = 0;

  int status;
  ptracer::doPtrace(PTRACE_SETREGS, pid, 0, &regs);
  ptracer::doPtrace(PTRACE_CONT, pid, 0, 0);
  VERIFY(waitpid(pid, &status, 0) == pid);
  VERIFY(WIFSTOPPED(status) && WSTOPSIG(status) == SIGTRAP);
  ptracer::doPtrace(PTRACE_GETREGS, pid, 0, &regs);
  if ((long)regs.rax < 0) {
    string err = "unable to inject syscall page, error: \n";
    runtimeError(err + strerror((long)-regs.rax));
  }
  ret = regs.rax;
  oldRegs.rip = regs.rip - 4; /* 0xcc, syscall, 0xcc = 4 bytes */
  memcpy(&regs, &oldRegs, sizeof(regs));
  ptracer::doPtrace(PTRACE_SETREGS, pid, 0, &regs);

  return ret;
}

void execution::handleExecEvent(pid_t pid) {
  struct user_regs_struct regs;

  ptracer::doPtrace(PTRACE_GETREGS, pid, 0, &regs);
  auto rip = regs.rip;
  unsigned long stub = 0xcc050fccUL;
  errno = 0;

  auto saved_insn = tracer.doPtrace(PTRACE_PEEKTEXT, pid, (void*)rip, 0);
  ptracer::doPtrace(
      PTRACE_POKETEXT, pid, (void*)rip,
      (void*)((saved_insn & ~0xffffffffUL) | stub));
  ptracer::doPtrace(PTRACE_CONT, pid, 0, 0);

  int status;
  VERIFY(waitpid(pid, &status, 0) == pid);
  VERIFY(WIFSTOPPED(status) && WSTOPSIG(status) == SIGTRAP);

  unsigned long mmapAddr = traceePreinitMmap(pid, tracer);

  disableVdso(pid);

  // TODO When does this ever happen?
  if (states.find(pid) == states.end()) {
    states.emplace(pid, state{pid, debugLevel, epoch, clock_step});
  }
  // Reset file descriptor state, it is wiped after execve.
  states.at(pid).fdStatus = make_shared<unordered_map<int, descriptorType>>();

  states.at(pid).mmapMemory.doesExist = true;
  states.at(pid).mmapMemory.setAddr(traceePtr<void>((void*)mmapAddr));

  ptracer::doPtrace(PTRACE_POKETEXT, pid, (void*)rip, (void*)saved_insn);
}

// =======================================================================================
bool execution::handleSeccomp(const pid_t traceesPid) {
  long syscallNum;
  ptracer::doPtrace(PTRACE_GETEVENTMSG, traceesPid, nullptr, &syscallNum);

  // TODO This might be totally unnecessary
  // INT16_MAX is sent by seccomp by convention as for system calls with no
  // rules.
  if (syscallNum == INT16_MAX) {
    // Fetch real system call from register.
    tracer.updateState(traceesPid);
    syscallNum = tracer.getSystemCallNumber();
    if (0 <= syscallNum && syscallNum < SYSTEM_CALL_COUNT) {
      runtimeError(
          "No filter rule for system call: " + systemCallMappings[syscallNum]);
    } else {
      runtimeError(
          "No filter rule for system call with unknown number: " +
          to_string(syscallNum));
    }
  }

  // TODO: Right now we update this information on every exit and entrance, as a
  // small optimization we might not want to...
  // Get registers from tracee.
  tracer.updateState(traceesPid);

  if (myGlobalState.allow_trapCPUID) {
    if (!states.at(traceesPid).CPUIDTrapSet && !myGlobalState.kernelPre4_12 &&
        NULL == getenv("DETTRACE_NO_CPUID_INTERCEPTION")) {
      // check if CPUID needs to be set, if it does, set trap
      trapCPUID(myGlobalState, states.at(traceesPid), tracer);
    }
  }

  auto callPostHook = handlePreSystemCall(states.at(traceesPid), traceesPid);
  return callPostHook;
}

struct CPUIDRegs {
  unsigned eax;
  unsigned ebx;
  unsigned ecx;
  unsigned edx;
};

// clang-format off
static const struct CPUIDRegs cpuids[] =
  {
   { 0x0000000D, 0x756E6547, 0x6C65746E, 0x49656E69, },
   { 0x00000663, 0x00000800, 0x80202001, 0x078BFBFD, },
   { 0x00000001, 0x00000000, 0x0000004D, 0x002C307D, },
   { 0x00000000, 0x00000000, 0x00000000, 0x00000000, },
   { 0x00000120, 0x01C0003F, 0x0000003F, 0x00000001, },
   { 0x00000000, 0x00000000, 0x00000003, 0x00000000, },
   { 0x00000000, 0x00000000, 0x00000000, 0x00000000, },
   { 0x00000000, 0x00000000, 0x00000000, 0x00000000, },
   { 0x00000000, 0x00000000, 0x00000000, 0x00000000, },
   { 0x00000000, 0x00000000, 0x00000000, 0x00000000, },
   { 0x00000000, 0x00000000, 0x00000000, 0x00000000, },
   { 0x00000000, 0x00000001, 0x00000100, 0x00000001, },
   { 0x00000000, 0x00000000, 0x00000000, 0x00000000, },
   { 0x00000000, 0x00000000, 0x00000000, 0x00000000, },
  };

static const struct CPUIDRegs extended_cpuids[] =
  {
   { 0x8000000A, 0x756E6547,0x6C65746E,0x49656E69, },
   { 0x00000663, 0x00000000,0x00000001,0x20100800, },
   { 0x554D4551, 0x72695620,0x6C617574,0x55504320, },
   { 0x72657620, 0x6E6F6973,0x352E3220,0x0000002B, },
   { 0x00000000, 0x00000000,0x00000000,0x00000000, },
   { 0x01FF01FF, 0x01FF01FF,0x40020140,0x40020140, },
   { 0x00000000, 0x42004200,0x02008140,0x00808140, },
   { 0x00000000, 0x00000000,0x00000000,0x00000000, },
   { 0x00003028, 0x00000000,0x00000000,0x00000000, },
   { 0x00000000, 0x00000000,0x00000000,0x00000000, },
   { 0x00000000, 0x00000000,0x00000000,0x00000000, },
};
// clang-format on

// =======================================================================================
void execution::handleSignal(int sigNum, const pid_t traceesPid) {
  if (sigNum == SIGSEGV) {
    tracer.updateState(traceesPid);
    uint32_t curr_insn32;
    ssize_t ret = readVmTraceeRaw(
        traceePtr<uint32_t>((uint32_t*)tracer.getRip().ptr), &curr_insn32,
        sizeof(uint32_t), traceesPid);

    if (ret == -1) {
      runtimeError(
          "Unable to read RIP for segfault. Cannot determine if rdtsc.\n");
    }

    if ((curr_insn32 << 16) == 0x310F0000 || (curr_insn32 << 8) == 0xF9010F00) {
      auto msg = "[%d] Tracer: Received rdtsc: Reading next instruction.\n";
      int ip_step = 2;

      if ((curr_insn32 << 8) == 0xF9010F00) {
        rdtscpEvents++;
        tracer.writeRcx(tscpCounter);
        tscpCounter += RDTSC_STEPPING;
        ip_step = 3;
        msg = "[%d] Tracer: Received rdtscp: Reading next instruction.\n";
      } else {
        rdtscEvents++;
      }

      tracer.writeRax(tscCounter);
      tracer.writeRdx(0);
      tscCounter += RDTSC_STEPPING;
      tracer.writeIp((uint64_t)tracer.getRip().ptr + ip_step);

      // Signal is now suppressed.
      states.at(traceesPid).signalToDeliver = 0;

      auto coloredMsg = log.makeTextColored(Color::blue, msg);

      // force a preemption to avoid possible busy reading TSCs.
      // myScheduler.preemptAndScheduleNext();
      log.writeToLog(Importance::inter, coloredMsg, traceesPid, sigNum);
      return;
    } else if ((curr_insn32 << 16) == 0xA20F0000) {
      struct user_regs_struct regs = tracer.getRegs();

      auto msg =
          "[%d] Tracer: intercepted cpuid instruction at %p. %rax == %p, %rcx "
          "== %p\n";
      auto coloredMsg = log.makeTextColored(Color::blue, msg);
      log.writeToLog(
          Importance::inter, coloredMsg, traceesPid, regs.rip, regs.rax,
          regs.rcx);

      // step over cpuid insn
      tracer.writeIp((uint64_t)tracer.getRip().ptr + 2);

      // suppress SIGSEGV from reaching the tracee
      states.at(traceesPid).signalToDeliver = 0;

      // fill in canonical cpuid return values

      const unsigned long nleafs = sizeof(cpuids) / sizeof(cpuids[0]);
      VERIFY(nleafs == 1 + cpuids[0].eax);

      const unsigned long nleafs_ext =
          0x80000000ul + sizeof(extended_cpuids) / sizeof(extended_cpuids[0]);
      VERIFY(nleafs_ext == 1 + extended_cpuids[0].eax);

      switch (regs.rax) {
      case 0x0 ... nleafs: {
        long leaf = regs.rax;
        const struct CPUIDRegs& cpuid = cpuids[leaf];
        tracer.writeRax(cpuid.eax);
        tracer.writeRbx(cpuid.ebx);
        tracer.writeRcx(cpuid.ecx);
        tracer.writeRdx(cpuid.edx);
      } break;
      case 0x80000000ul ... nleafs_ext: {
        long leaf = regs.rax - 0x80000000ul;
        const struct CPUIDRegs& cpuid_ext = extended_cpuids[leaf];
        tracer.writeRax(cpuid_ext.eax);
        tracer.writeRbx(cpuid_ext.ebx);
        tracer.writeRcx(cpuid_ext.ecx);
        tracer.writeRdx(cpuid_ext.edx);
      } break;
      default:
        runtimeError("CPUID unsupported %eax = " + to_string(regs.rax));
      }

      return;
    }
  }

  // Remember to deliver this signal to the tracee for next event! Happens in
  // getNextEvent.
  states.at(traceesPid).signalToDeliver = sigNum;

  auto msg = "[%d] Tracer: Received signal: %d. Forwarding signal to tracee.\n";
  auto coloredMsg = log.makeTextColored(Color::blue, msg);
  log.writeToLog(Importance::inter, coloredMsg, traceesPid, sigNum);
  return;
}
// =======================================================================================
bool execution::callPreHook(
    int syscallNumber,
    globalState& gs,
    state& s,
    ptracer& t,
    scheduler& sched) {
  switch (syscallNumber) {
  case SYS_access:
    return accessSystemCall::handleDetPre(gs, s, t, sched);

  case SYS_alarm:
    return alarmSystemCall::handleDetPre(gs, s, t, sched);

  case SYS_arch_prctl:
    return arch_prctlSystemCall::handleDetPre(gs, s, t, sched);

  case SYS_chdir:
    return chdirSystemCall::handleDetPre(gs, s, t, sched);

  case SYS_chmod:
    return chmodSystemCall::handleDetPre(gs, s, t, sched);

  case SYS_clock_gettime:
    return clock_gettimeSystemCall::handleDetPre(gs, s, t, sched);

  case SYS_close:
    return closeSystemCall::handleDetPre(gs, s, t, sched);

  case SYS_connect:
    return connectSystemCall::handleDetPre(gs, s, t, sched);

  case SYS_creat:
    return creatSystemCall::handleDetPre(gs, s, t, sched);

  case SYS_dup:
    return dupSystemCall::handleDetPre(gs, s, t, sched);

  case SYS_dup2:
    return dup2SystemCall::handleDetPre(gs, s, t, sched);

  case SYS_exit_group:
    return exit_groupSystemCall::handleDetPre(gs, s, t, sched);

  case SYS_epoll_ctl:
    return epoll_ctlSystemCall::handleDetPre(gs, s, t, sched);

  case SYS_epoll_wait:
    return epoll_waitSystemCall::handleDetPre(gs, s, t, sched);

  case SYS_epoll_pwait:
    return epoll_pwaitSystemCall::handleDetPre(gs, s, t, sched);

  case SYS_execve:
    return execveSystemCall::handleDetPre(gs, s, t, sched);

  case SYS_faccessat:
    return faccessatSystemCall::handleDetPre(gs, s, t, sched);

  case SYS_fgetxattr:
    return fgetxattrSystemCall::handleDetPre(gs, s, t, sched);

  case SYS_flistxattr:
    return flistxattrSystemCall::handleDetPre(gs, s, t, sched);

  case SYS_fchownat:
    return fchownatSystemCall::handleDetPre(gs, s, t, sched);

  case SYS_fchown:
    return fchownSystemCall::handleDetPre(gs, s, t, sched);

  case SYS_chown:
    return chownSystemCall::handleDetPre(gs, s, t, sched);

  case SYS_lchown:
    return lchownSystemCall::handleDetPre(gs, s, t, sched);

  case SYS_fcntl:
    return fcntlSystemCall::handleDetPre(gs, s, t, sched);

  case SYS_fstat:
    return fstatSystemCall::handleDetPre(gs, s, t, sched);

  case SYS_newfstatat:
    return newfstatatSystemCall::handleDetPre(gs, s, t, sched);

  case SYS_fstatfs:
    return fstatfsSystemCall::handleDetPre(gs, s, t, sched);

  case SYS_futex:
    return futexSystemCall::handleDetPre(gs, s, t, sched);

  case SYS_getcwd:
    return getcwdSystemCall::handleDetPre(gs, s, t, sched);

  case SYS_getdents:
    return getdentsSystemCall::handleDetPre(gs, s, t, sched);

  case SYS_getdents64:
    return getdents64SystemCall::handleDetPre(gs, s, t, sched);

  case SYS_getitimer:
    return getitimerSystemCall::handleDetPre(gs, s, t, sched);

  case SYS_getpeername:
    return getpeernameSystemCall::handleDetPre(gs, s, t, sched);

    // Some older systems do not have this  system call.
#ifdef SYS_getrandom
  case SYS_getrandom:
    return getrandomSystemCall::handleDetPre(gs, s, t, sched);
#endif

  case SYS_getrlimit:
    return getrlimitSystemCall::handleDetPre(gs, s, t, sched);

  case SYS_getrusage:
    return getrusageSystemCall::handleDetPre(gs, s, t, sched);

  case SYS_getsid:
    return getsidSystemCall::handleDetPre(gs, s, t, sched);

  case SYS_gettimeofday:
    return gettimeofdaySystemCall::handleDetPre(gs, s, t, sched);

  case SYS_ioctl:
    return ioctlSystemCall::handleDetPre(gs, s, t, sched);

  case SYS_llistxattr:
    return llistxattrSystemCall::handleDetPre(gs, s, t, sched);

  case SYS_lgetxattr:
    return lgetxattrSystemCall::handleDetPre(gs, s, t, sched);

  case SYS_nanosleep:
    return nanosleepSystemCall::handleDetPre(gs, s, t, sched);

  case SYS_mkdir:
    return mkdirSystemCall::handleDetPre(gs, s, t, sched);

  case SYS_mkdirat:
    return mkdiratSystemCall::handleDetPre(gs, s, t, sched);

  case SYS_lstat:
    return lstatSystemCall::handleDetPre(gs, s, t, sched);

  case SYS_link:
    return linkSystemCall::handleDetPre(gs, s, t, sched);

  case SYS_linkat:
    return linkatSystemCall::handleDetPre(gs, s, t, sched);

  case SYS_mmap:
    return mmapSystemCall::handleDetPre(gs, s, t, sched);

  case SYS_open:
    return openSystemCall::handleDetPre(gs, s, t, sched);

  case SYS_openat:
    return openatSystemCall::handleDetPre(gs, s, t, sched);

  case SYS_pause:
    return pauseSystemCall::handleDetPre(gs, s, t, sched);

  case SYS_pipe:
    return pipeSystemCall::handleDetPre(gs, s, t, sched);

  case SYS_pipe2:
    return pipe2SystemCall::handleDetPre(gs, s, t, sched);

  case SYS_pselect6:
    return pselect6SystemCall::handleDetPre(gs, s, t, sched);

  case SYS_poll:
    return pollSystemCall::handleDetPre(gs, s, t, sched);

  case SYS_prlimit64:
    return prlimit64SystemCall::handleDetPre(gs, s, t, sched);

  case SYS_read:
    return readSystemCall::handleDetPre(gs, s, t, sched);

  case SYS_readlink:
    return readlinkSystemCall::handleDetPre(gs, s, t, sched);

  case SYS_readlinkat:
    return readlinkatSystemCall::handleDetPre(gs, s, t, sched);

  case SYS_recvmsg:
    return recvmsgSystemCall::handleDetPre(gs, s, t, sched);

  case SYS_rename:
    return renameSystemCall::handleDetPre(gs, s, t, sched);

  case SYS_renameat:
    return renameatSystemCall::handleDetPre(gs, s, t, sched);

  case SYS_renameat2:
    return renameat2SystemCall::handleDetPre(gs, s, t, sched);

  case SYS_rmdir:
    return rmdirSystemCall::handleDetPre(gs, s, t, sched);

  case SYS_rt_sigprocmask:
    return rt_sigprocmaskSystemCall::handleDetPre(gs, s, t, sched);

  case SYS_rt_sigaction:
    return rt_sigactionSystemCall::handleDetPre(gs, s, t, sched);

  case SYS_rt_sigtimedwait:
    return rt_sigtimedwaitSystemCall::handleDetPre(gs, s, t, sched);

  case SYS_rt_sigsuspend:
    return rt_sigsuspendSystemCall::handleDetPre(gs, s, t, sched);

  case SYS_rt_sigpending:
    return rt_sigpendingSystemCall::handleDetPre(gs, s, t, sched);

  case SYS_sendto:
    return sendtoSystemCall::handleDetPre(gs, s, t, sched);

  case SYS_sendmsg:
    return sendmsgSystemCall::handleDetPre(gs, s, t, sched);

  case SYS_sendmmsg:
    return sendmmsgSystemCall::handleDetPre(gs, s, t, sched);

  case SYS_recvfrom:
    return recvfromSystemCall::handleDetPre(gs, s, t, sched);

  case SYS_select:
    return selectSystemCall::handleDetPre(gs, s, t, sched);

  case SYS_setitimer:
    return setitimerSystemCall::handleDetPre(gs, s, t, sched);

  case SYS_set_robust_list:
    return set_robust_listSystemCall::handleDetPre(gs, s, t, sched);

  case SYS_statfs:
    return statfsSystemCall::handleDetPre(gs, s, t, sched);

  case SYS_stat:
    return statSystemCall::handleDetPre(gs, s, t, sched);

  case SYS_sysinfo:
    return sysinfoSystemCall::handleDetPre(gs, s, t, sched);

  case SYS_symlink:
    return symlinkSystemCall::handleDetPre(gs, s, t, sched);

  case SYS_symlinkat:
    return symlinkatSystemCall::handleDetPre(gs, s, t, sched);

  case SYS_mknod:
    return mknodSystemCall::handleDetPre(gs, s, t, sched);

  case SYS_mknodat:
    return mknodatSystemCall::handleDetPre(gs, s, t, sched);

  case SYS_tgkill:
    return tgkillSystemCall::handleDetPre(gs, s, t, sched);

  case SYS_time:
    return timeSystemCall::handleDetPre(gs, s, t, sched);

  case SYS_timer_create:
    return timer_createSystemCall::handleDetPre(gs, s, t, sched);

  case SYS_timer_delete:
    return timer_deleteSystemCall::handleDetPre(gs, s, t, sched);

  case SYS_timer_getoverrun:
    return timer_getoverrunSystemCall::handleDetPre(gs, s, t, sched);

  case SYS_timer_gettime:
    return timer_gettimeSystemCall::handleDetPre(gs, s, t, sched);

  case SYS_timer_settime:
    return timer_settimeSystemCall::handleDetPre(gs, s, t, sched);

  case SYS_timerfd_create:
    return timerfd_createSystemCall::handleDetPre(gs, s, t, sched);

  case SYS_timerfd_settime:
    return timerfd_settimeSystemCall::handleDetPre(gs, s, t, sched);

  case SYS_timerfd_gettime:
    return timerfd_gettimeSystemCall::handleDetPre(gs, s, t, sched);

  case SYS_times:
    return timesSystemCall::handleDetPre(gs, s, t, sched);

  case SYS_uname:
    return unameSystemCall::handleDetPre(gs, s, t, sched);

  case SYS_unlink:
    return unlinkSystemCall::handleDetPre(gs, s, t, sched);

  case SYS_unlinkat:
    return unlinkatSystemCall::handleDetPre(gs, s, t, sched);

  case SYS_utime:
    return utimeSystemCall::handleDetPre(gs, s, t, sched);

  case SYS_utimes:
    return utimesSystemCall::handleDetPre(gs, s, t, sched);

  case SYS_utimensat:
    return utimensatSystemCall::handleDetPre(gs, s, t, sched);

  case SYS_futimesat:
    return futimesatSystemCall::handleDetPre(gs, s, t, sched);

  case SYS_wait4:
    return wait4SystemCall::handleDetPre(gs, s, t, sched);

  case SYS_waitid:
    return waitidSystemCall::handleDetPre(gs, s, t, sched);

  case SYS_write:
    return writeSystemCall::handleDetPre(gs, s, t, sched);

  case SYS_writev:
    return writevSystemCall::handleDetPre(gs, s, t, sched);
  case SYS_socket:
    return socketSystemCall::handleDetPre(gs, s, t, sched);
  case SYS_listen:
    return listenSystemCall::handleDetPre(gs, s, t, sched);
  case SYS_accept:
    return acceptSystemCall::handleDetPre(gs, s, t, sched);
  case SYS_accept4:
    return accept4SystemCall::handleDetPre(gs, s, t, sched);
  case SYS_shutdown:
    return shutdownSystemCall::handleDetPre(gs, s, t, sched);
  }

  // Generic system call. Throws error.
  runtimeError(
      "This is a bug. Missing case for system call: " +
      to_string(syscallNumber));
  // Can never happen, here to avoid spurious warning.
  return false;
}
// =======================================================================================
void execution::callPostHook(
    int syscallNumber,
    globalState& gs,
    state& s,
    ptracer& t,
    scheduler& sched) {
  switch (syscallNumber) {
  case SYS_access:
    return accessSystemCall::handleDetPost(gs, s, t, sched);

  case SYS_alarm:
    return alarmSystemCall::handleDetPost(gs, s, t, sched);

  case SYS_arch_prctl:
    return arch_prctlSystemCall::handleDetPost(gs, s, t, sched);

  case SYS_chdir:
    return chdirSystemCall::handleDetPost(gs, s, t, sched);

  case SYS_chown:
    return chownSystemCall::handleDetPost(gs, s, t, sched);

  case SYS_lchown:
    return lchownSystemCall::handleDetPost(gs, s, t, sched);

  case SYS_chmod:
    return chmodSystemCall::handleDetPost(gs, s, t, sched);

  case SYS_clock_gettime:
    return clock_gettimeSystemCall::handleDetPost(gs, s, t, sched);

  case SYS_close:
    return closeSystemCall::handleDetPost(gs, s, t, sched);

    // case SYS_clone:
    //   return cloneSystemCall::handleDetPost(gs, s, t, sched);

  case SYS_connect:
    return connectSystemCall::handleDetPost(gs, s, t, sched);

  case SYS_creat:
    return creatSystemCall::handleDetPost(gs, s, t, sched);

  case SYS_dup:
    return dupSystemCall::handleDetPost(gs, s, t, sched);

  case SYS_dup2:
    return dup2SystemCall::handleDetPost(gs, s, t, sched);

  case SYS_epoll_ctl:
    return epoll_ctlSystemCall::handleDetPost(gs, s, t, sched);

  case SYS_epoll_wait:
    return epoll_waitSystemCall::handleDetPost(gs, s, t, sched);

  case SYS_epoll_pwait:
    return epoll_pwaitSystemCall::handleDetPost(gs, s, t, sched);

  case SYS_faccessat:
    return faccessatSystemCall::handleDetPost(gs, s, t, sched);

  case SYS_fgetxattr:
    return fgetxattrSystemCall::handleDetPost(gs, s, t, sched);

  case SYS_flistxattr:
    return flistxattrSystemCall::handleDetPost(gs, s, t, sched);

  case SYS_fchownat:
    return fchownatSystemCall::handleDetPost(gs, s, t, sched);

  case SYS_fchown:
    return fchownSystemCall::handleDetPost(gs, s, t, sched);

  case SYS_fcntl:
    return fcntlSystemCall::handleDetPost(gs, s, t, sched);

  case SYS_fstat:
    return fstatSystemCall::handleDetPost(gs, s, t, sched);

  case SYS_newfstatat:
    return newfstatatSystemCall::handleDetPost(gs, s, t, sched);

  case SYS_fstatfs:
    return fstatfsSystemCall::handleDetPost(gs, s, t, sched);

  case SYS_futex:
    return futexSystemCall::handleDetPost(gs, s, t, sched);

  case SYS_getcwd:
    return getcwdSystemCall::handleDetPost(gs, s, t, sched);

  case SYS_getdents:
    return getdentsSystemCall::handleDetPost(gs, s, t, sched);

  case SYS_getdents64:
    return getdents64SystemCall::handleDetPost(gs, s, t, sched);

  case SYS_getitimer:
    return getitimerSystemCall::handleDetPost(gs, s, t, sched);

  case SYS_getpeername:
    return getpeernameSystemCall::handleDetPost(gs, s, t, sched);

    // Some older systems do not have this  system call.
#ifdef SYS_getrandom
  case SYS_getrandom:
    return getrandomSystemCall::handleDetPost(gs, s, t, sched);
#endif

  case SYS_getrlimit:
    return getrlimitSystemCall::handleDetPost(gs, s, t, sched);

  case SYS_getrusage:
    return getrusageSystemCall::handleDetPost(gs, s, t, sched);

  case SYS_getsid:
    return getsidSystemCall::handleDetPost(gs, s, t, sched);

  case SYS_gettimeofday:
    return gettimeofdaySystemCall::handleDetPost(gs, s, t, sched);

  case SYS_ioctl:
    return ioctlSystemCall::handleDetPost(gs, s, t, sched);

  case SYS_llistxattr:
    return llistxattrSystemCall::handleDetPost(gs, s, t, sched);

  case SYS_lgetxattr:
    return lgetxattrSystemCall::handleDetPost(gs, s, t, sched);

  case SYS_nanosleep:
    return nanosleepSystemCall::handleDetPost(gs, s, t, sched);

  case SYS_mkdir:
    return mkdirSystemCall::handleDetPost(gs, s, t, sched);

  case SYS_mkdirat:
    return mkdiratSystemCall::handleDetPost(gs, s, t, sched);

  case SYS_lstat:
    return lstatSystemCall::handleDetPost(gs, s, t, sched);

  case SYS_link:
    return linkSystemCall::handleDetPost(gs, s, t, sched);

  case SYS_linkat:
    return linkatSystemCall::handleDetPost(gs, s, t, sched);

  case SYS_mmap:
    return mmapSystemCall::handleDetPost(gs, s, t, sched);

  case SYS_open:
    return openSystemCall::handleDetPost(gs, s, t, sched);

  case SYS_openat:
    return openatSystemCall::handleDetPost(gs, s, t, sched);

  case SYS_pause:
    return pauseSystemCall::handleDetPost(gs, s, t, sched);

  case SYS_pipe:
    return pipeSystemCall::handleDetPost(gs, s, t, sched);

  case SYS_pipe2:
    return pipe2SystemCall::handleDetPost(gs, s, t, sched);

  case SYS_pselect6:
    return pselect6SystemCall::handleDetPost(gs, s, t, sched);

  case SYS_poll:
    return pollSystemCall::handleDetPost(gs, s, t, sched);

  case SYS_prlimit64:
    return prlimit64SystemCall::handleDetPost(gs, s, t, sched);

  case SYS_read:
    return readSystemCall::handleDetPost(gs, s, t, sched);

  case SYS_readlink:
    return readlinkSystemCall::handleDetPost(gs, s, t, sched);

  case SYS_readlinkat:
    return readlinkatSystemCall::handleDetPost(gs, s, t, sched);

  case SYS_recvmsg:
    return recvmsgSystemCall::handleDetPost(gs, s, t, sched);

  case SYS_rename:
    return renameSystemCall::handleDetPost(gs, s, t, sched);

  case SYS_renameat:
    return renameatSystemCall::handleDetPost(gs, s, t, sched);

  case SYS_renameat2:
    return renameat2SystemCall::handleDetPost(gs, s, t, sched);

  case SYS_rmdir:
    return rmdirSystemCall::handleDetPost(gs, s, t, sched);

  case SYS_rt_sigprocmask:
    return rt_sigprocmaskSystemCall::handleDetPost(gs, s, t, sched);

  case SYS_rt_sigaction:
    return rt_sigactionSystemCall::handleDetPost(gs, s, t, sched);

  case SYS_rt_sigtimedwait:
    return rt_sigtimedwaitSystemCall::handleDetPost(gs, s, t, sched);

  case SYS_rt_sigsuspend:
    return rt_sigsuspendSystemCall::handleDetPost(gs, s, t, sched);

  case SYS_rt_sigpending:
    return rt_sigpendingSystemCall::handleDetPost(gs, s, t, sched);

  case SYS_sendto:
    return sendtoSystemCall::handleDetPost(gs, s, t, sched);

  case SYS_sendmsg:
    return sendmsgSystemCall::handleDetPost(gs, s, t, sched);

  case SYS_sendmmsg:
    return sendmmsgSystemCall::handleDetPost(gs, s, t, sched);

  case SYS_recvfrom:
    return recvfromSystemCall::handleDetPost(gs, s, t, sched);

  case SYS_select:
    return selectSystemCall::handleDetPost(gs, s, t, sched);

  case SYS_setitimer:
    return setitimerSystemCall::handleDetPost(gs, s, t, sched);

  case SYS_set_robust_list:
    return set_robust_listSystemCall::handleDetPost(gs, s, t, sched);

  case SYS_statfs:
    return statfsSystemCall::handleDetPost(gs, s, t, sched);

  case SYS_stat:
    return statSystemCall::handleDetPost(gs, s, t, sched);

  case SYS_sysinfo:
    return sysinfoSystemCall::handleDetPost(gs, s, t, sched);

  case SYS_symlink:
    return symlinkSystemCall::handleDetPost(gs, s, t, sched);

  case SYS_symlinkat:
    return symlinkatSystemCall::handleDetPost(gs, s, t, sched);

  case SYS_mknod:
    return mknodSystemCall::handleDetPost(gs, s, t, sched);

  case SYS_mknodat:
    return mknodatSystemCall::handleDetPost(gs, s, t, sched);

  case SYS_tgkill:
    return tgkillSystemCall::handleDetPost(gs, s, t, sched);

  case SYS_time:
    return timeSystemCall::handleDetPost(gs, s, t, sched);

  case SYS_timer_create:
    return timer_createSystemCall::handleDetPost(gs, s, t, sched);

  case SYS_timer_delete:
    return timer_deleteSystemCall::handleDetPost(gs, s, t, sched);

  case SYS_timer_getoverrun:
    return timer_getoverrunSystemCall::handleDetPost(gs, s, t, sched);

  case SYS_timer_gettime:
    return timer_gettimeSystemCall::handleDetPost(gs, s, t, sched);

  case SYS_timer_settime:
    return timer_settimeSystemCall::handleDetPost(gs, s, t, sched);

  case SYS_timerfd_create:
    return timerfd_createSystemCall::handleDetPost(gs, s, t, sched);

  case SYS_timerfd_settime:
    return timerfd_settimeSystemCall::handleDetPost(gs, s, t, sched);

  case SYS_timerfd_gettime:
    return timerfd_gettimeSystemCall::handleDetPost(gs, s, t, sched);

  case SYS_times:
    return timesSystemCall::handleDetPost(gs, s, t, sched);

  case SYS_uname:
    return unameSystemCall::handleDetPost(gs, s, t, sched);

  case SYS_unlink:
    return unlinkSystemCall::handleDetPost(gs, s, t, sched);

  case SYS_unlinkat:
    return unlinkatSystemCall::handleDetPost(gs, s, t, sched);

  case SYS_utime:
    return utimeSystemCall::handleDetPost(gs, s, t, sched);

  case SYS_utimes:
    return utimesSystemCall::handleDetPost(gs, s, t, sched);

  case SYS_utimensat:
    return utimensatSystemCall::handleDetPost(gs, s, t, sched);

  case SYS_futimesat:
    return futimesatSystemCall::handleDetPost(gs, s, t, sched);

  case SYS_wait4:
    return wait4SystemCall::handleDetPost(gs, s, t, sched);

  case SYS_waitid:
    return waitidSystemCall::handleDetPost(gs, s, t, sched);

  case SYS_write:
    return writeSystemCall::handleDetPost(gs, s, t, sched);

  case SYS_writev:
    return writevSystemCall::handleDetPost(gs, s, t, sched);
  case SYS_socket:
    return socketSystemCall::handleDetPost(gs, s, t, sched);
  case SYS_listen:
    return listenSystemCall::handleDetPost(gs, s, t, sched);
  case SYS_accept:
    return acceptSystemCall::handleDetPost(gs, s, t, sched);
  case SYS_accept4:
    return accept4SystemCall::handleDetPost(gs, s, t, sched);
  case SYS_shutdown:
    return shutdownSystemCall::handleDetPost(gs, s, t, sched);
  }

  // Generic system call. Throws error.
  runtimeError(
      "This is a bug: "
      "Missing case for system call: " +
      to_string(syscallNumber));
}
// =======================================================================================
tuple<ptraceEvent, pid_t, int> execution::getNextEvent(
    pid_t pidToContinue, bool ptraceSystemcall) {
  // fprintf(stderr, "Getting next event for pid %d\n", pidToContinue);
  // 3rd return value of this function. Holds the status after waitpid call.
  int status = 0;
  // Pid of the process whose event we just intercepted through ptrace.
  pid_t traceesPid;

  // At every doPtrace we have the choice to deliver a signal. We must deliver a
  // signal when an actual signal was returned (ptraceEvent::signal), otherwise
  // the signal is never delivered to the tracee! This field is updated in
  // @handleSignal
  //
  // 64 bit value to avoid warning when casting to void* below.
  int64_t signalToDeliver = states.at(pidToContinue).signalToDeliver;

  // Reset signal field after for next event.
  states.at(pidToContinue).signalToDeliver = 0;

  // Usually we use PTRACE_CONT below because we are letting seccomp + bpf
  // handle the events. So unlike standard ptrace, we do not rely on system call
  // events. Instead, we wait for seccomp events. Note that seccomp + bpf only
  // sends us (the tracer) a ptrace event on pre-system call events. Sometimes
  // we need the system call to be called and then we change it's arguments. So
  // we call PTRACE_SYSCALL instead.
  if (ptraceSystemcall) {
    log.writeToLog(
        Importance::extra,
        "getNextEvent(): Waiting for next system call event.\n");
    struct user_regs_struct regs;
    ptracer::doPtrace(PTRACE_GETREGS, pidToContinue, 0, &regs);
    // old glibc (2.13) calls (buggy) vsyscall for certain syscalls
    // such as time. this doesn't play along well with recent
    // kernels with seccomp-bpf support (4.4+)
    // for more details, see `Caveats` section of kernel document:
    // https://www.kernel.org/doc/Documentation/prctl/seccomp_filter.txt
    if ((regs.rip & ~0xc00ULL) == 0xFFFFFFFFFF600000ULL) {
      log.writeToLog(
          Importance::extra, "getNextEvent(): Looking at VDSO in old glibc.\n");
      int status;
      int syscallNum = regs.orig_rax;
      // vsyscall seccomp stop is a special case
      // single step would cause the vsyscall exit fully
      // we cannot use `PTRACE_SYSCALL` as it wouldn't stop
      // at syscall exit like regular syscalls.
      ptracer::doPtrace(
          PTRACE_SINGLESTEP, pidToContinue, 0, (void*)signalToDeliver);
      // wait for our SIGTRAP
      // TODO check return value of this!!
      waitpid(pidToContinue, &status, 0);

      // call our post-hook manually for vsyscall stops.
      tracer.updateState(pidToContinue);

      // TODO this assumes we wanted to call the post-hook for this system call,
      // is this always true?
      callPostHook(
          syscallNum, myGlobalState, states.at(pidToContinue), tracer,
          myScheduler);

      // TODO What's the point of this second updateState call?
      tracer.updateState(pidToContinue);

      // 000000000009efe0 <time@@GLIBC_2.2.5>:
      // 9efe0:       48 83 ec 08             sub    $0x8,%rsp
      // 9efe4:       48 c7 c0 00 04 60 ff    mov    $0xffffffffff600400,%rax
      // 9efeb:       ff d0                   callq  *%rax
      // 9efed:       48 83 c4 08             add    $0x8,%rsp
      // 9eff1:       c3                      retq
      //
      // our expected rip is @9eff1. must resume with `PTRACE_CONT`
      // since our vsyscall has been *emulated*

      ptracer::doPtrace(PTRACE_CONT, pidToContinue, 0, (void*)signalToDeliver);
    } else {
      doWithCheck(
          ptrace(PTRACE_SYSCALL, pidToContinue, 0, (void*)signalToDeliver),
          "here at syscall!");
    }
  } else {
    log.writeToLog(
        Importance::extra, "getNextEvent(): Waiting at ptrace(CONT).\n");
    // Tell the process that we just intercepted an event for to continue, with
    // us tracking it's system calls. If this is the first time this function is
    // called, it will be the starting process. Which we expect to be in a
    // waiting state. doWithCheck(ptrace(PTRACE_CONT, pidToContinue, 0, (void*)
    // signalToDeliver),
    //             "dettrace ptrace continue failed on " +
    //             to_string(pidToContinue) + "\n");
    doWithCheck(
        ptrace(PTRACE_CONT, pidToContinue, 0, (void*)signalToDeliver),
        "failed to PTRACE_CONT from getNextEvent()\n");
  }

  // Wait for next event to intercept.
  traceesPid = doWithCheck(waitpid(pidToContinue, &status, 0), "waitpid");
  log.writeToLog(
      Importance::extra, "getNextEvent(): Got event from waitpid().\n");

  return make_tuple(getPtraceEvent(status), traceesPid, status);
}
// =======================================================================================

ptraceEvent execution::getPtraceEvent(const int status) {
  // Events ordered in order of likely hood.

  if (ptracer::isPtraceEvent(status, PTRACE_EVENT_SECCOMP)) {
    return ptraceEvent::seccomp;
  }

  // This is a stop caused by a system call exit-post.
  // All pre events are caught by seccomp.
  if (WIFSTOPPED(status) && (WSTOPSIG(status) == (SIGTRAP | 0x80))) {
    return ptraceEvent::syscall;
  }

  // Check if tracee has exited.
  if (WIFEXITED(status)) {
    log.writeToLog(Importance::extra, "nonEventExit\n");
    exit_code = WEXITSTATUS(status);
    return ptraceEvent::nonEventExit;
  }

  // Condition for PTRACE_O_TRACEEXEC
  if (ptracer::isPtraceEvent(status, PTRACE_EVENT_EXEC)) {
    log.writeToLog(Importance::extra, "exec\n");
    return ptraceEvent::exec;
  }

  // Condition for PTRACE_O_TRACECLONE
  if (ptracer::isPtraceEvent(status, PTRACE_EVENT_CLONE)) {
    log.writeToLog(Importance::extra, "clone\n");
    return ptraceEvent::clone;
  }

  // Condition for PTRACE_O_TRACEVFORK
  if (ptracer::isPtraceEvent(status, PTRACE_EVENT_VFORK)) {
    log.writeToLog(Importance::extra, "vfork\n");
    return ptraceEvent::vfork;
  }

  // Even though fork() is clone under the hood, any time that clone is used
  // with SIGCHLD, ptrace calls that event a fork *sigh*. Also requires
  // PTRACE_O_FORK flag.
  if (ptracer::isPtraceEvent(status, PTRACE_EVENT_FORK)) {
    log.writeToLog(Importance::extra, "fork\n");
    return ptraceEvent::fork;
  }

#ifdef PTRACE_EVENT_STOP
  if (ptracer::isPtraceEvent(status, PTRACE_EVENT_STOP)) {
    log.writeToLog(Importance::extra, "event stop\n");
    runtimeError("Ptrace event stop.\n");
  }
#endif

  if (ptracer::isPtraceEvent(status, PTRACE_EVENT_EXIT)) {
    exit_code = WEXITSTATUS(status);
    return ptraceEvent::eventExit;
  }

  // Check if we intercepted a signal before it was delivered to the child.
  if (WIFSTOPPED(status)) {
    return ptraceEvent::signal;
  }

  // Check if the child was terminated by a signal. This can happen after when
  // we,
  // the tracer, intercept a signal of the tracee and deliver it.
  if (WIFSIGNALED(status)) {
    exit_code = WTERMSIG(status);
    return ptraceEvent::terminatedBySignal;
  }

  runtimeError("Uknown event on execution::getPtraceEvent()");
  // Can never happen, here to avoid spurious warning.
  return ptraceEvent::nonEventExit;
}
// =======================================================================================
/**
 * Find and erase process from map. Returns parent (if any). Otherwise, -1.
 */
pid_t eraseChildEntry(multimap<pid_t, pid_t>& map, pid_t process) {
  pid_t parent = -1;
  for (auto iter = map.begin(); iter != map.end(); iter++) {
    if (iter->second == process) {
      parent = iter->first;
      map.erase(iter);
      break;
    }
  }

  return parent;
}
// =======================================================================================

void trapCPUID(globalState& gs, state& s, ptracer& t) {
  gs.log.writeToLog(
      Importance::info,
      "Injecting arch_prctl call to tracee to intercept CPUID!\n");
  // Save current register state to restore after arch_prctl
  s.regSaver.pushRegisterState(t.getRegs());

  // Inject arch_prctl system call
  s.syscallInjected = true;

  // Call arch_prctl
  t.writeArg1(ARCH_SET_CPUID);
  t.writeArg2(0);

  uint16_t minus2 = t.readFromTracee(
      traceePtr<uint16_t>((uint16_t*)((uint64_t)t.getRip().ptr - 2)),
      t.getPid());
  if (!(minus2 == 0x80CD || minus2 == 0x340F || minus2 == 0x050F)) {
    runtimeError("IP does not point to system call instruction!\n");
  }

  gs.totalReplays++;
  // Replay system call!
  t.changeSystemCall(SYS_arch_prctl);
  t.writeIp((uint64_t)t.getRip().ptr - 2);
  gs.log.writeToLog(Importance::info, "arch_prctl(%d, 0)\n", ARCH_SET_CPUID);
}

void deleteMultimapEntry(
    unordered_multimap<pid_t, pid_t>& mymap, pid_t key, pid_t value) {
  auto iterpair = mymap.equal_range(key);
  auto it = iterpair.first;
  for (; it != iterpair.second; ++it) {
    if (it->second == value) {
      mymap.erase(it);
      return;
    }
  }

  runtimeError(
      "Unable to delete entry thread group entry for (" + to_string(key) +
      ", " + to_string(value) + ")\n");
}

ptraceEvent execution::handleExitedThread(pid_t currentPid) {
  // This is a funky case. If we got here, it means we PTRACE_CONT on a exiting
  // thread and it didn't respond (ESRCH), we were hoping to get to it's
  // ptraceEventExit, but the thread is unresponsive. Instead, this event
  // probably already arrived, the thread seems to be stuck until we waitpid()
  // it's eventExit off the "waitpid event queue".

  // After that, it seems to respond just fine to a new PTRACE_CONT, which will
  // take us into the ptraceNonEventExit. I don't actually know that this will
  // always work, but emperically this seems to be what's happening.
  log.writeToLog(
      Importance::info,
      "No reponse from process, attempting to get exit event from waitpid.\n");
  bool succ;
  ptraceEvent event;
  tie(succ, event) = loopOnWaitpid(currentPid);

  if (!succ) {
    // assume we exited correctly.
    log.writeToLog(
        Importance::info,
        "Did not hear back from process after first loopOnWaitpid() "
        "assume it is done.\n");
    return ptraceEvent::nonEventExit;
  }

  // we succeeded with the wrong event
  if (event != ptraceEvent::eventExit) {
    runtimeError(
        "Unexpected event from loopOnWaitpid() 1 : " + to_string(int(event)));
  }

  // Continue over to the ptraceEvenNonExit.
  // TODO in the future we may relax the assumption that if a process succeeded
  // on the first event then we _have to_ hear back from ptrace(CONT).
  doWithCheck(
      ptrace(PTRACE_CONT, currentPid, 0, 0),
      "handleexitedThread(): Unable to continue thread to "
      "ptraceNonEventExit.\n");
  tie(succ, event) = loopOnWaitpid(currentPid);
  if (!succ) {
    log.writeToLog(
        Importance::info,
        "Did not hear back from process after second loopOnWaitpid() "
        "assume it is done.\n");
    // assume we exited correctly.
    return ptraceEvent::nonEventExit;
  }

  log.writeToLog(
      Importance::info, "Successfully received all events from thread.\n");
  return event;
}

pair<bool, ptraceEvent> execution::loopOnWaitpid(pid_t currentPid) {
  // Threads may not respond to ptrace calls since it has exited. Check waitpid
  // to see if an exit status was delivered to us.
  int status;

  // Attempt blocking wait. Will error if thread no longer responds.
  if (waitpid(currentPid, &status, 0) != -1) {
    return make_pair(true, getPtraceEvent(status));
  } else {
    log.writeToLog(
        Importance::info, "Failed to hear from tracee through waitpid\n.");
    // dummy ptrace event, you should ignore this field on false.
    return make_pair(false, ptraceEvent::eventExit);
  }

  // It seems we don't actually need to poll like this: but we leave in case it
  // is needed in the future.
  log.writeToLog(
      Importance::info,
      "Initial blocking waitpid failed, switching to polling?\n.");

  // Wait for event for N times.
  // TODO In the future a timeout-like event might be better than busy waiting.
  // for(int i = 0; i < 100000; i++){
  //   // Set function wide status here! Used at very end to report the correct
  //   message! int nextPid = waitpid(currentPid, &status, WNOHANG); if(nextPid
  //   == currentPid){
  //     done = true;
  //     auto msg = log.makeTextColored(Color::blue,
  //                  "Total calls to waitpid (ptrace syscall): %d\n");
  //     log.writeToLog(Importance::extra, msg, i + 1);
  //     break;
  //   } else if (nextPid == 0) {
  //     // Still looping hoping for event to come... continue.
  //     continue;
  //   } else {
  //     runtimeError("Unexpected return value from waitpid: " +
  //     to_string(nextPid));
  //   }
  // }

  // if (!done) {
  //   log.writeToLog(Importance::info, "Failed to hear from tracee through
  //   waitpid\n.");
  //   // dummy ptrace event, you should ignore this field on false.
  //   return make_pair(false, ptraceEvent::eventExit);
  // }

  // return make_pair(true, getPtraceEvent(status));
}
