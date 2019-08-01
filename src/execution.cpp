#include "logger.hpp"
#include "systemCallList.hpp"
#include "dettraceSystemCall.hpp"
#include "util.hpp"
#include "state.hpp"
#include "ptracer.hpp"
#include "execution.hpp"
#include "scheduler.hpp"
#include "vdso.hpp"

#include <stack>
#include <tuple>
#include <sys/utsname.h>
#include <cassert>
#include <errno.h>

#define MAKE_KERNEL_VERSION(x, y, z) ((x) << 16 | (y) << 8 | (z) )

void deleteMultimapEntry(unordered_multimap<pid_t, pid_t>& mymap, pid_t key, pid_t value);
pid_t eraseChildEntry(multimap<pid_t, pid_t>& map, pid_t process);
bool kernelCheck(int a, int b, int c);
void trapCPUID(globalState& gs, state& s, ptracer& t);

bool kernelCheck(int a, int b, int c){
  struct utsname utsname = {};
  long x, y, z;
  char* r = NULL, *rp = NULL;

  doWithCheck(uname(&utsname), "uname");

  r = utsname.release;
  x = strtoul(r, &rp, 10);
  if (rp == r){
    runtimeError("Problem parsing uname results.\n");
  }
  r = 1 + rp;
  y = strtoul(r, &rp, 10);
  if (rp == r){
    runtimeError("Problem parsing uname results.\n");
  }
  r = 1 + rp;
  z = strtoul(r, &rp, 10);

  return (MAKE_KERNEL_VERSION(x, y, z) < MAKE_KERNEL_VERSION(a, b, c) ?
          true : false);
}

// =======================================================================================
execution::execution(int debugLevel, pid_t startingPid, bool useColor,
                     string logFile, bool printStatistics,
                     pthread_t devRandomPthread, pthread_t devUrandomPthread,
                     map<string, tuple<unsigned long, unsigned long, unsigned long>> vdsoFuncs):
  kernelPre4_8 {kernelCheck(4,8,0)},
  log {logFile, debugLevel, useColor},
  silentLogger {"NONE", 0},
  printStatistics{printStatistics},
  devRandomPthread{devRandomPthread},
  devUrandomPthread{devUrandomPthread},
  // Waits for first process to be ready!
  tracer{startingPid},
  // Create our global state once, share across class.
  myGlobalState{
    log,
    ValueMapper<ino_t, ino_t> {log, "inode map", 1},
    ValueMapper<ino_t, time_t> {log, "mtime map", 1},
    kernelCheck(4,12,0)
  },
  myScheduler {startingPid, log},
  debugLevel {debugLevel},
  vdsoFuncs(vdsoFuncs) {
    // Set state for first process.
    states.emplace(startingPid, state{startingPid, debugLevel});
    myGlobalState.threadGroups.insert({startingPid, startingPid});
    myGlobalState.threadGroupNumber.insert({startingPid, startingPid});

    // First process is special and we must set the options ourselves.
    // This is done everytime a new process is spawned.
    ptracer::setOptions(startingPid);
  }
// =======================================================================================
// Despite what the name will imply, this function is actually called during a
// ptrace seccomp event. Not a pre-system call event. In newer kernel version there is no
// need to deal with ptrace pre-system call events. So the only reason we refer to it here
// is for backward compatibility reasons.
bool execution::handlePreSystemCall(state& currState, const pid_t traceesPid){
  int syscallNum = tracer.getSystemCallNumber();

  if(syscallNum < 0 || syscallNum > SYSTEM_CALL_COUNT){
    runtimeError("Unkown system call number: " +
                        to_string(syscallNum));
  }

  // Print!
  string systemCall = systemCallMappings[syscallNum];
  string redColoredSyscall = log.makeTextColored(Color::red, systemCall);
  log.writeToLog(Importance::inter,"[Pid %d] Intercepted %s\n", traceesPid,
                 redColoredSyscall.c_str());
  log.setPadding();

  bool callPostHook = callPreHook(syscallNum, myGlobalState, currState, tracer, myScheduler);

  if(kernelPre4_8){
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
    processSpawnEvents++;
    int status;
    ptraceEvent e;
    pid_t newPid;

    if(kernelPre4_8){
      // fork/vfork/clone pre system call.
      // On older version of the kernel, we would need to catch the pre-system call
      // event to forking system calls. This is event needs to be taken off the ptrace
      // queue so we do that here and simply ignore the event.
      tie(e, newPid, status) = getNextEvent(traceesPid, true);
      if(e != ptraceEvent::syscall){
        runtimeError("Expected pre-system call event after fork.");
      }
      // That was the pre-exit event, make sure we set onPreExitEvent to false.
      currState.onPreExitEvent = false;
    }
  }

  if(kernelPre4_8){
    // This is the seccomp event where we do the work for the pre-system call hook.
    // In older versions of seccomp, we must also do the pre-exit ptrace event, as we
    // have to. This is dictated by this variable.
    return true;
  }

  return callPostHook;
}
// =======================================================================================
void execution::handlePostSystemCall(state& currState){
  int syscallNum = tracer.getSystemCallNumber();

  // No idea what this system call is! error out.
  if(syscallNum < 0 || syscallNum > SYSTEM_CALL_COUNT){
    runtimeError("Unkown system call number: " +
                        to_string(syscallNum));
  }

  string syscallName = systemCallMappings[syscallNum];
  log.writeToLog(Importance::info,"Calling post hook for: " + syscallName + "\n");

  if (SYS_times == syscallNum || SYS_time == syscallNum) {
    // for syscalls with a nondet return value, print it at Importance::extra
    log.writeToLog(Importance::extra,"(nondet) Value before handler: %d\n",
                   tracer.getReturnValue());
  } else {
    log.writeToLog(Importance::info,"Value before handler: %d\n",
                   tracer.getReturnValue());
  }

  callPostHook(syscallNum, myGlobalState, currState, tracer, myScheduler);

  log.writeToLog(Importance::info,"Value after handler: %d\n",
                 tracer.getReturnValue());

  log.unsetPadding();
  return;
}
// =======================================================================================
void execution::handleSingleSyscall(pid_t nextPid){
  // We found a pid to do a syscall!
  myScheduler.addToRunnableQueue(nextPid);
    
  // We already know it's a seccomp event.
  // Go ahead and handle that.
  log.writeToLog(Importance::extra, "Is seccomp event!\n");
  systemCallsEvents++;

  // Prehook [seccomp event]
  states.at(nextPid).callPostHook = handleSeccomp(nextPid);
  // TODO: is this really dumb and unnecessary?
  bool postHook = states.at(nextPid).callPostHook;
 
  // Posthook [syscall event]
  if(postHook){
    int status;
    ptraceEvent retEvent;
    pid_t traceesPid;
    tie(retEvent, traceesPid, status) = getNextEvent(nextPid, postHook);
    if(retEvent != ptraceEvent::syscall){
      throw runtime_error("retEvent was not ptrace syscall!");
    }else{
      state& currentState = states.at(traceesPid);
      
      // old-kernel-only ptrace system call event for pre exit hook.
      if(kernelPre4_8 && currentState.onPreExitEvent){
        states.at(traceesPid).callPostHook = true;
        currentState.onPreExitEvent = false;
      }else{
        systemCallsEvents++;
        tracer.updateState(traceesPid);

        // Dealing with blocked syscalls, and replaying, and preempting
        // is all handled in handlePostSystemCall().
        int64_t signalToDeliver = states.at(traceesPid).signalToDeliver;
        states.at(traceesPid).signalToDeliver = 0;
        
        handlePostSystemCall(currentState);
        states.at(traceesPid).callPostHook = false;
        if(myScheduler.isInParallel(traceesPid)){
          doWithCheck(ptrace(PTRACE_CONT, traceesPid, 0, (void*) signalToDeliver),
                      "failed to PTRACE_CONT after posthook\n");
        }
      }
    }
  }else{
    // We don't need to do the posthook. We only need a subset of getNextEvent()
    // so we will only use a small part of it here.
    int64_t signalToDeliver = states.at(nextPid).signalToDeliver;
    states.at(nextPid).signalToDeliver = 0;
    
    // Do PTRACE_CONT to get the process going again.
    doWithCheck(ptrace(PTRACE_CONT, nextPid, 0, (void*) signalToDeliver),
                "failed to PTRACE_CONT after prehook (no posthook)\n");

    // Now that it has been restarted, remove it from either the runnableQueue and move it to 
    // parallelProcesses set.
    myScheduler.resumeParallel(nextPid);
  }
}
// =======================================================================================
void execution::runProgram(){
  log.writeToLog(Importance::inter, "dettrace starting up\n");

  // Once all processes have ended. We exit.
  // In waitOnAll() we find the next pid who wants to do a syscall.
  // It will return -1 when there are no processes left.
  
  bool exitLoop = false;
  
  while(!exitLoop){
    // Try everything currently in the runnableQueue. Each pid will either move back to
    // parallelProcesses, or move to the blockedQueue. Then reset: runnableQueue = blockedQueue,
    // and do a wait(-1).
  
    bool noRunnableProcs = myScheduler.emptyRunnableQueue();
    if(noRunnableProcs){
      pid_t nextPid = waitOnAll();
      if(nextPid == -1){
        // We are done.
        exitLoop = true;
      }else{
        myScheduler.addToRunnableQueue(nextPid); 
        continue;
      }
    }else{
      while(!myScheduler.emptyRunnableQueue()){
        pid_t frontPid = myScheduler.getNextRunnable();
        handleSingleSyscall(frontPid);      
      }
      myScheduler.swapQueues();
    }
  }

  // DEVRAND STEP 5: clean up /dev/[u]random fifo threads
  doWithCheck(pthread_cancel(devRandomPthread), "pthread_cancel /dev/random pthread");
  doWithCheck(pthread_cancel(devUrandomPthread), "pthread_cancel /dev/urandom pthread");

  auto msg =
    log.makeTextColored(Color::blue, "All processes done. Finished successfully!\n");
  log.writeToLog(Importance::info, msg);

  if(printStatistics){
    auto printStat =
      [&](string type, uint32_t value){
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
    printStat("Calls for scheduling next process: ", myScheduler.callsToScheduleNextStopped);
    printStat("Replays due to blocking system call: ", myGlobalState.replayDueToBlocking);
    printStat("Total replays: ", myGlobalState.totalReplays);
    printStat("ptrace peeks: ", tracer.ptracePeeks);
    printStat("process_vm_reads: ", tracer.readVmCalls);
    printStat("process_vm_writes: ", tracer.writeVmCalls);
  }

  if (!myGlobalState.liveThreads.empty()) {
    cerr << "Live thread set is not empty! We miss counted the threads somewhere..."
         << endl;
    exit(1);
  }

  if (!myGlobalState.threadGroups.empty()) {
    cerr << "threadGroups is not empty! We miss counted the threads somewhere..."
         << endl;
    exit(1);
  }

  // Add a check for states.empty(). Not adding it now since I don't want a bunch of packages.
  // to fail over this :b
}
// =======================================================================================
pid_t execution::waitOnAll(){
  pid_t nextPid = -1;
  bool seccompEvent = false;
  bool allProcsDone = false;
  
  while(!seccompEvent || !allProcsDone){
    log.writeToLog(Importance::info, "waiting on all potential processes!\n");

    if(myScheduler.emptyScheduler()) {
      // No more processes left!
      allProcsDone = true;
      nextPid = -1;
      continue;
    }else{
      int status = 0;
      nextPid = doWithCheck(waitpid(-1, &status, 0), "waitpid");
      
      if(nextPid == -1){
        runtimeError("wait(-1) errored for some reason in waitOnAll()\n");
      }

      ptraceEvent event = getPtraceEvent(status);
      if(event == ptraceEvent::seccomp){
        log.writeToLog(Importance::extra, "Is seccomp event!\n");
        systemCallsEvents++;
        seccompEvent = true;
        continue;
      }

      if(event == ptraceEvent::syscall){
        runtimeError("Should not be seeing syscall event in waitOnAll\n");
      }

      if(event == ptraceEvent::terminatedBySignal){
        auto msg =
          log.makeTextColored(Color::blue, "Process [%d] ended by signal %d.\n");
        log.writeToLog(Importance::inter, msg, nextPid, WTERMSIG(status));
        myScheduler.removeFromScheduler(nextPid);
        doWithCheck(ptracer::doPtrace(PTRACE_DETACH, nextPid, NULL, NULL),
                                      "failed to ptrace detach process in signal\n");
        continue;
      }

      // Process is about to exit.
      if(event == ptraceEvent::eventExit){
        auto msg = log.makeTextColored(Color::blue, "Process [%d] has finished. "
                                           "With ptraceEventExit.\n");
        log.writeToLog(Importance::inter, msg, nextPid);
        myScheduler.removeFromScheduler(nextPid); 

        doWithCheck(ptracer::doPtrace(PTRACE_DETACH, nextPid, NULL, NULL),
                                      "failed to ptrace detach process in eventExit\n");
        continue;
      }

      // TODO: may actually just never happen I don't know.
      // That's why I have these prints!
      // The process is fully dead. If it has not already been, remove
      // it from the scheduler.
      if(event == ptraceEvent::nonEventExit){
        auto msg = log.makeTextColored(Color::blue, "Process [%d] has completely exited (nonEvent).\n");
        log.writeToLog(Importance::inter, msg, nextPid);
        myScheduler.removeFromScheduler(nextPid);

        doWithCheck(ptracer::doPtrace(PTRACE_DETACH, nextPid, NULL, NULL),
                                      "failed to ptrace detach process in nonEvent\n");
        continue;
      }

      if(event == ptraceEvent::fork || event == ptraceEvent::vfork || event == ptraceEvent::clone){
        tracer.updateState(nextPid);
        int syscallNumber = (int)tracer.getSystemCallNumber();
        string msg = "none";

        // Per ptrace man page: we cannot reliably tell a clone syscall from it's event,
        // so we check explicitly.
        switch (syscallNumber) {
        case SYS_fork:
          msg = "fork";
          break;
        case SYS_vfork:
          msg = "vfork";
          break;
        case SYS_clone: {
          msg = "clone";
          break;
        }
        default:
          runtimeError("Unknown syscall number from fork/clone event: " +
                       to_string(syscallNumber));
        }

        log.writeToLog(Importance::inter,
                       log.makeTextColored(Color::blue, "[%d] caught %s event!\n"),
                       nextPid, msg.c_str());

        handleForkEvent(nextPid);
        states.at(nextPid).callPostHook = false;
        continue;
      }

      if(event == ptraceEvent::exec){
        log.writeToLog(Importance::inter,
                       log.makeTextColored(Color::blue, "[%d] Caught execve event!\n"),
                       nextPid);
        //reset CPUID trap flag
        states.at(nextPid).CPUIDTrapSet = false;

        handleExecEvent(nextPid);
        continue;
      }

      if(event == ptraceEvent::signal){
        log.writeToLog(Importance::inter,
                       log.makeTextColored(Color::blue, "[%d] Caught signal event!\n"),
                       nextPid);
        // TODO: ask joe if I should be handling signals
        //int signalNum = WSTOPSIG(status);
        //handleSignal(signalNum, traceesPid);
        continue;
      }

      runtimeError(to_string(nextPid) +
                        " Unknown return value for ptracer::getNextEvent()\n");
    }
  }
  return nextPid;
}
// =======================================================================================
void execution::handleForkEvent(const pid_t traceesPid){
  processSpawnEvents++;

  pid_t newChildPid = ptracer::getEventMessage(traceesPid);
  auto threadGroup = myGlobalState.threadGroupNumber.at(traceesPid);


  auto msg = log.makeTextColored(Color::blue, "Creating new thread group: %d\n");
  log.writeToLog(Importance::info, msg, newChildPid);

  // This should not happen! (Pid recycling?)
  if (myGlobalState.threadGroups.count(newChildPid) != 0) {
    runtimeError("Thread group already existed.\n");
  }

  // This is a process it owns it's own process group, create it.
  myGlobalState.threadGroups.insert({newChildPid, newChildPid});
  myGlobalState.threadGroupNumber.insert({newChildPid, newChildPid});

  // If a thread T1 spawns thread T2, then T1 is NOT the parent of T2. The parent is always
  // the process (the thread group leader) that T1 belongs to.
  // This is where we add new children to the thread group leader.
  processTree.insert(make_pair(threadGroup, newChildPid));

  // Share fdStatus. Processes get their own.
  // Deep Copy!
  unordered_map<int, descriptorType> fds = *states.at(threadGroup).fdStatus.get();
  states.emplace(newChildPid, state {newChildPid, debugLevel, fds});
  // Add this new process to our states.

  
  // Inherit file descriptor set from our parent.
  states.at(newChildPid).fdStatus = states.at(threadGroup).fdStatus;

  log.writeToLog(Importance::info,
                 log.makeTextColored(Color::blue,"Added process [%d] to states map.\n"),
                 newChildPid);

  // Once the child is ready for tracing, let it run in parallel until it wants to do
  // a system call. Inform the scheduler of its existance.
  myScheduler.addToParallelSet(newChildPid);

  // during fork, the parent's mmaped memory are COWed, as we set the mapping
  // attributes to MAP_PRIVATE. new child's `mmapMemory` hence must be inherited
  // from parent process, to be consistent with fork() semantic.
  // TODO for threads we may not need to do this?!
  states.at(newChildPid).mmapMemory.doesExist = true;
  states.at(newChildPid).mmapMemory.setAddr(states.at(traceesPid).mmapMemory.getAddr());

  // Wait for child to be ready.
  log.writeToLog(Importance::info, log.makeTextColored(Color::blue,
                 "Waiting for child to be ready for tracing...\n"));
  int status;
  int retPid = doWithCheck(waitpid(newChildPid, &status, 0), "waitpid");
  // This should never happen.
  if(retPid != newChildPid){
    runtimeError("wait call return pid does not match new child's pid.");
  }
  log.writeToLog(Importance::info,
                 log.makeTextColored(Color::blue, "Child ready!\n"));

  // Restart the child process. Let it run until it needs to do a syscall.
  doWithCheck(ptrace(PTRACE_CONT, newChildPid, 0, 0),
      "failed to ptrace_cont from handleForkEvent() for child\n");
  // Also restart the parent?
  doWithCheck(ptrace(PTRACE_CONT, traceesPid, 0, 0),
      "failed to ptrace_cont from handleForkEvent() for parent\n");
}

static inline unsigned long alignUp(unsigned long size, int align)
{
  return (size + align - 1) & ~(align -1);
}

void execution::disableVdso(pid_t pid) {
  struct ProcMapEntry vdsoMap, vvarMap;
  auto procMaps = parseProcMapEntries(pid);
  //procMaps = parseProcMapEntries(pid);

  memset(&vdsoMap, 0, sizeof(vdsoMap));
  memset(&vvarMap, 0, sizeof(vvarMap));

  for (auto ent: procMaps) {
    if (ent.procMapName == "[vdso]") {
      vdsoMap = ent;
    } else if (ent.procMapName == "[vvar]") {
      vvarMap = ent;
    } else {
    }
  }

  // vdso is enabled by kernel command line.
  if (vdsoMap.procMapBase != 0) {
    auto data = vdsoGetCandidateData();

    for (auto func: vdsoFuncs) {
      unsigned long offset, oldVdsoSize, vdsoAlignment;
      tie(offset, oldVdsoSize, vdsoAlignment) = func.second;
      unsigned long target  = vdsoMap.procMapBase + offset;
      unsigned long nbUpper = alignUp(oldVdsoSize, vdsoAlignment);
      unsigned long nb      = alignUp(data[func.first].size(), vdsoAlignment);
      assert(nb <= nbUpper);

      for (auto i = 0; i < nb / sizeof(long); i++) {
	uint64_t val;
	const unsigned char* z = data[func.first].c_str();
	unsigned long to = target + 8*i;
	memcpy(&val, &z[8*i], sizeof(val));
	ptracer::doPtrace(PTRACE_POKETEXT, pid, (void*)to, (void*)val);
      }

      unsigned long off = target + nb;
      unsigned long val = 0xccccccccccccccccUL;
      while (nb < nbUpper) {
	ptracer::doPtrace(PTRACE_POKETEXT, pid, (void*)off, (void*)val);
	off += sizeof(long);
	nb  += sizeof(long);
      }
      assert(nb == nbUpper);
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
    regs.rip += 1;      /* 0xcc; syscall(0x0f05); 0xcc */

    int status;

    ptracer::doPtrace(PTRACE_SETREGS, pid, 0, &regs);
    ptracer::doPtrace(PTRACE_CONT, pid, 0, 0);
    assert(waitpid(pid, &status, 0) == pid);
    assert(WIFSTOPPED(status) && WSTOPSIG(status) == SIGTRAP);
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
  assert(waitpid(pid, &status, 0) == pid);
  assert(WIFSTOPPED(status) && WSTOPSIG(status) == SIGTRAP);
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
  ptracer::doPtrace(PTRACE_POKETEXT, pid, (void*)rip, (void*)((saved_insn & ~0xffffffffUL) | stub));
  ptracer::doPtrace(PTRACE_CONT, pid, 0, 0);

  int status;
  assert(waitpid(pid, &status, 0) == pid);
  assert(WIFSTOPPED(status) && WSTOPSIG(status) == SIGTRAP);

  unsigned long mmapAddr = traceePreinitMmap(pid, tracer);

  disableVdso(pid);

  // TODO When does this ever happen?
  if (states.find(pid) == states.end()){
      states.emplace(pid, state {pid, debugLevel} );
  }
  // Reset file descriptor state, it is wiped after execve.
  states.at(pid).fdStatus = make_shared<unordered_map<int, descriptorType>>();

  states.at(pid).mmapMemory.doesExist = true;
  states.at(pid).mmapMemory.setAddr(traceePtr<void>((void*)mmapAddr));

  ptracer::doPtrace(PTRACE_POKETEXT, pid, (void*)rip, (void*)saved_insn);
  
  // Restart the stopped process.
  ptracer::doPtrace(PTRACE_CONT, pid, 0, 0);
}

// =======================================================================================
bool execution::handleSeccomp(const pid_t traceesPid){
  long syscallNum;
  ptracer::doPtrace(PTRACE_GETEVENTMSG, traceesPid, nullptr, &syscallNum);

  // TODO This might be totally unnecessary
  // INT16_MAX is sent by seccomp by convention as for system calls with no rules.
  if(syscallNum == INT16_MAX){
    // Fetch real system call from register.
    tracer.updateState(traceesPid);
    syscallNum = tracer.getSystemCallNumber();
    runtimeError("No filter rule for system call: " +
                        systemCallMappings[syscallNum]);
  }

  // TODO: Right now we update this information on every exit and entrance, as a
  // small optimization we might not want to...
  // Get registers from tracee.
  tracer.updateState(traceesPid);

  if(!states.at(traceesPid).CPUIDTrapSet && !myGlobalState.kernelPre4_12 && NULL == getenv("DETTRACE_NO_CPUID_INTERCEPTION")){
    //check if CPUID needs to be set, if it does, set trap
    trapCPUID(myGlobalState, states.at(traceesPid), tracer);
  }

  auto callPostHook = handlePreSystemCall( states.at(traceesPid), traceesPid );
  return callPostHook;
}
// =======================================================================================
void execution::handleSignal(int sigNum, const pid_t traceesPid){
  if(sigNum == SIGSEGV) {
    tracer.updateState(traceesPid);
    uint32_t curr_insn32;
    ssize_t ret = readVmTraceeRaw(traceePtr<uint32_t> ((uint32_t*)tracer.getRip().ptr),
                    &curr_insn32, sizeof(uint32_t), traceesPid);

    if (ret == -1) {
      runtimeError("Unable to read RIP for segfault. Cannot determine if rdtsc.\n");
    }


    if ((curr_insn32 << 16) == 0x310F0000 || (curr_insn32 << 8) == 0xF9010F00) {
      auto msg = "[%d] Tracer: Received rdtsc: Reading next instruction.\n";
      int ip_step = 2;

      if ((curr_insn32 << 8) == 0xF9010F00) {
        rdtscpEvents++;
        tracer.writeRcx(tscpCounter);
        tscpCounter++;
        ip_step = 3;
        msg = "[%d] Tracer: Received rdtscp: Reading next instruction.\n";
      }else{
        rdtscEvents++;
      }

      tracer.writeRax(tscCounter);
      tracer.writeRdx(0);
      tscCounter++;
      tracer.writeIp((uint64_t) tracer.getRip().ptr + ip_step);

      // Signal is now suppressed.
      states.at(traceesPid).signalToDeliver = 0;

      auto coloredMsg = log.makeTextColored(Color::blue, msg);
      log.writeToLog(Importance::inter, coloredMsg, traceesPid, sigNum);
      return;

    } else if ((curr_insn32 << 16) ==0xA20F0000) {
      struct user_regs_struct regs = tracer.getRegs();

      auto msg = "[%d] Tracer: intercepted cpuid instruction at %p. %rax == 0x%p, %rcx == 0x%p\n";
      auto coloredMsg = log.makeTextColored(Color::blue, msg);
      log.writeToLog(Importance::inter, coloredMsg, traceesPid, regs.rip, regs.rax, regs.rcx);

      // step over cpuid insn
      tracer.writeIp((uint64_t) tracer.getRip().ptr + 2);

      // suppress SIGSEGV from reaching the tracee
      states.at(traceesPid).signalToDeliver = 0;

      // fill in canonical cpuid return values

      switch (regs.rax) {
      case 0x0:
        tracer.writeRax( 0x00000002 ); // max supported %eax argument. Set to 4 to narrow support (IE Pentium 4).  For reference, Sandy Bridge has 0xD and Kaby Lake 0x16
        tracer.writeRbx( 0x756e6547 ); // "GenuineIntel" string
        tracer.writeRdx( 0x49656e69 );
        tracer.writeRcx( 0x6c65746e );
        //tracer.writeRcx( 0x6c6c6c6c ); // for debugging, returns "GenuineIllll" instead
        break;
      case 0x01: // basic features
        tracer.writeRax( 0x0 );
        tracer.writeRbx( 0x0 );
        tracer.writeRdx( 0x0 );
        tracer.writeRcx( 0x0 );
        break;
      case 0x02: // TLB/Cache/Prefetch Information
        // say that we have no caches, TLBs or prefetchers
        tracer.writeRax( 0x80000001 );
        tracer.writeRbx( 0x80000000 );
        tracer.writeRcx( 0x80000000 );
        tracer.writeRdx( 0x80000000 );
        break;
      case 0x03:
        tracer.writeRax( 0x0 );
        tracer.writeRbx( 0x0 );
        tracer.writeRdx( 0x0 );
        tracer.writeRcx( 0x0 );
        break;
      case 0x04:
        tracer.writeRax( 0x0 );
        tracer.writeRbx( 0x0 );
        tracer.writeRdx( 0x0 );
        tracer.writeRcx( 0x0 );
        break;
      case 0x80000000:
        tracer.writeRax( 0x80000000 );
        tracer.writeRbx( 0x0 );
        tracer.writeRdx( 0x0 );
        tracer.writeRcx( 0x0 );
        break;
      default:
        runtimeError("CPUID unsupported %eax argument");
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
bool execution::callPreHook(int syscallNumber, globalState& gs,
                            state& s, ptracer& t, scheduler& sched){
  switch(syscallNumber){
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

  case SYS_rt_sigaction:
    return rt_sigactionSystemCall::handleDetPre(gs, s, t, sched);

  case SYS_sendto:
    return sendtoSystemCall::handleDetPre(gs, s, t, sched);

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

  case SYS_write:
    return writeSystemCall::handleDetPre(gs, s, t, sched);

  case SYS_writev:
   return writevSystemCall::handleDetPre(gs, s, t, sched);
  }

  // Generic system call. Throws error.
  runtimeError("This is a bug. Missing case for system call: " +
                      to_string(syscallNumber));
  // Can never happen, here to avoid spurious warning.
  return false;
}
// =======================================================================================
void execution::callPostHook(int syscallNumber, globalState& gs,
                            state& s, ptracer& t, scheduler& sched){
  switch(syscallNumber){
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

  case SYS_rt_sigaction:
    return rt_sigactionSystemCall::handleDetPost(gs, s, t, sched);

  case SYS_sendto:
    return sendtoSystemCall::handleDetPost(gs, s, t, sched);

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

  case SYS_write:
    return writeSystemCall::handleDetPost(gs, s, t, sched);

  case SYS_writev:
   return writevSystemCall::handleDetPost(gs, s, t, sched);
  }

  // Generic system call. Throws error.
  runtimeError("This is a bug: "
                      "Missing case for system call: " +
                      to_string(syscallNumber));

}
// =======================================================================================
tuple<ptraceEvent, pid_t, int>
execution::getNextEvent(pid_t pidToContinue, bool ptraceSystemcall){
  // fprintf(stderr, "Getting next event for pid %d\n", pidToContinue);
  // 3rd return value of this function. Holds the status after waitpid call.
  int status = 0;
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
    log.writeToLog(Importance::extra, "getNextEvent(): Waiting for next system call event.\n");
    struct user_regs_struct regs;
    ptracer::doPtrace(PTRACE_GETREGS, pidToContinue, 0, &regs);
    // old glibc (2.13) calls (buggy) vsyscall for certain syscalls
    // such as time. this doesn't play along well with recent
    // kernels with seccomp-bpf support (4.4+)
    // for more details, see `Caveats` section of kernel document:
    // https://www.kernel.org/doc/Documentation/prctl/seccomp_filter.txt
    if ( (regs.rip & ~0xc00ULL) == 0xFFFFFFFFFF600000ULL) {
      log.writeToLog(Importance::extra, "getNextEvent(): Looking at VDSO in old glibc.\n");
      int status;
      int syscallNum = regs.orig_rax;
      // vsyscall seccomp stop is a special case
      // single step would cause the vsyscall exit fully
      // we cannot use `PTRACE_SYSCALL` as it wouldn't stop
      // at syscall exit like regular syscalls.
      ptracer::doPtrace(PTRACE_SINGLESTEP, pidToContinue, 0, (void*) signalToDeliver);
      // wait for our SIGTRAP
      // TODO check return value of this!!
      waitpid(pidToContinue, &status, 0);

      // call our post-hook manually for vsyscall stops.
      tracer.updateState(pidToContinue);

      // TODO this assumes we wanted to call the post-hook for this system call,
      // is this always true?
      callPostHook(syscallNum, myGlobalState, states.at(pidToContinue), tracer, myScheduler);

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

      ptracer::doPtrace(PTRACE_CONT, pidToContinue, 0, (void*) signalToDeliver);
    } else {
      doWithCheck(ptrace(PTRACE_SYSCALL, pidToContinue, 0, (void*) signalToDeliver),
                  "here at syscall!");
    }
  }else{
    log.writeToLog(Importance::extra, "getNextEvent(): Waiting at ptrace(CONT).\n");
    // Tell the process that we just intercepted an event for to continue, with us tracking
    // it's system calls. If this is the first time this function is called, it will be the
    // starting process. Which we expect to be in a waiting state.
    // doWithCheck(ptrace(PTRACE_CONT, pidToContinue, 0, (void*) signalToDeliver),
    //             "dettrace ptrace continue failed on " + to_string(pidToContinue) + "\n");
    doWithCheck(ptrace(PTRACE_CONT, pidToContinue, 0, (void*) signalToDeliver),
                "failed to PTRACE_CONT from getNextEvent()\n");
  }

  // Wait for next event to intercept.
  traceesPid = doWithCheck(waitpid(pidToContinue, &status, 0), "waitpid");
  log.writeToLog(Importance::extra, "getNextEvent(): Got event from waitpid().\n");

  return make_tuple(getPtraceEvent(status), traceesPid, status);
}
// =======================================================================================
ptraceEvent execution::getPtraceEvent(const int status){
  // Events ordered in order of likely hood.

  if( ptracer::isPtraceEvent(status, PTRACE_EVENT_SECCOMP) ){
    return ptraceEvent::seccomp;
  }

  // This is a stop caused by a system call exit-post.
  // All pre events are caught by seccomp.
  if(WIFSTOPPED(status) && (WSTOPSIG(status) == (SIGTRAP | 0x80)) ){
    return ptraceEvent::syscall;
  }

  // Check if tracee has exited.
  if (WIFEXITED(status)){
    log.writeToLog(Importance::extra, "nonEventExit\n");
    return ptraceEvent::nonEventExit;
  }

  // Condition for PTRACE_O_TRACEEXEC
  if( ptracer::isPtraceEvent(status, PTRACE_EVENT_EXEC) ){
    log.writeToLog(Importance::extra, "exec\n");
    return ptraceEvent::exec;
  }

  // Condition for PTRACE_O_TRACECLONE
  if( ptracer::isPtraceEvent(status, PTRACE_EVENT_CLONE) ){
    log.writeToLog(Importance::extra, "clone\n");
    return ptraceEvent::clone;
  }

  // Condition for PTRACE_O_TRACEVFORK
  if( ptracer::isPtraceEvent(status, PTRACE_EVENT_VFORK) ){
    log.writeToLog(Importance::extra, "vfork\n");
    return ptraceEvent::vfork;
  }

  // Even though fork() is clone under the hood, any time that clone is used with
  // SIGCHLD, ptrace calls that event a fork *sigh*.
  // Also requires PTRACE_O_FORK flag.
  if( ptracer::isPtraceEvent(status, PTRACE_EVENT_FORK) ){
    log.writeToLog(Importance::extra, "fork\n");
    return ptraceEvent::fork;
  }

#ifdef PTRACE_EVENT_STOP
  if( ptracer::isPtraceEvent(status, PTRACE_EVENT_STOP) ){
    log.writeToLog(Importance::extra, "event stop\n");
    runtimeError("Ptrace event stop.\n");
  }
#endif

  if( ptracer::isPtraceEvent(status, PTRACE_EVENT_EXIT) ){
    return ptraceEvent::eventExit;
  }

  // Check if we intercepted a signal before it was delivered to the child.
  if(WIFSTOPPED(status)){
    return ptraceEvent::signal;
  }

  // Check if the child was terminated by a signal. This can happen after when we,
  //the tracer, intercept a signal of the tracee and deliver it.
  if(WIFSIGNALED(status)){
    return ptraceEvent::terminatedBySignal;
  }

  runtimeError("Uknown event on dettrace::getNextEvent()");
  // Can never happen, here to avoid spurious warning.
  return ptraceEvent::nonEventExit;
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

void trapCPUID(globalState& gs, state& s, ptracer& t){
  gs.log.writeToLog(Importance::info, "Injecting arch_prctl call to tracee to intercept CPUID!\n");
  // Save current register state to restore after arch_prctl
  s.regSaver.pushRegisterState(t.getRegs());

  // Inject arch_prctl system call
  s.syscallInjected = true;

  // Call arch_prctl
  t.writeArg1(ARCH_SET_CPUID);
  t.writeArg2(0);

  uint16_t minus2 = t.readFromTracee(traceePtr<uint16_t>((uint16_t*) ((uint64_t) t.getRip().ptr - 2)), t.getPid());
  if (!(minus2 == 0x80CD || minus2 == 0x340F || minus2 == 0x050F)) {
    runtimeError("IP does not point to system call instruction!\n");
  }


  gs.totalReplays++;
  // Replay system call!
  t.changeSystemCall(SYS_arch_prctl);
  t.writeIp((uint64_t) t.getRip().ptr - 2);
  gs.log.writeToLog(Importance::info, "arch_prctl(%d, 0)\n", ARCH_SET_CPUID);
}

void deleteMultimapEntry(unordered_multimap<pid_t, pid_t>& mymap, pid_t key, pid_t value) {
    auto iterpair = mymap.equal_range(key);
    auto it = iterpair.first;
    for(; it != iterpair.second; ++it) {
      if(it->second == value) {
        mymap.erase(it);
        return;
      }
    }

    runtimeError("Unable to delete entry thread group entry for (" +
                        to_string(key) + ", " + to_string(value) + ")\n");
}

pair<bool, ptraceEvent> execution::loopOnWaitpid(pid_t currentPid) {
  // Threads may not respond to ptrace calls since it has exited. Check waitpid to see
  // if an exit status was delivered to us.
  int status;

  // Attempt blocking wait. Will error if thread no longer responds.
  if (waitpid(currentPid, &status, 0) != -1) {
    return make_pair(true, getPtraceEvent(status));
  } else {
    log.writeToLog(Importance::info, "Failed to hear from tracee through waitpid\n.");
    // dummy ptrace event, you should ignore this field on false.
    return make_pair(false, ptraceEvent::eventExit);
  }

  // It seems we don't actually need to poll like this: but we leave in case it is needed
  // in the future.
  log.writeToLog(Importance::info,
                 "Initial blocking waitpid failed, switching to polling?\n.");

  // Wait for event for N times.
  // TODO In the future a timeout-like event might be better than busy waiting.
  // for(int i = 0; i < 100000; i++){
  //   // Set function wide status here! Used at very end to report the correct message!
  //   int nextPid = waitpid(currentPid, &status, WNOHANG);
  //   if(nextPid == currentPid){
  //     done = true;
  //     auto msg = log.makeTextColored(Color::blue,
  //                  "Total calls to waitpid (ptrace syscall): %d\n");
  //     log.writeToLog(Importance::extra, msg, i + 1);
  //     break;
  //   } else if (nextPid == 0) {
  //     // Still looping hoping for event to come... continue.
  //     continue;
  //   } else {
  //     runtimeError("Unexpected return value from waitpid: " + to_string(nextPid));
  //   }
  // }

  // if (!done) {
  //   log.writeToLog(Importance::info, "Failed to hear from tracee through waitpid\n.");
  //   // dummy ptrace event, you should ignore this field on false.
  //   return make_pair(false, ptraceEvent::eventExit);
  // }

  // return make_pair(true, getPtraceEvent(status));
}
