#include "execution.hpp"
#include "dettrace.hpp"
#include "dettraceSystemCall.hpp"
#include "logger.hpp"
#include "ptracer.hpp"
#include "rnr_loader.hpp"
#include "scheduler.hpp"
#include "state.hpp"
#include "syscallStubs.hpp"
#include "systemCallList.hpp"
#include "util.hpp"
#include "utilSystemCalls.hpp"
#include "vdso.hpp"

#include <sys/utsname.h>
#include <stack>
#include <tuple>

#define MAKE_KERNEL_VERSION(x, y, z) ((x) << 16 | (y) << 8 | (z))

void deleteMultimapEntry(
    unordered_multimap<pid_t, pid_t>& mymap, pid_t key, pid_t value);
pid_t eraseChildEntry(multimap<pid_t, pid_t>& map, pid_t process);
bool kernelCheck(int a, int b, int c);

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
}
// =======================================================================================
// program exited with either EIFEXITED or WIFSIGNALED
// NB: should *not* do any ptrace(...) here.
//
// Notice it's the last-child-alive's job to schedule a finished parent to exit.
// If this is the  last-child-alive, but the parent is not marked as finished,
// that's fine, it still has more code to run, eventually it will spawn more
// children, or exit.

// This is the base case. You may, be wondering what happens if the
// currentProcess itself has children and got here, this can't happen. A process
// with live children will never get a nonEventExit.
void execution::handleNonEventExit(pid_t traceesPid, int exit_status) {
  this->exit_code = exit_status;
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
  }
  // This is the base case for any process, we have no children, and no parent
  // that we need to help exit.
  else {
    // Process done, schedule next process to run.
    myScheduler.removeAndScheduleNext(traceesPid);
  }
}

// during exit_group, threads with the group could have received
// a ptrace_event_exit first, see BUGS in ptrace(2).
static int await_non_event_exit(pid_t pid) {
  bool received_non_event_exit = false;
  int status, __exit_status;
  while (!received_non_event_exit) {
    VERIFY(waitpid(pid, &status, 0) == pid);
    if (WIFEXITED(status)) {
      __exit_status = WEXITSTATUS(status);
      received_non_event_exit = true;
    } else if (WIFSIGNALED(status)) {
      __exit_status = WTERMSIG(status) | 0x80;
      received_non_event_exit = true;
    } else if (
        status >> 16 == PTRACE_EVENT_EXIT &&
        (status & 0xff00) >> 8 == SIGTRAP) {
      // we received PTRACE_EVENT_EXIT, the next waitpid should return
      // exit_status.
      VERIFY(ptrace(PTRACE_CONT, pid, 0, 0) == 0);
    } else {
      std::string errmsg(
          "ptrace event exit, waitpid returned expected status: ");
      errmsg += to_string(status);
      runtimeError(errmsg);
    }
  }
  return __exit_status;
}

void execution::handlePtraceEventExit(pid_t traceesPid) {
  long __exit_status;
  ptracer::doPtrace(PTRACE_GETEVENTMSG, traceesPid, 0, (void*)&__exit_status);
  exit_code = (int)__exit_status;
  auto msg = log.makeTextColored(
      Color::blue,
      "Process [%d] has finished. "
      "With ptraceEventExit, exit_code: %d.");
  log.writeToLog(Importance::inter, msg, traceesPid, exit_code);

  bool isExitGroup = states.at(traceesPid).isExitGroup;
  states.at(traceesPid).isExitGroup = false;
  pid_t threadGroup = myGlobalState.threadGroupNumber.at(traceesPid);

  // Iterate through all threads in this exit group exiting them.
  // Only go in here for exit groups where there is threads. By default,
  // there is at least 1 (the process)
  log.writeToLog(
      Importance::info, "thread group #%d\n",
      myGlobalState.threadGroups.count(threadGroup));

  if (isExitGroup && myGlobalState.threadGroups.count(threadGroup) > 1) {
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
        // do a single step so that the next `waitpid` is guaranteed to
        // return instead of blocking.
        int ret = ptrace(PTRACE_SINGLESTEP, thread, 0, 0);
        VERIFY(ret == 0 || errno == ESRCH);
        continue;
      }

      auto msg = "Manually exiting thread %d after exit_group.\n";
      log.writeToLog(Importance::info, msg, thread);
      int status;

      int ret = ptrace(PTRACE_CONT, thread, 0, 0);
      // see BUGS in man 2 ptrace
      //
      // A  SIGKILL  signal  may  still cause a PTRACE_EVENT_EXIT stop before
      // actual signal death.  This may be changed in the future; SIGKILL is
      // meant to always immediately kill tasks even under ptrace.
      // Last confirmed on Linux 3.13.
      //
      // Apparently this applies to kernel 4.15 as well
      //
      VERIFY(ret == 0 || errno == ESRCH);
      handleNonEventExit(thread, await_non_event_exit(thread));
    }
  } else {
    // We have children still, we cannot exit.
    if (processTree.count(traceesPid) != 0) {
      myScheduler.markFinishedAndScheduleNext(traceesPid);
    }
    ptracer::doPtrace(PTRACE_CONT, traceesPid, 0, 0);
  }
}
// =======================================================================================
// Despite what the name will imply, this function is actually called during a
// ptrace seccomp event. Not a pre-system call event. In newer kernel version
// there is no need to deal with ptrace pre-system call events. So the only
// reason we refer to it here is for backward compatibility reasons.
bool execution::handlePreSystemCall(state& currState, pid_t traceesPid) {
  int syscallNum = tracer.getSystemCallNumber();

  if (syscallNum < 0 || syscallNum > SYSTEM_CALL_COUNT) {
    runtimeError("Unkown system call number: " + to_string(syscallNum));
  }

  string systemCall = systemCallMappings[syscallNum];
  string redColoredSyscall = log.makeTextColored(Color::red, systemCall);
  log.writeToLog(
      Importance::inter, "[Pid %d] Intercepted %s\n", traceesPid,
      redColoredSyscall.c_str());
  log.setPadding();

  bool callPostHook =
      callPreHook(syscallNum, myGlobalState, currState, tracer, myScheduler);

  if (sys_enter_hook && !currState.syscallInjected) {
    rnr::callPreHook(
        user_data, sys_enter_hook, syscallNum, myGlobalState, currState, tracer,
        myScheduler);
  }

  return kernelPre4_8 ? true : callPostHook;
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

  if (sys_exit_hook && !currState.syscallInjected) {
    rnr::callPostHook(
        user_data, sys_exit_hook, syscallNum, myGlobalState, currState, tracer,
        myScheduler);
  }

  log.writeToLog(
      Importance::info, "Value after handler: %d\n", tracer.getReturnValue());

  log.unsetPadding();
  return;
}

void execution::handleSeccompContinue(pid_t pid, bool is_ptrace_syscall) {
  long signalToDeliver = states.at(pid).signalToDeliver;
  states.at(pid).signalToDeliver = 0;
  auto log = myGlobalState.log;
  // Usually we use PTRACE_CONT below because we are letting seccomp + bpf
  // handle the events. So unlike standard ptrace, we do not rely on system call
  // events. Instead, we wait for seccomp events. Note that seccomp + bpf only
  // sends us (the tracer) a ptrace event on pre-system call events. Sometimes
  // we need the system call to be called and then we change it's arguments. So
  // we call PTRACE_SYSCALL instead.
  if (is_ptrace_syscall) {
    log.writeToLog(
        Importance::extra,
        "getNextEvent(): Waiting for next system call event.\n");
    struct user_regs_struct regs;
    ptracer::doPtrace(PTRACE_GETREGS, pid, 0, &regs);
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
      ptracer::doPtrace(PTRACE_SINGLESTEP, pid, 0, (void*)signalToDeliver);
      // wait for our SIGTRAP
      // TODO check return value of this!!
      VERIFY(waitpid(pid, &status, 0) == pid);

      // call our post-hook manually for vsyscall stops.
      tracer.updateState(pid);

      // TODO this assumes we wanted to call the post-hook for this system call,
      // is this always true?
      callPostHook(
          syscallNum, myGlobalState, states.at(pid), tracer, myScheduler);

      // TODO What's the point of this second updateState call?
      tracer.updateState(pid);

      // 000000000009efe0 <time@@GLIBC_2.2.5>:
      // 9efe0:       48 83 ec 08             sub    $0x8,%rsp
      // 9efe4:       48 c7 c0 00 04 60 ff    mov    $0xffffffffff600400,%rax
      // 9efeb:       ff d0                   callq  *%rax
      // 9efed:       48 83 c4 08             add    $0x8,%rsp
      // 9eff1:       c3                      retq
      //
      // our expected rip is @9eff1. must resume with `PTRACE_CONT`
      // since our vsyscall has been *emulated*

      ptracer::doPtrace(PTRACE_CONT, pid, 0, (void*)signalToDeliver);
    } else {
      ptracer::doPtrace(PTRACE_SYSCALL, pid, 0, (void*)signalToDeliver);
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
    ptracer::doPtrace(PTRACE_CONT, pid, 0, (void*)signalToDeliver);
  }
}

// ptrace event handler
// NB: every event handler *must* do proper PTRACE_CONT/PTRACE_SYSCALL
// to make sure tracee could make progress
// caller of `handlePtraceEvent` would call `waitpid` only.
void execution::handlePtraceEvent(pid_t pid, int status) {
  int signal = (status >> 8) & 0xff;
  int event = status >> 16;
  tracer.updateState(pid);

  switch (event) {
  case 0: {
    if (signal == (SIGTRAP | 0x80)) { // PTRACE_EVENT_SYSCALL
      handlePtraceSyscall(pid);
    } else {
      handleSignal(pid, signal);
    }
    break;
  }
  case PTRACE_EVENT_CLONE:
  case PTRACE_EVENT_FORK:
  case PTRACE_EVENT_VFORK: {
    unsigned long flags = (unsigned long)tracer.arg1();
    bool isThread = (flags & CLONE_THREAD) != 0;
    handleForkEvent(pid, isThread);
    break;
  }
  case PTRACE_EVENT_VFORK_DONE:
    ptracer::doPtrace(PTRACE_CONT, pid, 0, 0);
    break;
  case PTRACE_EVENT_EXIT:
    handlePtraceEventExit(pid);
    break;
  case PTRACE_EVENT_EXEC:
    handleExecEvent(pid);
    break;
  // ptrace group stop, shouldn't reach here because we're not
  // using PTRACE_SEIZE.
  case PTRACE_EVENT_STOP: {
    string errmsg("unexpected PTRACE_EVENT_STOP from pid ");
    errmsg += to_string(pid);
    runtimeError(errmsg);
    break;
  }
  case PTRACE_EVENT_SECCOMP:
    systemCallsEvents++;
    handleSeccomp(pid);
    break;
  default: {
    std::string errmsg(__func__);
    errmsg += ": unknown ptrace event: ";
    errmsg += to_string(event);
    runtimeError(errmsg);
  }
  }
}

// =======================================================================================
int execution::runProgram() {
  log.writeToLog(Importance::inter, "dettrace starting up\n");
  pid_t pid;

  // Iterate over entire process' and all subprocess' execution.
  while ((pid = myScheduler.getNext()) != -1) {
    int status;

    // Ideally this should be the only `waitpid` to wait tracee
    // however, there're many corner cases. Despite that, we should
    // consider the mainloop always do `waitpid` to await tracee
    // (progress), as a result, every event handler here must
    // guarantee tracee could make progress.
    // for ptrace event (including signal devlier), this means
    // each handler must make sure proper `PTRACE_CONT` is called.
    VERIFY(waitpid(pid, &status, 0) == pid);

    if (WIFEXITED(status)) { // exited, *not* ptrace_exit_event.
      handleNonEventExit(pid, WEXITSTATUS(status));
    } else if (WIFSIGNALED(status)) { // terminated by signal
      handleNonEventExit(pid, WTERMSIG(status) | 0x80);
    } else if (WIFSTOPPED(status)) { // ptrace stops
      handlePtraceEvent(pid, status);
    } else { //
      string errmsg("waitpid(");
      errmsg += to_string(pid);
      errmsg += ") returned unexpect status: ";
      errmsg += to_string(status);
      runtimeError(errmsg);
    }
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
pid_t execution::handleForkEvent(pid_t traceesPid, bool isThread) {
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

  // Wait for child to be ready.
  log.writeToLog(
      Importance::info,
      log.makeTextColored(
          Color::blue, "Waiting for child to be ready for tracing...\n"));
  int status;
  VERIFY(waitpid(newChildPid, &status, 0) == newChildPid);
  VERIFY(WIFSTOPPED(status) && WSTOPSIG(status) == SIGSTOP);
  log.writeToLog(
      Importance::info, log.makeTextColored(Color::blue, "Child ready!\n"));

  ptracer::doPtrace(PTRACE_CONT, newChildPid, 0, 0);

  // This is a bit tricky here, as mentioned in `runProgram`, each event
  // handler (ptrace) must call proper `PTRACE_CONT`, for fork families
  // we could return two tasks, but dettrace must sequencialize task
  // execution, as a result, we should only single step parent (or child)
  // so that only a single task is in *running* state.
  // we do a `PTRACE_SINGLESTEP` here so that next `waitpid` in `runProgram`
  // can return a new status (instead of blocking).
  ptracer::doPtrace(PTRACE_SINGLESTEP, traceesPid, 0, 0);

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

// =======================================================================================
static void trapCPUID(globalState& gs, state& s, ptracer& t) {
  SyscallArgs args(ARCH_SET_CPUID, 0);
  long retval = injectSystemCall(t.getPid(), SYS_arch_prctl, args);
  if (retval != 0) {
    string errmsg("cpuid interception (cpuid_fault) via arch_prctl failed: ");
    errmsg += strerror(-t.getReturnValue());
    errmsg += "\nPlease check `cpuid_fault` flag from `cat /proc/cpuinfo`";
    gs.log.writeToLog(Importance::inter, errmsg);
    gs.allow_trapCPUID = false;
  } else {
    gs.allow_trapCPUID = true;
  }
}

static unsigned long traceePreinitMmap(pid_t pid, ptracer& t) {
  struct user_regs_struct regs;
  unsigned long ret;

  ptracer::doPtrace(PTRACE_GETREGS, pid, 0, &regs);
  auto oldRegs = regs;

  regs.orig_rax = SYS_mmap;
  regs.rax = SYS_mmap;
  // mmap two fixed pages @0x7000_0000
  // 0x7000_0000 -- 0x7000_1000 is used for syscall stubs
  //   perm: r-xp
  // 0x7000_1000 -- 0x7000_2000 is used for dettrace mmap page
  //   perm: rwxp
  regs.rdi = SYSCALL_STUB_PAGE_START;
  regs.rsi = 0x2000; // keep syscall stubs and mmap page together, 4KB each.
  regs.rdx = PROT_READ | PROT_WRITE | PROT_EXEC;
  regs.r10 = MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED;
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

  /**
   * 0:   0f 05           syscall
   * 2:   c3              retq          ; not filered by seccomp,
   * untraced_syscall 3:   90              nop 4:   0f 05           syscall ;
   * traced syscall 6:   c3              retq 7:   90              nop 8:   e8
   * f3 ff ff ff  callq  0 <_do_syscall>      ; untraced syscall, then
   * breakpoint. d:   cc              int3 e:   66 90           xchg   %ax,%ax
   * 10:  e8 ef ff ff ff  callq  4 <_do_syscall+0x4>  ; traced syscall, then
   * breakpoint 15:  cc              int3 16:  66 90           xchg   %ax,%ax
   */
  unsigned long injected_insns[] = {
      0x90c3050f90c3050fUL,
      0x9066ccfffffff3e8UL,
      0x9066ccffffffefe8UL,
  };

  for (int i = 0; i < sizeof(injected_insns) / sizeof(injected_insns[0]); i++) {
    ptracer::doPtrace(
        PTRACE_POKEDATA, pid,
        (void*)(SYSCALL_STUB_PAGE_START + sizeof(unsigned long) * i),
        (void*)injected_insns[i]);
  }

  // use the 2nd page for mmapedMemory, which length is set to 2048B in
  // state.cpp constr.
  return ret + 0x1000;
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

  states.at(pid).mmapMemory.setAddr(traceePtr<void>((void*)mmapAddr));

  SyscallArgs args(
      SYSCALL_STUB_PAGE_START, SYSCALL_STUB_PAGE_SIZE, PROT_READ | PROT_EXEC);
  // make sure syscall stubs is read only.
  VERIFY(injectSystemCall(pid, SYS_mprotect, args) == 0);
  if (myGlobalState.allow_trapCPUID) {
    if (!states.at(pid).CPUIDTrapSet && !myGlobalState.kernelPre4_12 &&
        NULL == getenv("DETTRACE_NO_CPUID_INTERCEPTION")) {
      // check if CPUID needs to be set, if it does, set trap
      trapCPUID(myGlobalState, states.at(pid), tracer);
    }
  }
  ptracer::doPtrace(PTRACE_POKETEXT, pid, (void*)rip, (void*)saved_insn);
  ptracer::doPtrace(PTRACE_CONT, pid, 0, 0);
}

// =======================================================================================
void execution::handleSeccomp(pid_t traceesPid) {
  unsigned long seccomp_data;
  ptracer::doPtrace(PTRACE_GETEVENTMSG, traceesPid, nullptr, &seccomp_data);

  VERIFY(seccomp_data != (unsigned long)INT16_MAX);

  // TODO: Right now we update this information on every exit and entrance, as a
  // small optimization we might not want to...
  // Get registers from tracee.
  tracer.updateState(traceesPid);

  auto callPostHook = handlePreSystemCall(states.at(traceesPid), traceesPid);

  handleSeccompContinue(traceesPid, callPostHook);
}

void execution::handlePtraceSyscall(pid_t pid) {
  // For older kernels, we see a system call event and we also see a handle
  // seccomp event. I chose to always handle the pre-system call on the
  // ptracer seccomp event. So we skip the pre-system call event here on
  // older kernels.
  state& currentState = states.at(pid);

  // old-kernel-only ptrace system call event for pre exit hook.
  if (kernelPre4_8 && currentState.onPreExitEvent) {
    currentState.callPostHook = true;
    currentState.onPreExitEvent = false;
  } else {
    // Only count here due to comment above (we see this event twice in
    // older kernels).
    systemCallsEvents++;
    tracer.updateState(pid);
    handlePostSystemCall(currentState);
    // set callPostHook to default value for next iteration.
    currentState.callPostHook = false;
  }
  ptracer::doPtrace(PTRACE_CONT, pid, 0, 0);
}

void execution::handleSignalDelivery(pid_t traceesPid, int signal) {
  // Remember to deliver this signal to the tracee for next event! Happens in
  // getNextEvent.
  states.at(traceesPid).signalToDeliver = signal;

  auto msg = "[%d] Tracer: Received signal: %d. Forwarding signal to tracee.\n";
  auto coloredMsg = log.makeTextColored(Color::blue, msg);
  log.writeToLog(Importance::inter, coloredMsg, traceesPid, signal);
}

void execution::handleBreakpoint(
    pid_t traceesPid, const struct user_regs_struct& regs) {}

void execution::handleRdtscs(pid_t pid, bool is_rdtscp) {
  auto msg = "[%d] Tracer: Received rdtsc: Reading next instruction.\n";
  int ip_step = is_rdtscp ? 3 : 2;

  if (is_rdtscp) {
    rdtscpEvents++;
    tracer.writeRcx(
        tscpCounter); // XXX: IA32_TSC_AUX: this should be logical core instead.
    tscpCounter += RDTSC_STEPPING;
    msg = "[%d] Tracer: Received rdtscp: Reading next instruction.\n";
  } else {
    rdtscEvents++;
  }

  tracer.writeRax(tscCounter & 0xffffffffUL);
  tracer.writeRdx(tscCounter >> 8);
  tscCounter += RDTSC_STEPPING;

  tracer.writeIp((uint64_t)tracer.getRip().ptr + ip_step);

  auto coloredMsg = log.makeTextColored(Color::blue, msg);
  log.writeToLog(Importance::inter, coloredMsg, pid);
}

void execution::handleCpuid(pid_t pid, const struct user_regs_struct& regs) {
  struct CPUIDRegs {
    unsigned eax;
    unsigned ebx;
    unsigned ecx;
    unsigned edx;
  };

  // clang-format off
  const struct CPUIDRegs cpuids[] =
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

  const struct CPUIDRegs extended_cpuids[] =
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

  auto msg =
      "[%d] Tracer: intercepted cpuid instruction at %p. %rax == %p, %rcx "
      "== %p\n";
  auto coloredMsg = log.makeTextColored(Color::blue, msg);
  log.writeToLog(
      Importance::inter, coloredMsg, pid, regs.rip, regs.rax,
      regs.rcx);

  // step over cpuid insn
  tracer.writeIp((uint64_t)tracer.getRip().ptr + 2);

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
}
// =======================================================================================
void execution::handleSignal(pid_t traceesPid, int signal) {
  tracer.updateState(traceesPid);
  states.at(traceesPid).signalToDeliver = 0;
  struct user_regs_struct regs = tracer.getRegs();  // updated by `updateState`.

  if (signal == SIGSEGV) {
    unsigned long insn = ptracer::doPtrace(PTRACE_PEEKTEXT, traceesPid, (void*)regs.rip, 0);
    if ( (insn & 0xffffUL) == 0x310fUL) {
      handleRdtscs(traceesPid, false);
    } else if ( (insn & 0xffffffUL) == 0xf9010fUL) {
      handleRdtscs(traceesPid, true);
    } else if ( (insn & 0xffffUL) == 0xa20fUL) {
      handleCpuid(traceesPid, regs);
    } else {
      handleSignalDelivery(traceesPid, signal);
    }
    VERIFY(ptrace(PTRACE_CONT, traceesPid, 0, 0) == 0);
  } else if (signal == SIGTRAP) {
    handleBreakpoint(traceesPid, regs);
    VERIFY(ptrace(PTRACE_CONT, traceesPid, 0, 0) == 0);
  } else {
    handleSignalDelivery(traceesPid, signal);
    VERIFY(ptrace(PTRACE_CONT, traceesPid, 0, (void*)(long)signal) == 0);
  }
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

  case SYS_clock_nanosleep:
    return clock_nanosleepSystemCall::handleDetPre(gs, s, t, sched);

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

  case SYS_clock_nanosleep:
    return clock_nanosleepSystemCall::handleDetPost(gs, s, t, sched);

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
