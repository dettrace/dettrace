#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/utsname.h>
#include <sys/ioctl.h>
#include <fcntl.h>              /* Obtain O_* constant definitions */
#include <inttypes.h>
#include <sys/times.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <sys/syscall.h>

#include <limits>
#include <cstring>

#include <sys/time.h>
#include <sys/resource.h>
#include <sys/sysinfo.h>
#include <sys/uio.h>
#include <linux/futex.h>
#include <linux/fs.h>
#include <sys/types.h>
#include <utime.h>

#include <asm/prctl.h>
#include <sys/prctl.h>

#include <unordered_map>

#include "dettraceSystemCall.hpp"
#include "ptracer.hpp"


// Enable tracee reads that are not strictly necessary for functionality, but
// are enabled for instrumentation or sanity checking. For example, verify,
// before system call replay, that RIP points at a valid system call insn.
#define EXTRANEOUS_TRACEE_READS 0

using namespace std;
// =======================================================================================
// Prototypes for common functions.
void zeroOutStatfs(struct statfs& stats);
void handleStatFamily(globalState& gs, state& s, ptracer& t, string syscallName);
void printInfoString(uint64_t addressOfCString, globalState& gs, state& s, ptracer& t,
                     string postFix = " path: ");
void injectFstat(globalState& gs, state& s, ptracer& t, int fd);
void injectPause(globalState& gs, state& s, ptracer& t);

pair<int,int> getPipeFds(globalState& gs, state& s, ptracer& t);

static void replaceSystemCallWithNoop(globalState& gs, state& s, ptracer& t);
static bool sendTraceeSignalNow(int signum, globalState& gs, state& s, ptracer& t, scheduler& sched);

/**
 *
 * newfstatat is a stat variant with a "at" for using a file descriptor to a directory
 * to prepend to the relative path. For several system calls that delete a file e.g.
 * rename, renameat, renameat2,  we intercept them and make the original call a noop.
 * This is needed as once we hit the post-hook it is too late to call newfstatat.

 * This function does all the work to "switch out" the current system call and convert it
 * to newfstatat, only if needed, that is, based on whether this is the "first try" for
 * the current system call, or our replay done _after_ we have already injected newfstatat.
 *
 * returns true if the system call is to be injected, otherwise false.
 */
bool injectNewfstatatIfNeeded(globalState& gs, state& s, ptracer& t, int dirfd,
                              char* pathnameTraceesMem);
void removeInodeFromMaps(ino_t inode, globalState& gs, ptracer& t);
// =======================================================================================
/**
 *
 * Replays system call if the value of errnoValue is equal to the errno value that the libc
 * call would have returned. Also logs event in logger. For example for read:
 *   replaySyscallIfBlocked(s, t, sched, EAGAIN);
 *
 * @return: true if call was replayed, else false.
 */
bool replaySyscallIfBlocked(globalState& gs, state& s, ptracer& t,
                            scheduler& sched, int64_t errnoValue);
bool preemptIfBlocked(globalState& gs, state& s, ptracer& t, scheduler& sched,
                      int64_t errornoValue);
// =======================================================================================
bool accessSystemCall::handleDetPre(globalState& gs, state& s, ptracer& t, scheduler& sched){
  printInfoString(t.arg1(), gs, s, t);
  return true;
}
// =======================================================================================
bool arch_prctlSystemCall::handleDetPre(globalState& gs, state& s, ptracer& t, scheduler& sched){

  gs.log.writeToLog(Importance::info, "pre-hook for arch_prctl(%d, 0) == ARCH_SET_CPUID? %d\n", t.arg1(), t.arg1() == ARCH_SET_CPUID);

  switch (t.arg1()) {
  case ARCH_SET_CPUID:
    return true;
  case ARCH_SET_FS: // getting/setting these segment registers is reproducible, we don't need to intercept post-hook
  case ARCH_GET_FS:
  case ARCH_SET_GS:
  case ARCH_GET_GS:
    return false;
  default:
    throw runtime_error("dettrace runtime exception: unsupported arch_prctl syscall");
  }
  return false; // unreachable
}
void arch_prctlSystemCall::handleDetPost(globalState& gs, state& s, ptracer& t, scheduler& sched){
  if (s.syscallInjected)
  {
    gs.log.writeToLog(Importance::info, "post-hook for arch_prctl, returning %d\n", t.getReturnValue());

    if (!s.CPUIDTrapSet) {
      s.syscallInjected = false;
      s.CPUIDTrapSet = true;

      // restore reg state
      // I don't believe arch_prctl(ARCH_SET_CPUID) writes to tracee memory at all
      t.setRegs(s.regSaver.popRegisterState());

      gs.log.writeToLog(Importance::info, "restored register state from access() post-hook\n");
    }

    replaySystemCall(gs, t, t.getSystemCallNumber());
  }

}
// =======================================================================================
bool alarmSystemCall::handleDetPre(globalState& gs, state& s, ptracer& t, scheduler& sched){
  gs.log.writeToLog(Importance::info, "alarm pre-hook, requesting alarm in %u second(s)\n", t.arg1());
  // run post-hook if necessary
  return sendTraceeSignalNow(SIGALRM, gs, s, t, sched);
}
// =======================================================================================
bool chdirSystemCall::handleDetPre(globalState& gs, state& s, ptracer& t, scheduler& sched){
  printInfoString(t.arg1(), gs, s, t);

  return false;
}
// =======================================================================================
bool chmodSystemCall::handleDetPre(globalState& gs, state& s, ptracer& t, scheduler& sched){
  printInfoString(t.arg1(), gs, s, t);
  return false;
}
// =======================================================================================
bool chownSystemCall::handleDetPre(globalState& gs, state& s, ptracer& t, scheduler& sched){
  printInfoString(t.arg1(), gs, s, t);
  return false;
}
// =======================================================================================
void clock_gettimeSystemCall::handleDetPost(globalState& gs, state& s, ptracer& t, scheduler& sched) {
  gs.timeCalls++;
  struct timespec* tp = (struct timespec*) t.arg2();

  if (tp != nullptr) {
    struct timespec myTp = {};
    // TODO: One day, unify time.
    myTp.tv_sec = s.getLogicalTime();
    myTp.tv_nsec = 0;

    t.writeToTracee(traceePtr<struct timespec>(tp), myTp, t.getPid());
    s.incrementTime();
  }

  return;
}
// =======================================================================================
void closeSystemCall::handleDetPost(globalState& gs, state& s, ptracer& t, scheduler& sched){
  int fd = (int) t.arg1();
  // Remove entry from our direEntries.
  auto result = s.dirEntries.find(fd);
  // Exists.
  if(result != s.dirEntries.end()){
    gs.log.writeToLog(Importance::info, "Removing directory entries for fd: %d!\n", fd);
    s.dirEntries.erase(result);
  }

  // Remove entry from our fd set for pipes.
  if(s.fdStatus.count(fd) != 0){
    gs.log.writeToLog(Importance::info, "Removing pipe fd: %d!\n", fd);
    s.fdStatus.erase(fd);
  }
}
// =======================================================================================
// TODO
bool connectSystemCall::handleDetPre(globalState& gs, state& s, ptracer& t, scheduler& sched){
  return true;
}

void connectSystemCall::handleDetPost(globalState& gs, state& s, ptracer& t, scheduler& sched){
  return;
}
// =======================================================================================
bool creatSystemCall::handleDetPre(globalState& gs, state& s, ptracer& t, scheduler& sched){
  printInfoString(t.arg1(), gs, s, t);
  return true;
}

void creatSystemCall::handleDetPost(globalState& gs, state& s, ptracer& t, scheduler& sched){
  // Nothing for us to do skip the post hook!
  if((int) t.getReturnValue() < 0){
    return;
  }

  // Inject fstat, creat always make a new file with write permissions.
  injectFstat(gs, s, t, t.getReturnValue());
  return;
}
// =======================================================================================
void dupSystemCall::handleDetPost(globalState& gs, state& s, ptracer& t, scheduler& sched){
  int newfd = (int) t.getReturnValue();
  int fd =  (int) t.arg1();
  if(newfd < 0){
    return;
  }

  // dup succeeded.
  if(s.fdStatus.count(fd) != 0){ // Only for pipes
    s.fdStatus[newfd] = s.fdStatus[fd]; // copy over status.
    gs.log.writeToLog(Importance::info, "%d = dup(%d)\n", newfd, fd);
  }
}
// =======================================================================================
void dup2SystemCall::handleDetPost(globalState& gs, state& s, ptracer& t, scheduler& sched){
  int newfd = (int) t.getReturnValue();
  int fd =  (int) t.arg1();
  if(newfd < 0){
    return;
  }

  // dup2 succeeded.
  if(s.fdStatus.count(fd) != 0){ // Only for pipes

    // Semantics of dup2 say old fd could be closed and overwritten, we do that
    // implicitly here!
    s.fdStatus[newfd] = s.fdStatus[fd]; // copy over status.
    gs.log.writeToLog(Importance::info, "%d = dup2(%d)\n", newfd, fd);
  }
}

// =======================================================================================
bool execveSystemCall::handleDetPre(globalState& gs, state& s, ptracer& t, scheduler& sched){
  printInfoString(t.arg1(), gs, s, t);

  char** argv = (char**) t.arg2();
  string execveArgs {};

  // Print all arguments to execve!
  if(gs.log.getDebugLevel() > 0 && argv != nullptr){
    // Remeber these are addresses in the tracee. We must explicitly read them
    // ourselves!
    for(int i = 0; true; i++){
      // Make sure it's non null before reading to string.
      char* address = t.readFromTracee(traceePtr<char*>(&(argv[i])), t.getPid());
      if(address == nullptr){
        break;
      }

      execveArgs += " \"" + t.readTraceeCString(traceePtr<char>(address), t.getPid()) + "\" ";
    }

    auto msg = "Args: " + gs.log.makeTextColored(Color::green, execveArgs) + "\n";
    gs.log.writeToLog(Importance::info, msg);
  }

  return true;
}
void execveSystemCall::handleDetPost(globalState& gs, state& s, ptracer& t, scheduler& sched){
  gs.log.writeToLog(Importance::info, "in execve post-hook\n");

  // this will cause us to inject the appropriate prctl incantation on the next
  // access() system call TODO: this is a *HUGE* hack, only checking on
  // access(), but empirically it seems that access() often happens right after
  // the exec and this is easier to implement than checking in every system call
  // (I'm not sure how to plumb things through the superclass).
  s.CPUIDTrapSet = false;
}

// =======================================================================================
bool fchownatSystemCall::handleDetPre(globalState& gs, state& s, ptracer& t, scheduler& sched){
  printInfoString(t.arg2(), gs, s, t);

  // int dirfd = t.arg1();
  // uid_t owner = t.arg3();
  // gid_t group = t.arg4();
  // int flags = t.arg5();
  // string fchowatStr = "fchownat(fd = %d, _, owner = %d, group = %d, flags = %d)\n";
  // s.log.writeToLog(Importance::extra, fchowatStr, dirfd, owner, group, flags);
  return false;
}
// =======================================================================================
void fcntlSystemCall::handleDetPost(globalState& gs, state& s, ptracer& t, scheduler& sched){
  int retval = t.getReturnValue();
  if(retval != 0){
    return;
  }

  int fd = t.arg1();
  int cmd = t.arg2();
  int arg = t.arg3();
  if(cmd == F_DUPFD || cmd == F_DUPFD_CLOEXEC){
    auto str = "found fcntl(%d, FDUPFD || F_DUPFD_CLOCEXEC) = %d\n";
    int newfd = retval;
    gs.log.writeToLog(Importance::info, str, fd, newfd);
    // Same status as what it was duped from.
    auto newStatus = s.fdStatus[fd];
    s.fdStatus[newfd] = newStatus;
  }
  // User attempting to change blocked status.
  if(cmd == F_SETFL && ((arg & O_NONBLOCK) != 0)){
    auto str = "found fcntl setting %d to non blocking!\n";
    if(s.fdStatus.count(fd) != 0){
      gs.log.writeToLog(Importance::info, str, fd);
      s.fdStatus[fd] = descriptorType::nonBlocking;
    }else{
      gs.log.writeToLog(Importance::info, str, fd);
      gs.log.writeToLog(Importance::info, "But this is not a pipe... ignoring.\n");
    }
  }
}
  // =======================================================================================
bool faccessatSystemCall::handleDetPre(globalState& gs, state& s, ptracer& t,
                                       scheduler& sched){
  printInfoString(t.arg2(), gs, s, t);

  return false;
}
// =======================================================================================
void fgetxattrSystemCall::handleDetPost(globalState& gs, state& s, ptracer& t,
                                        scheduler& sched){
  printInfoString(t.arg2(), gs, s, t);

  return;
}
// =======================================================================================
void flistxattrSystemCall::handleDetPost(globalState& gs, state& s, ptracer& t,
                                         scheduler& sched){
  printInfoString(t.arg2(), gs, s, t);

  return;
}
// =======================================================================================
bool fstatSystemCall::handleDetPre(globalState& gs, state& s, ptracer& t, scheduler& sched){
  gs.log.writeToLog(Importance::info, "fstat(fd=%d)\n", t.arg1());
  return true;
}
void fstatSystemCall::handleDetPost(globalState& gs, state& s, ptracer& t, scheduler& sched){

  // This isn't a natural call fstat from the tracee we injected this call ourselves!
  if(s.syscallInjected){
    gs.log.writeToLog(Importance::info, "This fstat was inject for mtime puposes.\n");
    if((int) t.getReturnValue() < 0){
      throw runtime_error("dettrace runtime exception: Unable to properly inject fstat call to tracee!\n"
                          "fstat call returned: " +
                          to_string(t.getReturnValue()) + "\n");
    }
    s.syscallInjected = false;
    gs.log.writeToLog(Importance::info, "reading struct stat from %p\n", (void*)t.arg2());
    struct stat myStat = t.readFromTracee(traceePtr<struct stat>((struct stat*) t.arg2()), s.traceePid);

    gs.log.writeToLog(Importance::extra, "(device,inode) = (%lu,%lu)\n", myStat.st_dev, myStat.st_ino);

    // Add an entry for this new file to our inode with a newer modified date.
    if( ! gs.mtimeMap.realValueExists(myStat.st_ino) ){
      gs.mtimeMap.addRealValue(myStat.st_ino);
    }

    // Previous state that should have been set by system call that created this fstat
    // injection.
    t.setRegs(s.regSaver.popRegisterState());
  }else{
    handleStatFamily(gs, s, t, "fstat");
  }

  return;
}
// =======================================================================================
void fstatfsSystemCall::handleDetPost(globalState& gs, state& s, ptracer& t, scheduler& sched){
  struct statfs* statfsPtr = (struct statfs*) t.arg2();

  if(statfsPtr == nullptr){
    gs.log.writeToLog(Importance::info, "fstatfs: statfsbuf null.\n");
    return;
  }

  if(t.getReturnValue() == 0){
    // Read values written to by system call.

    // jld: filling in myStatfs from tracee memory does not seem to be used at
    // all, as zeroOutStatfs() overwrites all its fields.
    struct statfs myStatfs; //= t.readFromTracee(traceePtr<struct statfs>(statfsPtr), s.traceePid);

    // Assume we're using this file sytem?
    zeroOutStatfs(myStatfs);

    // Write back result for child.
    t.writeToTracee(traceePtr<struct statfs>(statfsPtr), myStatfs, s.traceePid);
  }

  return;
}
// =======================================================================================
bool futexSystemCall::handleDetPre(globalState& gs, state& s, ptracer& t, scheduler& sched){
  // If operation is a FUTEX_WAIT, set timeout to zero for polling instead of blocking.
  int futexOp = t.arg2();
  int futexValue = t.arg3();
  timespec* timeoutPtr = (timespec*) t.arg4();
  string operation;

  try{
     operation = futexNames.at(futexOp);
  }catch(...){
    // Uknown operation? Pehaps a combination of multiple non trivial options.
    operation = to_string(futexOp);
  }

  gs.log.writeToLog(Importance::extra, "Futex operation: " + operation + "\n");

  // See definitions of variables here.
  // https://github.com/spotify/linux/blob/master/include/linux/futex.h
  int futexCmd = futexOp & FUTEX_CMD_MASK;

  // Handle wake operations by notifying scheduler of progress.
  if(futexCmd == FUTEX_WAKE || futexCmd == FUTEX_REQUEUE || futexCmd == FUTEX_CMP_REQUEUE ||
     futexCmd == FUTEX_WAKE_BITSET || futexCmd == FUTEX_WAKE_OP){
    sched.reportProgress(t.getPid());
    gs.log.writeToLog(Importance::info, "Waking on address: %p\n", t.arg1());
    // No need to go into the post hook.
    return false;
  }

  // Handle wait operations, by setting our timeout to zero, and seeing if time runs out.
  if(futexCmd == FUTEX_WAIT ||
     futexCmd == FUTEX_WAIT_BITSET ||
     futexCmd == FUTEX_WAIT_REQUEUE_PI
     ){
    gs.log.writeToLog(Importance::info, "Futex wait on: %p.\n", t.arg1());
    gs.log.writeToLog(Importance::info, "On value: " + to_string(futexValue) + "\n");
    if (gs.log.getDebugLevel() > 0) {
      int actualValue = (int) t.readFromTracee(traceePtr<int>((int*) t.arg1()), t.getPid());
      gs.log.writeToLog(Importance::extra, "Actual value: " + to_string(actualValue) + "\n");
    }

    // Overwrite the current value with our value. Restore value in post hook.
    s.originalArg4 = (uint64_t) timeoutPtr;
    // Our timespec value to copy over.
    timespec ourTimeout = {0};

    if(timeoutPtr == nullptr){
      // We need somewhere to store timespec. We will write this data below the current
      // stack pointer accounting for the red zone, known to be 128 bytes.
      gs.log.writeToLog(Importance::info,
                        "timeout null, writing our data below the current stack frame...\n");

      // Enough space for timespec struct.
      timespec* newAddress = (timespec*) s.mmapMemory.getAddr().ptr;

      t.writeToTracee(traceePtr<timespec>(newAddress), ourTimeout, s.traceePid);

      // Point system call to new address.
      t.writeArg4((uint64_t) newAddress);
    }else{
      if (gs.log.getDebugLevel() > 0 ) {
        timespec timeout = t.readFromTracee(traceePtr<timespec>(timeoutPtr), t.getPid());
        gs.log.writeToLog(Importance::info,
                          "Using original timeout value: (s = %d, ns = %d)\n",
                          timeout.tv_sec, timeout.tv_nsec);
      }
      t.writeToTracee(traceePtr<timespec>(timeoutPtr), ourTimeout, s.traceePid);
      s.userDefinedTimeout = true;
    }
  }

  return true;
}

void futexSystemCall::handleDetPost(globalState& gs, state& s, ptracer& t, scheduler& sched){
  int futexOp = t.arg2();
  int futexCmd = futexOp & FUTEX_CMD_MASK;
  if(futexCmd == FUTEX_WAIT ||
     futexCmd == FUTEX_WAIT_BITSET ||
     futexCmd == FUTEX_WAIT_REQUEUE_PI
     ){

    // The process is trying to poll. We preempt but do not mark as blocked to avoid
    // getting stuck on an infite polling loop.
    if(s.userDefinedTimeout){
      // Only preempt if we would have timeout out. Othewise let if continue running!
      if((int) t.getReturnValue() == -ETIMEDOUT){
        sched.preemptAndScheduleNext(s.traceePid, preemptOptions::runnable);
      }

      s.userDefinedTimeout = false;
      return;
    } else {
      t.writeArg4(s.originalArg4);
      replaySyscallIfBlocked(gs, s, t, sched, ETIMEDOUT);
    }

  }
  return;
}
// =======================================================================================
void getcwdSystemCall::handleDetPost(globalState& gs, state& s, ptracer& t,
                                     scheduler& sched){
  printInfoString(t.arg1(), gs, s, t);

  return;
}
// =======================================================================================
void getdentsSystemCall::handleDetPost(globalState& gs, state& s, ptracer& t, scheduler& sched){
  handleDents<linux_dirent>(gs, s, t, sched);
  return;
}
// =======================================================================================
void getdents64SystemCall::handleDetPost(globalState& gs, state& s, ptracer& t, scheduler& sched){
  handleDents<linux_dirent64>(gs, s, t, sched);
  return;
}
// =======================================================================================
void getpeernameSystemCall::handleDetPost(globalState& gs, state& s, ptracer& t, scheduler& sched){
  int ret = t.getReturnValue();
  if(ret == 0){
    throw runtime_error("dettrace runtime exception: Call to getpeername with network socket not suported.\n");
  }
  return;
}
// =======================================================================================
bool getpidSystemCall::handleDetPre(globalState& gs, state& s, ptracer& t, scheduler& sched){
  return true;
}
void getpidSystemCall::handleDetPost(globalState& gs, state& s, ptracer& t, scheduler& sched){
  if (s.noopSystemCall) {
    gs.log.writeToLog(Importance::info, "NOOP system call (getpid) setting return value to 0\n");
    s.noopSystemCall = false;
    t.setReturnRegister(0); // pretend like the system call (that we replaced) has succeeded
  }
}
// =======================================================================================
void getrandomSystemCall::handleDetPost(globalState& gs, state& s, ptracer& t, scheduler& sched){
  gs.getRandomCalls++;
  // Fill buffer with our own deterministic values.
  char* buf = (char*) t.arg1();
  auto traceeMem = traceePtr<char>{buf};
  size_t bufLength = (size_t) t.arg2();

  // const int flags = 0;

  // TODO For a big enough value this could stack overflow.
  char constValues[bufLength];
  for(size_t i = 0; i < bufLength; i++){
    constValues[i] = i;
  }

  writeVmTraceeRaw(constValues, traceeMem, bufLength, t.getPid());
  // Explicitly increase counter.
  t.writeVmCalls++;

  return;
}
// =======================================================================================
void getrlimitSystemCall::handleDetPost(globalState& gs, state& s, ptracer& t, scheduler& sched){
  struct rlimit* rp = (struct rlimit*) t.arg2();
  if (rp != nullptr) {
    // struct rlimit noLimits = {};
    // TODO See prlimit64SystemCall
    // noLimits.rlim_cur = RLIM_INFINITY;
    // noLimits.rlim_max = RLIM_INFINITY;

    // t.writeToTracee(rp, noLimits, t.getPid());
  }

  return;
}
// =======================================================================================
void getrusageSystemCall::handleDetPost(globalState& gs, state& s, ptracer& t, scheduler& sched){
  gs.timeCalls++;
  struct rusage* usagePtr = (struct rusage*) t.arg2();

  if(usagePtr == nullptr){
    gs.log.writeToLog(Importance::info, "getrusage pointer null.");
  }else{
    // jld; initializing usage from tracee memory seems redundant, as all fields
    // are overwritten below
    struct rusage usage; // = t.readFromTracee(traceePtr<struct rusage>(usagePtr), t.getPid());
    /* user CPU time used */
    usage.ru_utime = timeval { .tv_sec =  (long) s.getLogicalTime(),
                               .tv_usec = (long )s.getLogicalTime() };
    /* system CPU time used */
    usage.ru_stime = timeval { .tv_sec =  (long) s.getLogicalTime(),
                               .tv_usec = (long )s.getLogicalTime() };
    usage.ru_maxrss = LONG_MAX;                    /* maximum resident set size */
    usage.ru_ixrss = LONG_MAX;                     /* integral shared memory size */
    usage.ru_idrss = LONG_MAX;    		   /* integral unshared data size */
    usage.ru_isrss = LONG_MAX;    		   /* integral unshared stack size */
    usage.ru_minflt = LONG_MAX;   		   /* page reclaims (soft page faults) */
    usage.ru_majflt = LONG_MAX;   		   /* page faults (hard page faults) */
    usage.ru_nswap = LONG_MAX;    		   /* swaps */
    usage.ru_inblock = LONG_MAX;  		   /* block input operations */
    usage.ru_oublock = LONG_MAX;  		   /* block output operations */
    usage.ru_msgsnd = LONG_MAX;   		   /* IPC messages sent */
    usage.ru_msgrcv = LONG_MAX;   		   /* IPC messages received */
    usage.ru_nsignals = LONG_MAX; 		   /* signals received */
    usage.ru_nvcsw = LONG_MAX;    		   /* voluntary context switches */
    usage.ru_nivcsw = LONG_MAX;   		   /* involuntary context switches */

    t.writeToTracee(traceePtr<struct rusage>(usagePtr), usage, t.getPid());
  }

  s.incrementTime();
  return;
}
// =======================================================================================
void gettimeofdaySystemCall::handleDetPost(globalState& gs, state& s, ptracer& t, scheduler& sched){
  gs.timeCalls++;
  struct timeval* tp = (struct timeval*) t.arg1();
  if (nullptr != tp) {
    struct timeval myTv = {};
    myTv.tv_sec = s.getLogicalTime();
    myTv.tv_usec = 0;

    t.writeToTracee(traceePtr<struct timeval>(tp), myTv, t.getPid());
    s.incrementTime();
  }

  return;
}
// =======================================================================================
void ioctlSystemCall::handleDetPost(globalState& gs, state& s, ptracer& t, scheduler& sched){
  int fd = t.arg1();
  const uint64_t request = t.arg2();
  gs.log.writeToLog(Importance::info, "fd %d\n", fd);
  gs.log.writeToLog(Importance::info, "Request %" PRId64 "\n", request);

  // Even though we don't particularly like TCGETS, we will let it through as we need
  // it for some programs to work, like `more`.
  if(TCGETS == request || TCSETS == request || FIOCLEX){
    return;
  }

  // Do not suport querying for these.
  if(TCGETS == request ||
     TIOCGWINSZ == request // Window size of terminal.
     ) {
    t.setReturnRegister((uint64_t) -ENOTTY);
  }

  // These are fine, allow them through.
  else if(TIOCGPGRP == request || // group pid of foreground process.
          SIOCSIFMAP == request || // efficient reading of files.
          0xC020660B /*FS_IOC_FIEMAP*/ == request // For some reason causes compiler
          // error if I use the macro?
#ifdef FICLONE
          || FICLONE == request // Not avaliable in older kernel versions.
#endif
          ){ // clone file
    return;
  }else{
    throw runtime_error("dettrace runtime exception: Unsupported ioctl call: fd=" + to_string(t.arg1()) +
                        " request=" + to_string(request));
  }
  return;
}
// =======================================================================================
// TODO
void llistxattrSystemCall::handleDetPost(globalState& gs, state& s, ptracer& t, scheduler& sched){

}
// =======================================================================================
// TODO
void lgetxattrSystemCall::handleDetPost(globalState& gs, state& s, ptracer& t, scheduler& sched){

}
// =======================================================================================
void mmapSystemCall::handleDetPost(globalState& gs, state& s, ptracer& t, scheduler& sched){
  // This isn't a natural call mmap from the tracee we injected this call ourselves!
  if(s.syscallInjected){
    gs.log.writeToLog(Importance::info, "This mmap was inject for use in pre and post hook purposes.\n");
    if((void*) t.getReturnValue() == MAP_FAILED){
      throw runtime_error("Unable to properly inject mmap call to tracee!\n"
                          "mmap call returned: " +
                          to_string(t.getReturnValue()) + "\n");
    }
    s.syscallInjected = false;


    // save memory address to be used later
    s.mmapMemory.setAddr(traceePtr<void>((void*) t.getReturnValue()));

    // Inject original system call:
    // Previous state that should have been set by system call that created this fstat
    // injection.
    t.setRegs(s.regSaver.popRegisterState());
    replaySystemCall(gs, t, t.getSystemCallNumber());
  }
}

// =======================================================================================
bool
nanosleepSystemCall::handleDetPre(globalState& gs, state& s, ptracer& t, scheduler& sched){
  // noopSystemCall(gs, t);
  // sched.reportProgress(s.traceePid);
  // sched.preemptAndScheduleNext(s.traceePid, preemptOptions::runnable);

  // Write zero seconds to time required to skip waiting.
  struct timespec *req = (struct timespec *) t.arg1();
  if(req != nullptr){
    uint64_t rsp = (uint64_t) t.getRsp().ptr;
    struct timespec* myReq = (timespec*) (rsp - 128 - sizeof(struct timespec));
    struct timespec localReq = {0};

    t.writeToTracee(traceePtr<struct timespec>(myReq), localReq, s.traceePid);
    t.writeArg1((uint64_t) myReq);
  }
  return false;
}
// =======================================================================================
bool mkdirSystemCall::handleDetPre(globalState& gs, state& s, ptracer& t,
                                   scheduler& sched){
  printInfoString(t.arg1(), gs, s, t);

  return false;
}
// =======================================================================================
bool mkdiratSystemCall::handleDetPre(globalState& gs, state& s, ptracer& t,
                                     scheduler& sched){
  printInfoString(t.arg2(), gs, s, t);

  return false;
}
// =======================================================================================
void newfstatatSystemCall::handleDetPost(globalState& gs, state& s, ptracer& t,
                                         scheduler& sched){
  printInfoString(t.arg2(), gs, s, t);

  // This newfstatat was injected to get the inode belonging to a file that was deleted
  // through: unlink, unlinkat, or rmdir.
  if(s.syscallInjected){
    gs.log.writeToLog(Importance::info, "This newfstatat was injected.\n");
    s.syscallInjected = false;

    if((int) t.getReturnValue() >= 0){
      struct stat* statbufPtr = (struct stat*) t.arg3();
      struct stat statbuf = t.readFromTracee(traceePtr<struct stat>(statbufPtr), s.traceePid);

      gs.log.writeToLog(Importance::extra, "marking (device,inode) = (%lu,%lu) for deletion\n", statbuf.st_dev, statbuf.st_ino);

      s.inodeToDelete = statbuf.st_ino;
    }else{
      gs.log.writeToLog(Importance::info, "No such file, that's okay.\n");
      s.inodeToDelete = -1;
    }

    // We got what we wanted. The inode that matches the file called from either
    // unlink, unlinkat, or rmdir. Now replay that system call as we did not let
    // it though.
    t.setRegs(s.regSaver.popRegisterState());
    replaySystemCall(gs, t, t.getSystemCallNumber());
    s.firstTrySystemcall = false;
  }else{
    handleStatFamily(gs, s, t, "newfstatat");
  }

  return;
}
// =======================================================================================
bool lstatSystemCall::handleDetPre(globalState& gs, state& s, ptracer& t, scheduler& sched){
  printInfoString(t.arg1(), gs, s, t);

  return true;
}

void lstatSystemCall::handleDetPost(globalState& gs, state& s, ptracer& t, scheduler& sched){
  handleStatFamily(gs, s, t, "lstat");
  return;
}
// =======================================================================================
bool linkSystemCall::handleDetPre(globalState& gs, state& s, ptracer& t, scheduler& sched){

  printInfoString(t.arg2(), gs, s, t, " hardlinking path: ");
  printInfoString(t.arg1(), gs, s, t, " to path: ");

  return false;
}
// =======================================================================================
bool linkatSystemCall::handleDetPre(globalState& gs, state& s, ptracer& t, scheduler& sched){

  printInfoString(t.arg4(), gs, s, t, " hardlinking path: ");
  printInfoString(t.arg2(), gs, s, t, " to path: ");

  return false;
}
// =======================================================================================
bool openSystemCall::handleDetPre(globalState& gs, state& s, ptracer& t, scheduler& sched){
  char* addressOfCString = (char*) t.arg1();
  // Do not use printInfo string, we want the path for checking against certain strings.
  if(addressOfCString != nullptr){
#ifdef EXTRANEOUS_TRACEE_READS
    auto ptr = traceePtr<char>(addressOfCString);
    string path = t.readTraceeCString(ptr, s.traceePid);
    string coloredPath = gs.log.makeTextColored(Color::green, path);
    string msg = s.systemcall->syscallName + " path:" + coloredPath + "\n";
    gs.log.writeToLog(Importance::info, msg);

    if(path == "/dev/random"){
      gs.devRandomOpens++;
    }else if(path == "/dev/urandom"){
      gs.devUrandomOpens++;
    }
#endif
  }else{
    gs.log.writeToLog(Importance::info, "Null path given to system call.\n");
  }

  return true;
}

void openSystemCall::handleDetPost(globalState& gs, state& s, ptracer& t, scheduler& sched){
  // Nothing for us to do skip the post hook!
  if((int) t.getReturnValue() < 0){
    return;
  }

  int flags = t.arg2();

  // Check if this file is modifiable by tracee.
  if(flags & (O_WRONLY | O_RDWR | O_APPEND | O_TRUNC | O_CREAT)){
    injectFstat(gs, s, t, t.getReturnValue());
  }
}
// =======================================================================================
bool openatSystemCall::handleDetPre(globalState& gs, state& s, ptracer& t, scheduler& sched){
    char* addressOfCString = (char*) t.arg2();
  // Do not use printInfo string, we want the path for checking against certain strings.
  if(addressOfCString != nullptr){
#ifdef EXTRANEOUS_TRACEE_READS
    auto ptr = traceePtr<char>(addressOfCString);
    string path = t.readTraceeCString(ptr, s.traceePid);
    string coloredPath = gs.log.makeTextColored(Color::green, path);
    string msg = s.systemcall->syscallName + " path:" + coloredPath + "\n";
    gs.log.writeToLog(Importance::info, msg);

    if(path == "/dev/random"){
      gs.devRandomOpens++;
    }else if(path == "/dev/urandom"){
      gs.devUrandomOpens++;
    }
#endif
  }else{
    gs.log.writeToLog(Importance::info, "Null path given to system call.\n");
  }

  return true;
}

void openatSystemCall::handleDetPost(globalState& gs, state& s, ptracer& t, scheduler& sched){
  // Nothing for us to do skip the post hook!
  if((int) t.getReturnValue() < 0){
    return;
  }

  int flags = t.arg3();
  // Check if this file is modifiable by tracee.
  if(flags & (O_WRONLY | O_RDWR | O_APPEND | O_TRUNC | O_CREAT)){
    injectFstat(gs, s, t, t.getReturnValue());
  }
}
// =======================================================================================
bool pauseSystemCall::handleDetPre(globalState& gs, state& s, ptracer& t, scheduler& sched){
  gs.log.writeToLog(Importance::info, "pause pre-hook\n");
  return true;
}

void pauseSystemCall::handleDetPost(globalState& gs, state& s, ptracer& t, scheduler& sched){
  gs.log.writeToLog(Importance::info, "pause post-hook\n");
  if (s.signalInjected) {
    uint64_t retval = t.getReturnValue();
    gs.log.writeToLog(Importance::info, "pause returned %lld\n", retval);

    // ick: fake the return value for the call we hijacked.
    // For alarm(), 0 means there was no previously scheduled alarm.
    // For timer_settime() and setitimer(), 0 means it succeeded
    s.signalInjected = false;
    t.setReturnRegister(0);
  }
}

// =======================================================================================
bool pipeSystemCall::handleDetPre(globalState& gs, state& s, ptracer& t, scheduler& sched){
  gs.log.writeToLog(Importance::info, "Making this pipe non-blocking via pipe2\n");

  s.syscallInjected = true;
  t.changeSystemCall(SYS_pipe2);

  // Set so we can restore in pipe2 later.
  s.originalArg2 = t.arg2();
  t.writeArg2(O_NONBLOCK);

  return true;
}

void pipeSystemCall::handleDetPost(globalState& gs, state& s, ptracer& t, scheduler& sched){
  // We should never get here. We always change the call to pipe to a call to pipe2.
  throw runtime_error("did not expect to arrive a pipe post hook.");
  // Restore original register state.
  // t.writeArg2(s.originalArg2);
  // auto p = getPipeFds(gs, s, t);
  // s.fdStatus[p.first] = descriptorType::blocking;
  // s.fdStatus[p.second] = descriptorType::blocking;
}
// =======================================================================================
bool pipe2SystemCall::handleDetPre(globalState& gs, state& s, ptracer& t, scheduler& sched){
  // We only see this pre-hook if the call was originally a pipe2 and not a pipe that was
  // converted into a pipe2. That's why it's okay to set s.originalArg2 here.
  gs.log.writeToLog(Importance::info, "Making this pipe2 non-blocking\n");
  // Convert pipe call to pipe2 to set O_NONBLOCK.
  s.originalArg2 = t.arg2();
  t.writeArg2(t.arg2() | O_NONBLOCK);

  return true;
}

void pipe2SystemCall::handleDetPost(globalState& gs, state& s, ptracer& t, scheduler& sched){
  // Restore original registers.
  t.writeArg2(s.originalArg2);
  auto p = getPipeFds(gs, s, t);

  // This was a pipe that  got converted to a pipe2.
  if(s.syscallInjected){
    s.syscallInjected = false;
    gs.log.writeToLog(Importance::info, "This used to a pipe()!\n");
    gs.log.writeToLog(Importance::info, "Set pipe %d as blocking.\n", p.first);
    gs.log.writeToLog(Importance::info, "Set pipe %d as blocking.\n", p.second);
    s.fdStatus[p.first] = descriptorType::blocking;
    s.fdStatus[p.second] = descriptorType::blocking;
  }else{
    // Must be checked after resetting state.
    int flags = (int) t.arg2();

    // Check if set as non=blocking.
    if((flags & O_NONBLOCK) == 0){
      gs.log.writeToLog(Importance::info, "Set pipe %d as blocking.\n", p.first);
      gs.log.writeToLog(Importance::info, "Set pipe %d as blocking.\n", p.second);
      s.fdStatus[p.first] = descriptorType::blocking;
      s.fdStatus[p.second] = descriptorType::blocking;
    }else{
      gs.log.writeToLog(Importance::info, "Set pipe %d as non-blocking.\n", p.first);
      gs.log.writeToLog(Importance::info, "Set pipe %d as non-blocking.\n", p.second);
      s.fdStatus[p.first] = descriptorType::nonBlocking;
      s.fdStatus[p.second] = descriptorType::nonBlocking;
    }
  }
}
// =======================================================================================
bool pselect6SystemCall::handleDetPre(globalState& gs, state& s, ptracer& t, scheduler& sched){
  return true;
}

void pselect6SystemCall::handleDetPost(globalState& gs, state& s, ptracer& t, scheduler& sched){
  return;
}
// =======================================================================================
bool pollSystemCall::handleDetPre(globalState& gs, state& s, ptracer& t, scheduler& sched){
  s.originalArg3 = t.arg3();
  // Make this call non blocking by setting timeout to zero!
  if ((int) s.originalArg3 != 0){
    t.writeArg3(0);
  }
  return true;
}

void pollSystemCall::handleDetPost(globalState& gs, state& s, ptracer& t, scheduler& sched){
  // Check if user set to timeout to block forever.
  if((int) s.originalArg3 < 0){
    gs.log.writeToLog(Importance::info, "Blocking poll found\n");
    bool replay = replaySyscallIfBlocked(gs, s, t, sched, 0);
    if(replay){
      // Restore state of argument 3.
      t.writeArg3(s.originalArg3);
    }
  }else{
    gs.log.writeToLog(Importance::info, "Non-blocking poll found\n");
    preemptIfBlocked(gs, s, t, sched, EAGAIN);
  }


  return;
}
// =======================================================================================
// for reference, here's the prlimit() prototype
// int prlimit(pid_t pid, int resource, const struct rlimit *new_limit, struct rlimit *old_limit);
bool prlimit64SystemCall::handleDetPre(globalState& gs, state& s, ptracer& t, scheduler& sched){
  s.originalArg3 = t.arg3();
  t.writeArg3(0/*NULL*/); // suppress attempts to set new limits

  // Check if first argument (pid) is non-zero. If so fail.
  // TODO: could also always overwrite first argument with zero
  int pid = (pid_t) t.arg1();
  if(pid != 0){
    throw runtime_error("dettrace runtime exception: prlimit64: We do not support prlimit64 on other processes.\n "
                        "(pid: " + to_string(pid));
  }

  return true;
}

void prlimit64SystemCall::handleDetPost(globalState& gs, state& s, ptracer& t, scheduler& sched){
  /* To bypass the complexity of this system call (lots of different resources,
   * dynamic limits, ...) we just always say everything is unlimited, and ignore
   * requests from the application to try to increase the soft limit.
   *
   * Alternatively, we could track limits dynamically per-process and preserve
   * the illusion that they can be changed. It may be possible to actually
   * change limits deterministically in many cases, if need be, so long as the
   * starting limits are deterministic.
   */
  t.writeArg3(s.originalArg3);
  struct rlimit* rp = (struct rlimit*) t.arg4();
  if (rp != nullptr) {
    // TODO: For memory: return correct memory used, which should be deterministic.
    // TODO: Allow actual max memory through, I believe this is outside our deterministic
    // gurantee.

    // struct rlimit noLimits = {};

    // noLimits.rlim_cur =
    // noLimits.rlim_max = RLIM_INFINITY;

    //gs.log.writeToLog(Importance::info, "rp=" + to_string(t.arg4()), t.getPid());
    // t.writeToTracee(rp, noLimits, t.getPid());
  }

  return;
}
// =======================================================================================
bool readSystemCall::handleDetPre(globalState& gs, state& s, ptracer& t, scheduler& sched){
  gs.log.writeToLog(Importance::info, "File descriptor: %d\n", t.arg1());
  gs.log.writeToLog(Importance::info, "Bytes to read %d\n", t.arg3());

  return true;
}

void readSystemCall::handleDetPost(globalState& gs, state& s, ptracer& t, scheduler& sched){
  int fd = t.arg1();
  auto resetState =
    [&](){
      // Restore user regs so that it appears as if only one syscall occurred
      t.setReturnRegister(s.totalBytes);
      t.writeArg2(s.beforeRetry.rsi);
      t.writeArg3(s.beforeRetry.rdx);

      // reset for next syscall that we may have to retry
      s.firstTrySystemcall = true;
      s.totalBytes = 0;
    };

  // Pipe exists in our map and it's set to non blocking.
  if(s.fdStatus.count(fd) != 0 && s.fdStatus[fd] == descriptorType::nonBlocking){
    gs.log.writeToLog(Importance::info,
                      "read found with non blocking pipe!\n");
    bool blocked = preemptIfBlocked(gs, s, t, sched, EAGAIN);
    // We cannot read more from this polling pipe, we're done. Looping over reads
    // trying to read more.
    if(blocked){
      resetState();
      return;
    }
  }else{
    bool preemptAndTryLater = replaySyscallIfBlocked(gs, s, t, sched, EAGAIN);
    if(preemptAndTryLater){
      gs.readRetryEvents++;
      return;
    }
  }

  ssize_t bytes_read = t.getReturnValue();
  if(bytes_read < 0){
    gs.log.writeToLog(Importance::info, "Returned negative: %d.",
                      bytes_read);
    return;
  }

  if(bytes_read > 0){
    // This operation is very expensive!
    // char buffer[bytes_read];
    // readVmTracee(traceePtr<void>((void*) t.arg2()), buffer, bytes_read, s.traceePid);
    // gs.log.writeToLog(Importance::extra, "Read output: \"\n");
    // for(int i = 0; i < bytes_read; i++){
    // gs.log.writeToLog(Importance::extra, "%d", (int) buffer[i]);
    // }
    // gs.log.writeToLog(Importance::extra, "\"\n");
  }

  // Replay system call if not enought bytes were read.
  s.totalBytes += bytes_read;

  if(s.firstTrySystemcall){
    gs.log.writeToLog(Importance::info, "First time seeing this read!\n");
    s.firstTrySystemcall = false;
    s.beforeRetry = t.getRegs();
  }

  // EOF, or read returned everything we asked for.
  if(bytes_read == 0  || // EOF
     s.totalBytes == s.beforeRetry.rdx){  // original bytes requested
    gs.log.writeToLog(Importance::info, "EOF or read all bytes.\n");
    resetState();
  } else {
    gs.log.writeToLog(Importance::info, "Got less bytes than requested.\n");
    t.writeArg2(t.arg2() + bytes_read);
    t.writeArg3(t.arg3() - bytes_read);

    replaySystemCall(gs, t, t.getSystemCallNumber());
  }

  return;
}
// =======================================================================================
bool readvSystemCall::handleDetPre(globalState& gs, state& s, ptracer& t, scheduler& sched){
  return true;
}

void readvSystemCall::handleDetPost(globalState& gs, state& s, ptracer& t, scheduler& sched){
  return;
}
// =======================================================================================
bool readlinkSystemCall::handleDetPre(globalState& gs, state& s, ptracer& t,
                                      scheduler& sched){
  printInfoString(t.arg1(), gs, s, t);

  return false;
}
// =======================================================================================
bool readlinkatSystemCall::handleDetPre(globalState& gs, state& s, ptracer& t,
                                      scheduler& sched){
  printInfoString(t.arg2(), gs, s, t);

  return false;
}
// =======================================================================================
bool recvmsgSystemCall::handleDetPre(globalState& gs, state& s, ptracer& t,
                                     scheduler& sched){
  return true;
}

void recvmsgSystemCall::handleDetPost(globalState& gs, state& s, ptracer& t,
                                      scheduler& sched){
  return;
}

// =======================================================================================
bool renameSystemCall::handleDetPre(globalState& gs, state& s, ptracer& t,
                                    scheduler& sched){
  gs.log.writeToLog(Importance::info, "rename pre-hook, s.firstTrySystemcall:%d\n", s.firstTrySystemcall);
  printInfoString(t.arg1(), gs, s, t, " old path: ");
  printInfoString(t.arg2(), gs, s, t, " new path: ");

  // Turn into a newfstatat system call to see if newpath exists. If so, we must mark
  // newpath as deleted.
  bool ret = injectNewfstatatIfNeeded(gs, s, t, AT_FDCWD, (char*) t.arg2());
  if(ret){
    // We have work to do in the newfstatat post hook! Make sure to intercept this, hence,
    // true.
    return true;
  }

  // We must go into the post hook to delete the inode.
  return true;
}

void renameSystemCall::handleDetPost(globalState& gs, state& s, ptracer& t,
                                    scheduler& sched){
  if((int) t.getReturnValue() >= 0){
    removeInodeFromMaps(s.inodeToDelete, gs, t);
    s.inodeToDelete = -1;
  }
  s.firstTrySystemcall = true;

  return;
}
// =======================================================================================
bool renameatSystemCall::handleDetPre(globalState& gs, state& s, ptracer& t,
                                    scheduler& sched){
  // Turn into a newfstatat system call to see if oldpath existed. If so, we must mark
  // all path as deleted.
  int newdirfd = (int) t.arg3();
  char* newpath = (char*) t.arg4();
  bool ret = injectNewfstatatIfNeeded(gs, s, t, newdirfd, newpath);
  if(ret){
    // We have work to do in the newfstatat post hook! Make sure to intercept this, hence,
    // true.
    return true;
  }

  printInfoString(t.arg2(), gs, s, t, " renaming-ing path: ");
  printInfoString(t.arg4(), gs, s, t, " to path: ");
  // We must go into the post hook to delete the inode.
  return true;
}

void renameatSystemCall::handleDetPost(globalState& gs, state& s, ptracer& t,
                                    scheduler& sched){
  if((int) t.getReturnValue() >= 0){
    removeInodeFromMaps(s.inodeToDelete, gs, t);
    s.inodeToDelete = -1;
  }
  s.firstTrySystemcall = true;
}
// =======================================================================================
bool renameat2SystemCall::handleDetPre(globalState& gs, state& s, ptracer& t,
                                    scheduler& sched){
  int flags = (int) t.arg5();
  // We do not handle this flag TODO
#ifdef RENAME_EXCHANGE
  if((flags | RENAME_EXCHANGE) == flags){
    throw runtime_error("dettrace runtime exception: We do not handle RENAME_EXCHANGE flag.\n");
  }
#endif

  // Turn into a newfstatat system call to see if oldpath existed. If so, we must mark
  // all path as deleted.
  int newdirfd = (int) t.arg3();
  char* newpath = (char*) t.arg4();
  bool ret = injectNewfstatatIfNeeded(gs, s, t, newdirfd, newpath);
  if(ret){
    // We have work to do in the newfstatat post hook! Make sure to intercept this, hence,
    // true.
    return true;
  }

  printInfoString(t.arg2(), gs, s, t, " renaming-ing path: ");
  printInfoString(t.arg4(), gs, s, t, " to path: ");
  // We must go into the post hook to delete the inode.
  return true;
}

void renameat2SystemCall::handleDetPost(globalState& gs, state& s, ptracer& t,
                                    scheduler& sched){
  if((int) t.getReturnValue() >= 0){
    removeInodeFromMaps(s.inodeToDelete, gs, t);
    s.inodeToDelete = -1;
  }
  s.firstTrySystemcall = true;
}
// =======================================================================================
bool rmdirSystemCall::handleDetPre(globalState& gs, state& s, ptracer& t, scheduler& sched){
  // Turn into a newfstatat system call.
  bool ret = injectNewfstatatIfNeeded(gs, s, t, AT_FDCWD, (char*) t.arg1());
  if(ret){
    // We have work to do in the newfstatat post hook! Make sure to intercept this, hence,
    // true.
    return true;
  }

  printInfoString(t.arg1(), gs, s, t);
  // We must go into the post hook to delete the inode.
  return true;

}

void rmdirSystemCall::handleDetPost(globalState& gs, state& s, ptracer& t, scheduler& sched){
  // We delete the inode here instead of at newfstatatSystemCall since we don't know
  // until here whether the call to rmdir actually succeeded.
  // TODO: What happens if this a symbolic link to a directory?
  if((int) t.getReturnValue() >= 0){
    removeInodeFromMaps(s.inodeToDelete, gs, t);
    s.inodeToDelete = -1;
  }
  s.firstTrySystemcall = true;
}
// =======================================================================================
// cribbed from strace, as using the standard struct sigaction does not yield
// correct output. I guess libc internally translates from the new user-facing
// struct to this older one, and passes the older one to the kernel.
// https://github.com/strace/strace/blob/v4.23/signal.c#L297
struct kernel_sigaction {
  /* sa_handler may be a libc #define, need to use another name: */
  unsigned long sa_handler__;
  unsigned long sa_mask;
  unsigned long sa_flags;
  unsigned long sa_restorer;
};
bool rt_sigactionSystemCall::handleDetPre(globalState& gs, state& s, ptracer& t,
                                          scheduler& sched){
  gs.log.writeToLog(Importance::info, "rt_sigaction pre-hook for signal " +
                    to_string(t.arg1())+"\n");
  const uint64_t signum = t.arg1();
  s.requestedSignalToHandle = signum;

  if (0 == t.arg2()) {
    // no need to run the post-hook since tracee is not updating signal handlers
    return false;
  }

  // figure out what kind of handler the tracee is trying to install
  struct kernel_sigaction sa =
    t.readFromTracee(traceePtr<struct kernel_sigaction>((struct kernel_sigaction*) t.arg2()), t.getPid() );
  gs.log.writeToLog(Importance::info, "struct sigaction*: %p\n", t.arg2());
  gs.log.writeToLog(Importance::info, "sa_flags: " +
                    to_string(sa.sa_flags) + " " +
                    to_string(SA_RESETHAND)+" \n");
  gs.log.writeToLog(Importance::info, "sa_handler: " +
                    to_string((uint64_t)sa.sa_handler__) +
                    "\n");

  if (((unsigned long)SIG_IGN) == sa.sa_handler__) {
    s.requestedSignalHandler = SIGHANDLER_IGNORED;
  } else if (((unsigned long)SIG_DFL) == sa.sa_handler__) {
    s.requestedSignalHandler = SIGHANDLER_DEFAULT;
  } else {
    if (sa.sa_flags & SA_RESETHAND) {
      // SA_RESETHAND flag specified, which restores SIG_DFL after running the
      // custom handler once.
      s.requestedSignalHandler = SIGHANDLER_CUSTOM_1SHOT;
    } else {
      s.requestedSignalHandler = SIGHANDLER_CUSTOM;
    }
  }
  gs.log.writeToLog(Importance::info, "signal " + to_string(signum) +
                    " handler requested: " +
                    to_string(s.requestedSignalHandler) + "\n");

  // run the post-hook to see if signal handler installation was successful
  return true;
}

void rt_sigactionSystemCall::handleDetPost(globalState& gs, state& s, ptracer& t,
                                           scheduler& sched){
  gs.log.writeToLog(Importance::info, "rt_sigaction post-hook\n");
  if (0 == t.getReturnValue()) {
    // signal handler installation was successful
    s.currentSignalHandlers[s.requestedSignalToHandle] = s.requestedSignalHandler;

    gs.log.writeToLog(Importance::info, "signal "+to_string(s.requestedSignalToHandle)+
                      " handler of type "+to_string(s.requestedSignalHandler)+" installed\n");

    s.requestedSignalHandler = SIGHANDLER_INVALID;
    s.requestedSignalToHandle = -1;
  }
  return;
}
// =======================================================================================
// TODO
bool sendtoSystemCall::handleDetPre(globalState& gs, state& s, ptracer& t, scheduler& sched){
  return true;
}

void sendtoSystemCall::handleDetPost(globalState& gs, state& s, ptracer& t, scheduler& sched){
  return;
}
// =======================================================================================
bool selectSystemCall::handleDetPre(globalState& gs, state& s, ptracer& t, scheduler& sched){
  // Get the original set structs.
  // Set them in the state class.
  if((void*) t.arg2() != NULL){
    s.rdfsNotNull = true;
    s.origRdfs = t.readFromTracee(traceePtr<fd_set>((fd_set*) t.arg2()), t.getPid());
  }
  if((void*) t.arg3() != NULL){
    s.wrfsNotNull = true;
    s.origWrfs = t.readFromTracee(traceePtr<fd_set>((fd_set*) t.arg3()), t.getPid());
  }
  if((void*) t.arg4() != NULL){
    s.exfsNotNull = true;
    s.origExfs = t.readFromTracee(traceePtr<fd_set>((fd_set*) t.arg4()), t.getPid());
  }

  // Set the timeout to zero.
  timeval* timeoutPtr = (timeval*) t.arg5();
  s.originalArg5 = (uint64_t) timeoutPtr;
  timeval ourTimeout = {0};
  ourTimeout.tv_sec = 0;

  if(timeoutPtr == nullptr){
    // Has to be created in memory.
    timeval* newAddr = (timeval*) s.mmapMemory.getAddr().ptr;
    t.writeToTracee(traceePtr<timeval>(newAddr), ourTimeout, s.traceePid);

    t.writeArg5((uint64_t) newAddr);
  }else{
    // Already exists in memory.
    // jld: useless read from tracee memory
    //timeval timeout = t.readFromTracee(traceePtr<timeval>(timeoutPtr), t.getPid());
    t.writeToTracee(traceePtr<timeval>(timeoutPtr), ourTimeout, s.traceePid);
    s.userDefinedTimeout = true;
  }

  return true;
}

void selectSystemCall::handleDetPost(globalState& gs, state& s, ptracer& t, scheduler& sched){
  if(s.userDefinedTimeout){
    if(t.getReturnValue() == 0){
      sched.preemptAndScheduleNext(s.traceePid, preemptOptions::runnable);
    }
  } else {
    bool replayed = replaySyscallIfBlocked(gs, s, t, sched, 0);

    if(replayed){
      if(s.rdfsNotNull){
        t.writeToTracee(traceePtr<fd_set>((fd_set*) t.arg2()), s.origRdfs, t.getPid());
      }
      if(s.wrfsNotNull){
        t.writeToTracee(traceePtr<fd_set>((fd_set*) t.arg3()), s.origWrfs, t.getPid());
      }
      if(s.exfsNotNull){
        t.writeToTracee(traceePtr<fd_set>((fd_set*) t.arg4()), s.origExfs, t.getPid());
      }
      s.rdfsNotNull = false;
      s.wrfsNotNull = false;
      s.exfsNotNull = false;
      t.writeArg5((uint64_t) s.originalArg5);
    }
  }
  return;
}
// =======================================================================================
// TODO

bool set_robust_listSystemCall::handleDetPre(globalState& gs, state& s, ptracer& t, scheduler& sched){
  return true;
}
void set_robust_listSystemCall::handleDetPost(globalState& gs, state& s, ptracer& t, scheduler& sched){
  return;
}

// =======================================================================================
bool statSystemCall::handleDetPre(globalState& gs, state& s, ptracer& t, scheduler& sched){
  printInfoString(t.arg1(), gs, s, t);

  return true;
}

void statSystemCall::handleDetPost(globalState& gs, state& s, ptracer& t, scheduler& sched){
  handleStatFamily(gs, s, t, "stat");
  return;
}
// =======================================================================================
void statfsSystemCall::handleDetPost(globalState& gs, state& s, ptracer& t, scheduler& sched){
  struct statfs* statfsPtr = (struct statfs*) t.arg2();
  if(statfsPtr == nullptr){
    gs.log.writeToLog(Importance::info, "statfs: statbuf null.\n");
    return;
  }

  if(t.getReturnValue() == 0){
    // Read values written to by system call.
    // jld: useless read from tracee memory
    struct statfs stats; // = t.readFromTracee(traceePtr<struct statfs>(statfsPtr), s.traceePid);

    // Assume we're using this file sytem?
    zeroOutStatfs(stats);

    // Write back result for child.
    t.writeToTracee(traceePtr<struct statfs>(statfsPtr), stats, s.traceePid);
  }

  return;
}
// =======================================================================================
void sysinfoSystemCall::handleDetPost(globalState& gs, state& s, ptracer& t, scheduler& sched){
  struct sysinfo* infoPtr = (struct sysinfo *) t.arg1();
  if(infoPtr == nullptr){
    return;
  }

  struct sysinfo info = {};
  info.uptime = 365LL * 24 * 3600;
  // total = used + free + buff/cache
  // buff/cache includes shared
  info.totalram = 32ULL << 32;
  info.freeram = 31ULL << 32;
  info.sharedram = 1ULL << 30;
  info.bufferram = 1ULL << 32;
  info.totalswap = 0;
  info.freeswap = 0;
  info.procs = 256;
  info.totalhigh = 0;
  info.freehigh = 0;
  info.mem_unit = 1;
  // set loadavg to 1.0
  info.loads[0] = 65536;
  info.loads[1] = 65536;
  info.loads[2] = 65536;

  t.writeToTracee(traceePtr<struct sysinfo>(infoPtr), info, t.getPid());
  return;
}
// =======================================================================================
bool symlinkSystemCall::handleDetPre(globalState& gs, state& s, ptracer& t, scheduler& sched){
  printInfoString(t.arg1(), gs, s, t, " target: ");
  printInfoString(t.arg2(), gs, s, t, " linkpath: ");
  return false;
}
// =======================================================================================
bool tgkillSystemCall::handleDetPre(globalState& gs, state& s, ptracer& t, scheduler& sched){
  int tgid = (int) t.arg1();
  int tid = (int) t.arg2();
  int signal = (int) t.arg3();
  gs.log.writeToLog(Importance::info, "tgkill(tgid = %d, tid = %d, signal = %d)\n",
                    tgid, tid, signal);

  if (signal == SIGABRT && tgid == sched.pidMap.getVirtualValue(s.traceePid) &&
      tgid == tid /* TODO: when we support threads, we should also compare against tracee's tid (from gettid) */) {
    // ok
  } else {
    gs.log.writeToLog(Importance::info, "tgkillSystemCall::handleDetPre: tracee vtgid="+to_string(tgid)+" vtid=" +to_string(tid)+ " ptgid="+to_string(sched.pidMap.getVirtualValue(s.traceePid))+" trying to send unsupported signal="+to_string(signal));
    throw runtime_error("dettrace runtime exception: tgkillSystemCall::handleDetPre: tracee trying to send unsupported signal");
  }

  return true;
}

void tgkillSystemCall::handleDetPost(globalState& gs, state& s, ptracer& t, scheduler& sched){
  return;
}
// =======================================================================================
void timeSystemCall::handleDetPost(globalState& gs, state& s, ptracer& t, scheduler& sched){
  gs.timeCalls++;
  int retVal = (int) t.getReturnValue();
  if(retVal < 0){
    gs.log.writeToLog(Importance::info,
                      "Time call failed: \n" + string { strerror(- retVal)});
    return;
  }

  time_t* timePtr = (time_t*) t.arg1();
  gs.log.writeToLog(Importance::info, "time: tloc is null.");
  t.writeRax(s.getLogicalTime());
  if(timePtr == nullptr){
    return;
  }

  t.writeToTracee(traceePtr<time_t>(timePtr), (time_t) s.getLogicalTime(), s.traceePid);
  // Tick up time.
  s.incrementTime();
  return;
}
// =======================================================================================
bool timer_createSystemCall::handleDetPre(globalState& gs, state& s, ptracer& t, scheduler& sched){
  gs.log.writeToLog(Importance::info, "timer_create syscall pre-hook\n");

  // we support any clockid, but only notification via certain signals delivered to the process
  class timerInfo ti;

  traceePtr<struct sigevent> sep((struct sigevent*)t.arg2());
  if (nullptr == sep.ptr) {
    ti.sendSignal = true;
    ti.signum = SIGALRM;
    ti.signalHandlerData = nullptr;

  } else { // non-default settings, have to read tracee's struct sigevent

    struct sigevent se = t.readFromTracee(sep, t.getPid());

    switch (se.sigev_notify) {
    case SIGEV_NONE: // don't send a signal, alarm value will be read via timer_gettime()
    case SIGEV_SIGNAL: // send a signal upon timer expiration
      break;
    case SIGEV_THREAD:
      throw runtime_error("dettrace runtime exception: unsupported launching a thread on timer expiration in timer_create()");
      break;
    case SIGEV_THREAD_ID:
      throw runtime_error("dettrace runtime exception: unsupported sending a signal to a specific thread in timer_create()");
      break;
    default:
      throw runtime_error("dettrace runtime exception: unsupported sigev_notify value in timer_create() " +
                          to_string(se.sigev_notify));
      break;
    }

    // NB: we allow any signal in se.sigev_signo, since there's no harm in
    // creating a timer that's never used. We only support certain signals being
    // delivered, however, and we catch that error later in timer_settime().

    ti.sendSignal = (SIGEV_SIGNAL == se.sigev_notify);
    ti.signum = ti.sendSignal ? se.sigev_signo : -1 ;
    // TODO: JLD: we aren't seting siginfo_t fields si_code and si_value appropriately
    ti.signalHandlerData = ti.sendSignal ? se.sigev_value.sival_ptr : nullptr ;
  }

  timerID_t timerid = s.timerCreateTimers.size();
  s.timerCreateTimers[timerid] = ti;

  gs.log.writeToLog(Importance::info, "created new timer "+to_string(timerid)+"\n");

  // write timerid into tracee memory
  gs.log.writeToLog(Importance::info, "writing timerid to %p\n", t.arg3());
  t.writeToTracee(traceePtr<uint64_t>((uint64_t*)t.arg3()), timerid, s.traceePid);

  // convert timer_create() into nop
  replaceSystemCallWithNoop(gs, s, t);
  // in getpid post-hook we set return value to 0 so tracee thinks timer_create has succeeded

  // run the post-hook, which will be the getpid cleanup
  return true;
}
bool timer_deleteSystemCall::handleDetPre(globalState& gs, state& s, ptracer& t, scheduler& sched){
  timerID_t timerid = t.arg1();
  gs.log.writeToLog(Importance::info, "timer_delete pre-hook for timer "+to_string(timerid)+"\n");
  if (!s.timerCreateTimers.count(timerid)) {
    throw runtime_error("dettrace runtime exception: invalid timerid "+to_string(timerid));
  }
  return true;
}
void timer_deleteSystemCall::handleDetPost(globalState& gs, state& s, ptracer& t, scheduler& sched){
  t.setReturnRegister(0);
}

bool timer_getoverrunSystemCall::handleDetPre(globalState& gs, state& s, ptracer& t, scheduler& sched){
  timerID_t timerid = t.arg1();
  gs.log.writeToLog(Importance::info, "timer_getoverrun pre-hook for timer "+to_string(timerid)+"\n");
  if (!s.timerCreateTimers.count(timerid)) {
    throw runtime_error("dettrace runtime exception: invalid timerid "+to_string(timerid));
  }
  return true;
}
void timer_getoverrunSystemCall::handleDetPost(globalState& gs, state& s, ptracer& t, scheduler& sched){
  t.setReturnRegister(0);
}

bool timer_gettimeSystemCall::handleDetPre(globalState& gs, state& s, ptracer& t, scheduler& sched){
  timerID_t timerid = t.arg1();
  gs.log.writeToLog(Importance::info, "timer_gettime pre-hook for timer "+to_string(timerid)+"\n");

  if (!s.timerCreateTimers.count(timerid)) {
    throw runtime_error("dettrace runtime exception: invalid timerid "+to_string(timerid));
  }

  struct itimerspec *isp = (struct itimerspec*) t.arg2();
  if (isp != nullptr) {
    // timer has expired
    struct itimerspec is;
    is.it_interval.tv_sec = is.it_interval.tv_nsec = 0;
    is.it_value.tv_sec = is.it_value.tv_nsec = 0;
    t.writeToTracee(traceePtr<struct itimerspec>(isp), is, s.traceePid);
  }

  // Set invalid arguments so kernel doesn't overwrite our special struct
  // itimerspec. We fix up the return value in the post-hook so tracee thinks
  // call succeeded.
  t.writeArg1(0);
  t.writeArg2(0);

  return true;
}
void timer_gettimeSystemCall::handleDetPost(globalState& gs, state& s, ptracer& t, scheduler& sched){
  t.setReturnRegister(0);
}

bool timer_settimeSystemCall::handleDetPre(globalState& gs, state& s, ptracer& t, scheduler& sched){

  gs.log.writeToLog(Importance::info, "timer_settime pre-hook for timer "+to_string(t.arg1())+"\n");

  timerID_t timerid = t.arg1();

  if (!s.timerCreateTimers.count(timerid)) {
    throw runtime_error("dettrace runtime exception: invalid timerid "+to_string(timerid));
  }

  timerInfo tinfo = s.timerCreateTimers[timerid];
  if (!tinfo.sendSignal) {
    replaceSystemCallWithNoop(gs, s, t);
    return true; // run getpid post-hook
  } else {
    // run post-hook if necessary
    return sendTraceeSignalNow(tinfo.signum, gs, s, t, sched);
  }

  return true;
}

bool getitimerSystemCall::handleDetPre(globalState& gs, state& s, ptracer& t, scheduler& sched) {
  gs.log.writeToLog(Importance::info, "getitimer pre-hook\n");

  struct itimerval *ivp = (struct itimerval*) t.arg2();
  if (ivp != nullptr) {
    // say that timer has expired
    struct itimerval iv;
    iv.it_interval.tv_sec = iv.it_interval.tv_usec = 0;
    iv.it_value.tv_sec = iv.it_value.tv_usec = 0;
    t.writeToTracee(traceePtr<struct itimerval>(ivp), iv, s.traceePid);
  }

  // Set invalid arguments so kernel doesn't overwrite our special struct
  // itimerval. We fix up the return value in the post-hook so tracee thinks
  // call succeeded.
  t.writeArg2(0);

  return true;
}
void getitimerSystemCall::handleDetPost(globalState& gs, state& s, ptracer& t, scheduler& sched) {
  t.setReturnRegister(0);
}

bool setitimerSystemCall::handleDetPre(globalState& gs, state& s, ptracer& t, scheduler& sched) {
  gs.log.writeToLog(Importance::info, "setitimer pre-hook\n");

  int whichTimer = t.arg1();
  switch (whichTimer) {
  case ITIMER_REAL:
    return sendTraceeSignalNow(SIGALRM, gs, s, t, sched);
  case ITIMER_VIRTUAL:
    return sendTraceeSignalNow(SIGVTALRM, gs, s, t, sched);
  case ITIMER_PROF:
    return sendTraceeSignalNow(SIGPROF, gs, s, t, sched);
  default:
    throw runtime_error("dettrace runtime exception: invalid timer for setitimer "+to_string(whichTimer));
  }

  return true;
}

// =======================================================================================
void timesSystemCall::handleDetPost(globalState& gs, state& s, ptracer& t, scheduler& sched){
  // Failure nothing for us to do.
  if((clock_t) t.getReturnValue() == -1){
    return;
  }

  tms* bufPtr = (tms*) t.arg1();
  if(bufPtr != nullptr){
    tms myTms = {
      .tms_utime = 0,
      .tms_stime = 0,
      .tms_cutime = 0,
      .tms_cstime = 0,
    };

    t.writeToTracee(traceePtr<tms>(bufPtr), myTms, s.traceePid);
  }

  t.setReturnRegister(s.getLogicalTime());
  s.incrementTime();
}
// =======================================================================================
void unameSystemCall::handleDetPost(globalState& gs, state& s, ptracer& t, scheduler& sched){
  // Populate the utsname struct with our own generic data.
  struct utsname* utsnamePtr = (struct utsname*) t.arg1();

  // example struct utsname from acggrid28
  //uname({sysname="Linux", nodename="acggrid28", release="4.4.114-42-default", version="#1 SMP Tue Feb 6 10:58:10 UTC 2018 (b6ee9ae)", machine="x86_64", domainname="(none)"}
  if(utsnamePtr != nullptr){
    struct utsname myUts = {}; // initializes to all zeroes

    // compiler-time check to ensure that each member is large enough
    // magic due to https://stackoverflow.com/questions/3553296/c-sizeof-single-struct-member
    const uint32_t MEMBER_LENGTH = 60;
    if (sizeof(((struct utsname*)0)->sysname) < MEMBER_LENGTH ||
        sizeof(((struct utsname*)0)->release) < MEMBER_LENGTH ||
        sizeof(((struct utsname*)0)->version) < MEMBER_LENGTH ||
        sizeof(((struct utsname*)0)->machine) < MEMBER_LENGTH) {
      throw runtime_error("dettrace runtime exception: unameSystemCall::handleDetPost: struct utsname members too small!");
    }

    // NB: this is our standard environment
    strncpy(myUts.sysname, "Linux", MEMBER_LENGTH);
    strncpy(myUts.release, "4.0", MEMBER_LENGTH);
    strncpy(myUts.version, "#1", MEMBER_LENGTH);
    strncpy(myUts.machine, "x86_64", MEMBER_LENGTH);

    t.writeToTracee(traceePtr<struct utsname>(utsnamePtr), myUts, t.getPid());
  }
  return;
}
// =======================================================================================
bool
unlinkSystemCall::handleDetPre(globalState& gs, state& s, ptracer& t, scheduler& sched){
  // Turn into a newfstatat system call.
  bool ret = injectNewfstatatIfNeeded(gs, s, t, AT_FDCWD, (char*) t.arg1());
  if(ret){
    // We have work to do in the newfstatat post hook! Make sure to intercept this, hence,
    // true.
    return true;
  }

  printInfoString(t.arg1(), gs, s, t);
  // We must go into the post hook to delete the inode.
  return true;
}

void
unlinkSystemCall::handleDetPost(globalState& gs, state& s, ptracer& t, scheduler& sched){
   // Not our first time. This is after the real unlink actually happened.
  if((int) t.getReturnValue() >= 0){
    removeInodeFromMaps(s.inodeToDelete, gs, t);
    s.inodeToDelete = -1;
  }
  s.firstTrySystemcall = true;

  return;
}
// =======================================================================================
bool
unlinkatSystemCall::handleDetPre(globalState& gs, state& s, ptracer& t, scheduler& sched){
  // Turn into a newfstatat system call.
  bool ret = injectNewfstatatIfNeeded(gs, s, t, (int) t.arg1(), (char*) t.arg2());
  if(ret){
    // We have work to do in the newfstatat post hook! Make sure to intercept this, hence,
    // true.
    return true;
  }
  printInfoString(t.arg2(), gs, s, t);
  // We must go into the post hook to delete the inode.
  return true;
}

void
unlinkatSystemCall::handleDetPost(globalState& gs, state& s, ptracer& t, scheduler& sched){
  // Not our first time. This is after the real unlink actually happened.
  if((int) t.getReturnValue() >= 0){
    removeInodeFromMaps(s.inodeToDelete, gs, t);
    s.inodeToDelete = -1;
  }

  s.firstTrySystemcall = true;

  return;
}

// =======================================================================================
bool utimeSystemCall::handleDetPre(globalState& gs, state& s, ptracer& t, scheduler& sched){
  gs.timeCalls++;
  // Set times to our own logical time for deterministic time only if times is null.
  if((const struct utimbuf*) t.arg2() != nullptr){
    // user specified his/her own time which should be deterministic.
    return false;
  }
  s.originalArg2 = t.arg2();

  // Enough space for 2 timespec structs.
  utimbuf* ourUtimbuf = (utimbuf*) s.mmapMemory.getAddr().ptr;

  // Create our own struct with our time.
  // TODO: In the future we might want to unify this with our mtimeMapper.
  utimbuf clockTime = {
    .actime = 0,
    .modtime = 0,
  };

  // Write our struct to the tracee's memory.
  t.writeToTracee(traceePtr<utimbuf>(ourUtimbuf), clockTime, s.traceePid);

  // Point system call to new address.
  t.writeArg2((uint64_t) ourUtimbuf);
  s.incrementTime();

  // Needed to restore the original value in register.
  return true;
}

void utimeSystemCall::handleDetPost(globalState& gs, state& s, ptracer& t, scheduler& sched){
  // Restore value of register.
  t.writeArg2(s.originalArg2);
}
// =======================================================================================
bool utimesSystemCall::handleDetPre(globalState& gs, state& s, ptracer& t, scheduler& sched){
  gs.timeCalls++;
  // Set times to our own logical time for deterministic time only if times is null.
  if((const struct timeval*) t.arg2() != nullptr){
    // user specified his/her own time which should be deterministic.
    return false;
  }

  // We need somewhere to store a timespec struct if our struct is null. We will write
  // this data below the current stack pointer accounting for the red zone, known to be
  // 128 bytes.
  s.originalArg2 = t.arg2();
  // Enough space for 2 timeval structs.
  timeval* ourTimeval = (timeval*) s.mmapMemory.getAddr().ptr;

  // Create our own struct with our time.
  // TODO: In the future we might want to unify this with our mtimeMapper.
  timeval clockTime = {
    .tv_sec = 0,
    .tv_usec = 0,
  };

  // Write our struct to the tracee's memory.
  t.writeToTracee(traceePtr<timeval>(& (ourTimeval[0])), clockTime, s.traceePid);
  t.writeToTracee(traceePtr<timeval>(& (ourTimeval[1])), clockTime, s.traceePid);

  // Point system call to new address.
  t.writeArg2((uint64_t) ourTimeval);
  s.incrementTime();

  // Needed to restore the original value in register.
  return true;
}

void utimesSystemCall::handleDetPost(globalState& gs, state& s, ptracer& t, scheduler& sched){
  // Restore value of register.
  t.writeArg2(s.originalArg2);
}
// =======================================================================================
bool utimensatSystemCall::handleDetPre(globalState& gs, state& s, ptracer& t, scheduler& sched){
  // Set times to our own logical time for deterministic time only if times is null.
  if((const struct timespec*) t.arg3() != nullptr){
    // user specified his/her own time which should be deterministic.
    return false;
  }

  // We need somewhere to store a timespec struct if our struct is null. We will write
  // this data below the current stack pointer accounting for the red zone, known to be
  // 128 bytes.
  s.originalArg3 = t.arg3();
  // Enough space for 2 timespec structs.
  timespec* ourTimespec = (timespec*) s.mmapMemory.getAddr().ptr;

  // Create our own struct with our time.
  // TODO: In the future we might want to unify this with our mtimeMapper.
  timespec clockTime = {
    .tv_sec = 0,// (time_t) s.getLogicalTime(),
    .tv_nsec = 0, //(time_t) s.getLogicalTime()
  };

  // Write our struct to the tracee's memory.
  t.writeToTracee(traceePtr<timespec>(& (ourTimespec[0])), clockTime, s.traceePid);
  t.writeToTracee(traceePtr<timespec>(& (ourTimespec[1])), clockTime, s.traceePid);

  // Point system call to new address.
  t.writeArg3((uint64_t) ourTimespec);
  s.incrementTime();

  // Needed to restore the original value in register.
  return true;
}

void utimensatSystemCall::handleDetPost(globalState& gs, state& s, ptracer& t, scheduler& sched){
  // Restore value of register.
  t.writeArg3(s.originalArg3);
}
// =======================================================================================
bool writeSystemCall::handleDetPre(globalState& gs, state& s, ptracer& t, scheduler& sched){
  gs.log.writeToLog(Importance::info, "fd: %d\n", t.arg1());
  gs.log.writeToLog(Importance::info, "Bytes to write %d\n", t.arg3());

  return true;
}

void writeSystemCall::handleDetPost(globalState& gs, state& s, ptracer& t, scheduler& sched){
  int fd = t.arg1();
  bool preemptAndTryLater = false;

  auto resetState = [&](){
                      // Nothing left to write.
                      gs.log.writeToLog(Importance::info, "All bytes written.\n");
                      t.setReturnRegister(s.totalBytes);

                      t.writeArg2(s.beforeRetry.rsi);
                      t.writeArg3(s.beforeRetry.rdx);

                      s.firstTrySystemcall = true;
                      s.totalBytes = 0;
                    };

  // Pipe exists in our map and it's set to non blocking.
  if(s.fdStatus.count(fd) != 0 && s.fdStatus[fd] == descriptorType::nonBlocking){
    gs.log.writeToLog(Importance::info,
                      "read found with non-blocking pipe!\n");
    preemptAndTryLater = preemptIfBlocked(gs, s, t, sched, EAGAIN);
    // We have looped, and cannot read any more bytes from the pipe... Return.
    if(preemptAndTryLater){
      gs.log.writeToLog(Importance::info,
                      "All done with non-blocking pipe replay!\n");
      resetState();
      return;
    }
  }else{
    preemptAndTryLater = replaySyscallIfBlocked(gs, s, t, sched, EAGAIN);
    // We have not read all bytes, but pipe has nothing, set ourselves as blocked and we
    // will retry later.
    if(preemptAndTryLater){
      gs.writeRetryEvents++;
      return;
    }
  }

  size_t bytes_written = t.getReturnValue();
  gs.log.writeToLog(Importance::info, "bytesWritten: %d.\n", bytes_written);

  if((int) bytes_written < 0){
    gs.log.writeToLog(Importance::info, "Returned negative: %d.\n",
                      bytes_written);
    return;
  }

  s.totalBytes += bytes_written;
  if(s.firstTrySystemcall){
    s.firstTrySystemcall = false;
    s.beforeRetry = t.getRegs();
  }
  gs.log.writeToLog(Importance::info, "total bytes: %d.\n", bytes_written);
  gs.log.writeToLog(Importance::info, "before retry rdx: %d.\n", s.beforeRetry.rdx);

  // Finally wrote all bytes user wanted.

  // The zero case should not really happen. But our fuse tests allow for this
  // behavior so we catch it here. Otherwise we forever try to read 0 bytes.
  // https://stackoverflow.com/questions/41904221/can-write2-return-0-bytes-written-and-what-to-do-if-it-does?utm_medium=organic&utm_source=google_rich_qa&utm_campaign=google_rich_qa
  if(s.totalBytes == s.beforeRetry.rdx ||
     bytes_written == 0){
    resetState();
  }else{
    gs.log.writeToLog(Importance::info, "Not all bytes written: Replaying system call!\n");
    t.writeArg2(t.arg2() + bytes_written);
    t.writeArg3(t.arg3() - bytes_written);
    replaySystemCall(gs, t, t.getSystemCallNumber());
  }

  return;
}
// =======================================================================================
bool wait4SystemCall::handleDetPre(globalState& gs, state& s, ptracer& t, scheduler& sched){
  s.wait4Blocking = (t.arg3() & WNOHANG) == 0;
  gs.log.writeToLog(Importance::info, "Making this a non-blocking wait4\n");

  // Make this a non blocking hang!
  s.originalArg3 = t.arg3();
  t.writeArg3(s.originalArg3 | WNOHANG);
  return true;
}
void wait4SystemCall::handleDetPost(globalState& gs, state& s, ptracer& t, scheduler& sched){
  if(s.wait4Blocking){
    gs.log.writeToLog(Importance::info, "Non-blocking wait4 found\n");
    replaySyscallIfBlocked(gs, s, t, sched, 0);
  }else{
    gs.log.writeToLog(Importance::info, "Blocking wait4 found\n");
    preemptIfBlocked(gs, s, t, sched, EAGAIN);
  }
  // Reset.
  t.writeArg3(s.originalArg3);

  return;
}
// =======================================================================================
bool writevSystemCall::handleDetPre(globalState& gs, state& s, ptracer& t, scheduler& sched){
  return true;
}

void writevSystemCall::handleDetPost(globalState& gs, state& s, ptracer& t, scheduler& sched){
  // TODO: Handle bytes written.
  // int retVal = t.getReturnValue();
  // if (retVal < 0) {
    // throw runtime_error("dettrace runtime exception: Write failed with: " + string{ strerror(- retVal) });
  // }

  // //uint16_t minus2 = t.readFromTracee((uint16_t*) (t.regs.rip - 2), s.traceePid);
  // uint16_t minus2 = t.readFromTracee((uint16_t*) (t.getRip() - 2), s.traceePid);
  // if (!(minus2 == 0x80CD || minus2 == 0x340F || minus2 == 0x050F)) {
  //   throw runtime_error("dettrace runtime exception: Write failed with: non syscall insn");
  // }
  // ssize_t bytes_written = retVal;
  // s.totalBytes += bytes_written;
  // //ssize_t bytes_requested = t.arg3();

  // if (s.firstTrySystemcall) {
  //   s.firstTrySystemcall = false;
  //   //s.beforeRetry = t.regs;
  //   s.beforeRetry = t.getRegs();
  // }

  // // 0 indicates nothing was written.
  // if (bytes_written != 0) {
  //   t.writeArg2(t.arg2() + bytes_written);
  //   t.writeArg3(t.arg3() - bytes_written);
  //   //t.regs.rax = t.getSystemCallNumber();
  //   t.writeRax(t.getSystemCallNumber());
  //   //t.writeIp(t.regs.rip - 2);
  //   t.writeIp(t.getRip() - 2);
  //  } else { // Nothing left to write.
  //    t.setReturnRegister(s.totalBytes);
  //    t.writeArg1(s.beforeRetry.rdi);
  //    t.writeArg2(s.beforeRetry.rsi);
  //    t.writeArg3(s.beforeRetry.rdx);
  //    s.firstTrySystemcall = true;
  //    s.totalBytes = 0;
  //  }
  return;
}
// =======================================================================================

bool preemptIfBlocked(globalState& gs, state& s, ptracer& t, scheduler& sched,
                            int64_t errornoValue){
  if(- errornoValue == (int64_t) t.getReturnValue()){
    gs.log.writeToLog(Importance::info,
                      s.systemcall->syscallName + " would have blocked!\n");

    sched.preemptAndScheduleNext(s.traceePid, preemptOptions::runnable);
    return true;
  }else{
    // Disambiguiate. Otherwise it's impossible to tell the difference between a
    // maybeRunnable process that made no progress vs the case where we were on
    // maybeRunnable and we made progress, and eventually we hit another blocking
    // system call.
    sched.reportProgress(s.traceePid);
    return false;
  }
}

/**
   This function provides unified handling for timer-based signals stemming from
   alarm(), setitimer() and timer_create().

   The first step is to track a tracee's signal handlers, which can be set via
   rt_sigaction() -- on cat16 at least, the signal() and sigaction() ultimately
   resolve to the rt_sigaction() syscall. Any given signal may be ignored, set
   to its default behavior (usually termination, but it varies by signal), or
   have a custom handler. These handlers for all signals are tracked in
   the state::currentSignalHandlers map.

   Then, when a tracee requests a signal be delivered some time in the future,
   we convert this request into immediate deterministic signal delivery. Let's
   refer to alarm(), setitimer() and timer_settime() as signal-generated
   functions (SGFs).

   If the signal generated by the SGF is being ignored, then we convert the SFG
   into a NOP: instead of actually having a signal sent and risking some
   nondeterministic EINTR on some other system call, we don't send the signal in
   the first place and the tracee shouldn't be able to tell.

   If the signal generated by the SGF is set to cause termination (usually the
   default behavior), we convert the SGF into an exit() syscall.

   If the signal generated by the SGF invokes a custom handler, then we have to
   actually send a real signal. We convert the SGF into a pause() syscall and
   send a real signal from the tracer to the tracee via tgkill(). When the
   tracee receives the signal, its handler will run and pause() will then
   return.
   */
static bool sendTraceeSignalNow(int signum, globalState& gs, state& s, ptracer& t, scheduler& sched) {

  enum sighandler_type sh = SIGHANDLER_DEFAULT;
  if (s.currentSignalHandlers.count(signum)) {
    sh = s.currentSignalHandlers[signum];
  }

  switch (sh) {

  case SIGHANDLER_CUSTOM_1SHOT: {
    gs.log.writeToLog(Importance::info, "tracee has a custom 1-shot signal "+to_string(signum)+" handler, sending signal to pid %u\n", sched.pidMap.getVirtualValue(t.getPid()));

    // TODO: JLD is this a race? the tracee isn't technically paused yet
    t.changeSystemCall(SYS_pause);
    s.signalInjected = true;
    s.currentSignalHandlers[signum] = SIGHANDLER_DEFAULT; // go back to default next time
    int retVal = syscall(SYS_tgkill, t.getPid(), t.getPid(), signum);
    if (0 != retVal) {
      throw runtime_error("dettrace runtime exception: sending myself signal "+to_string(signum)+" failed, tgkill returned " + to_string(retVal));
    }
    return true; // run pause post-hook
  }

  case SIGHANDLER_CUSTOM: {
    gs.log.writeToLog(Importance::info, "tracee has a custom signal "+to_string(signum)+" handler, sending signal to pid %u\n", sched.pidMap.getVirtualValue(t.getPid()));

    // TODO: JLD is this a race? the tracee isn't technically paused yet
    t.changeSystemCall(SYS_pause);
    s.signalInjected = true;
    int retVal = syscall(SYS_tgkill, t.getPid(), t.getPid(), signum);
    if (0 != retVal) {
      throw runtime_error("dettrace runtime exception: sending myself signal "+to_string(signum)+" failed, tgkill returned " + to_string(retVal));
    }
    return true; // run pause post-hook
  }

  case SIGHANDLER_DEFAULT: {
    if (SIGALRM != signum && SIGVTALRM != signum && SIGPROF != signum) {
      throw runtime_error("dettrace runtime exception: can't send myself a signal "+to_string(signum));
    }
    // for SIGALRM, SIGVTALRM, SIGPROF, default handler terminates the tracee
    gs.log.writeToLog(Importance::info, "tracee has default signal "+to_string(signum)+" handler, injecting exit() for pid %u\n", t.getPid());
    t.changeSystemCall(SYS_exit);
    t.writeArg1( 128 + signum ); // status reflects exit due to signal
    return false; // there shouldn't be a post-hook for exit
  }

  case SIGHANDLER_IGNORED: // don't do anything
    replaceSystemCallWithNoop(gs, s, t);
    gs.log.writeToLog(Importance::info, "tracee is ignoring signal "+to_string(signum)+", doing nothing\n");
    return true; // run noop (getpid) post-hook

  default:
    throw runtime_error("dettrace runtime exception: invalid handler "+to_string(sh)+
                        " for signal "+to_string(signum));
  }
}
// =======================================================================================
bool replaySyscallIfBlocked(globalState& gs, state& s, ptracer& t, scheduler& sched, int64_t errornoValue){
  if(- errornoValue == (int64_t) t.getReturnValue()){
    gs.log.writeToLog(Importance::info,
                      s.systemcall->syscallName + " would have blocked!\n");

    gs.replayDueToBlocking++;
    sched.preemptAndScheduleNext(s.traceePid, preemptOptions::markAsBlocked);
    replaySystemCall(gs, t, t.getSystemCallNumber());
    return true;
  }else{
    // Disambiguiate. Otherwise it's impossible to tell the difference between a
    // maybeRunnable process that made no progress vs the case where we were on
    // maybeRunnable and we made progress, and eventually we hit another blocking
    // system call.
    sched.reportProgress(s.traceePid);
    return false;
  }
}
// =======================================================================================
void replaySystemCall(globalState& gs, ptracer& t, uint64_t systemCall){
#ifdef EXTRANEOUS_TRACEE_READS
  uint16_t minus2 = t.readFromTracee(traceePtr<uint16_t>((uint16_t*) ((uint64_t) t.getRip().ptr - 2)), t.getPid());
  if (!(minus2 == 0x80CD || minus2 == 0x340F || minus2 == 0x050F)) {
    throw runtime_error("dettrace runtime exception: IP does not point to system call instruction!\n");
  }
#endif

  gs.totalReplays++;
  // Replay system call!
  t.changeSystemCall(systemCall);
  t.writeIp((uint64_t) t.getRip().ptr - 2);
}
// =======================================================================================
void zeroOutStatfs(struct statfs& stats){
  // Type of filesystem
  stats.f_type = 0xEF53;// EXT4_SUPER_MAGIC
  stats.f_bsize = 100;   /* Optimal transfer block size */
  stats.f_blocks = 1000;  /* Total data blocks in filesystem */
  stats.f_bfree = 10000;   /* Free blocks in filesystem */
  stats.f_bavail = 5000;  /* Free blocks available to
                             unprivileged user */
  stats.f_files = 1000;   /* Total file nodes in filesystem */
  stats.f_ffree = 1000;   /* Free file nodes in filesystem */
  stats.f_fsid.__val[0] = 0;
  stats.f_fsid.__val[1] = 0;
  stats.f_namelen = 200; /* Maximum length of filenames */
  stats.f_frsize = 20;  /* Fragment size (since Linux 2.6) */
  stats.f_flags = 1;   /* Mount flags of filesystem */
}
// =======================================================================================
void handleStatFamily(globalState& gs, state& s, ptracer& t, string syscallName){
  struct stat* statPtr;

  if(syscallName == "newfstatat"){
    statPtr = (struct stat*) t.arg3();
  }else{
    statPtr = (struct stat*) t.arg2();
  }

  if(statPtr == nullptr){
    gs.log.writeToLog(Importance::info, syscallName + ": statbuf null.\n");
    return;
  }

  int retVal = t.getReturnValue();
  if(retVal == 0){
    struct stat myStat = t.readFromTracee(traceePtr<struct stat>(statPtr), s.traceePid);
    ino_t inode = myStat.st_ino;
    gs.log.writeToLog(Importance::extra, "(device,inode) = (%lu,%lu)\n", myStat.st_dev, inode);
    // Use inode to check if we created this file during our run.
    time_t virtualMtime = gs.mtimeMap.realValueExists(inode) ?
      gs.mtimeMap.getVirtualValue(inode) :
      0; // This was an old file that has not been opened for modification.

    /* Time of last access */
    myStat.st_atim = timespec { .tv_sec =  0,
                                .tv_nsec = 0 };
    /* Time of last modification */
    myStat.st_mtim = timespec { .tv_sec =  virtualMtime,
                                .tv_nsec = 0 };
    /* Time of last status change */
    myStat.st_ctim = timespec { .tv_sec = 0,
                                .tv_nsec = 0 };

    // TODO: I'm surprised this doesn't break things. I guess nobody uses this
    // result?
    myStat.st_dev = 1;         /* ID of device containing file */

    myStat.st_ino = gs.inodeMap.realValueExists(inode) ?
      gs.inodeMap.getVirtualValue(inode) :
      gs.inodeMap.addRealValue(inode) ;

    // st_mode holds the permissions to the file. If we zero it out libc functions
    // will think we don't have access to this file. Hence we keep our permissions
    // as part of the stat.
    // mode_t    st_mode;        /* File type and mode */

    myStat.st_nlink = 1;       /* Number of hard links */

    // These should never be set! The container handles group and user id through
    // setting these will lead to inconistencies which will manifest themselves as
    // weird permission denied errors for some system calls.
    // myStat.st_uid = 65534;         /* User ID of owner */
    // myStat.st_gid = 1;         /* Group ID of owner */

    myStat.st_rdev = 1;        /* Device ID (if special file) */

    // Program will stall if we put some arbitrary value here: TODO.
    // myStat.st_size = 512;        /* Total size, in bytes */

    myStat.st_blksize = 512;     /* Block size for filesystem I/O */

    // TODO: could return actual value here?
    myStat.st_blocks = 1;      /* Number of 512B blocks allocated */

    // Write back result for child.
    t.writeToTracee(traceePtr<struct stat>(statPtr), myStat, s.traceePid);
  }
  return;
}
// =======================================================================================
/**
 * Helper function to print path for system call.
 * Given the address of the string (this can be fetched by t.argN() ).
 * It will print this string as a green text to the logger.
 *
 * @arg postFix: This is a default argument. Usually " path:" unless something
 * else is given.
 */
void printInfoString(uint64_t addressOfCString, globalState& gs, state& s, ptracer& t, string postFix){
  if((char*) addressOfCString != nullptr){
    if(gs.log.getDebugLevel() > 0){
      string path = t.readTraceeCString(traceePtr<char>((char*) addressOfCString), s.traceePid);
      string msg = s.systemcall->syscallName + postFix +
        gs.log.makeTextColored(Color::green, path) + "\n";
      gs.log.writeToLog(Importance::info, msg);
    }
  }else{
    gs.log.writeToLog(Importance::info, "Null path given to system call.\n");
  }

  return;
}
// =======================================================================================
// Inject fstat system call. struct stat is written belows the stack and can be fetched
// by ptrace read.
void injectFstat(globalState& gs, state& s, ptracer& t, int fd){
  gs.injectedSystemCalls++;
  gs.log.writeToLog(Importance::info, "Injecting fstat call to tracee!\n");
  // Save current register state to restore in fstat.
  s.regSaver.pushRegisterState(t.getRegs());

  // Inject fstat system call to perform!
  s.syscallInjected = true;

  struct stat* traceesMem = (struct stat*) s.mmapMemory.getAddr().ptr;

  // zero out struct stat memory
  struct stat zeroStat = {0};
  t.writeToTracee(traceePtr<struct stat>(traceesMem), zeroStat, s.traceePid);

  // Call fstat.
  t.writeArg1(fd); // file descriptor.
  t.writeArg2((uint64_t )traceesMem);
  replaySystemCall(gs, t, SYS_fstat);

  gs.log.writeToLog(Importance::info, "fstat(%d, %p)!\n", fd, traceesMem);
}
// =======================================================================================
void injectPause(globalState& gs, state& s, ptracer& t){
  gs.log.writeToLog(Importance::info, "Injecting pause call to tracee!\n");
  s.syscallInjected = true;
  gs.injectedSystemCalls++;

  replaySystemCall(gs, t, SYS_pause);
}
// =======================================================================================
bool injectNewfstatatIfNeeded(globalState& gs, state& s, ptracer& t, int dirfd,
                              char* pathnameTraceesMem){
  // This is not the first time we see this system call. We have already replayed it.
  // not injecting.
  if(! s.firstTrySystemcall){
    auto str = "No need to inject newfstatat in tracee, this is not the first time!\n";
    gs.log.writeToLog(Importance::info, str);
    return false;
  }

  gs.log.writeToLog(Importance::info, "Replacing newfstatat call in tracee!\n");
  gs.injectedSystemCalls++;

  // Save current register state to restore in newfstatat.
  s.regSaver.pushRegisterState(t.getRegs());

  // Inject fstat system call to perform!
  s.syscallInjected = true;

  struct stat* traceesMem = (struct stat*) s.mmapMemory.getAddr().ptr;

  replaySystemCall(gs, t, SYS_newfstatat);
  t.writeArg1(dirfd); // file descriptor.
  t.writeArg2((uint64_t) pathnameTraceesMem);
  t.writeArg3((uint64_t ) traceesMem);
  // Needed to handle directories and symlinks correctly.
  t.writeArg4((uint64_t) AT_SYMLINK_NOFOLLOW | AT_EMPTY_PATH);

  s.firstTrySystemcall = false;

  return true;
}

// =======================================================================================
/*
 * Only delete if exists, not existing is not an error.
 */
void removeInodeFromMaps(ino_t inode, globalState& gs, ptracer& t){

  gs.log.writeToLog(Importance::extra, "Attempting to remove inode %d from maps...\n", inode);

  // Nothing to do.
  if(inode == -1){
    return;
  }

  // Remove from inode and mtime maps if exists.
  if(gs.inodeMap.realValueExists(inode)){
    gs.log.writeToLog(Importance::extra, "Deleted inode from map: %d\n", inode);
    gs.inodeMap.eraseBasedOnKey(inode);
  }
  if(gs.mtimeMap.realValueExists(inode)){
    gs.log.writeToLog(Importance::extra, "Deleted mtime from map: %d\n", inode);
    gs.mtimeMap.eraseBasedOnKey(inode);
  }

  return;
}
// =======================================================================================
// Turn system call into a noop by changing it into a getpid. This should be called from
// the pre hook only!
void replaceSystemCallWithNoop(globalState& gs, state& s, ptracer& t){
  t.changeSystemCall(SYS_getpid);
  gs.log.writeToLog(Importance::info, "Turning this system call into a NOOP\n");
  s.noopSystemCall = true;
  return;
}
// =======================================================================================
pair<int,int> getPipeFds(globalState& gs, state& s, ptracer& t){
// Get values of both file descriptors.
  int* pipefdTracee = (int*) t.arg1();
  traceePtr<int> fdPtr1 = traceePtr<int>(& pipefdTracee[0]);
  traceePtr<int> fdPtr2 = traceePtr<int>(& pipefdTracee[1]);

  int fd1 = t.readFromTracee(fdPtr1, t.getPid());
  int fd2 = t.readFromTracee(fdPtr2, t.getPid());

  gs.log.writeToLog(Importance::info, "Got pipe fd1: " + to_string(fd1) + "\n");
  gs.log.writeToLog(Importance::info, "Got pipe fd2: " + to_string(fd2) + "\n");

  // Track this file descriptor:
  if(s.fdStatus.count(fd1) != 0){
    throw runtime_error("dettrace runtime exception: Value already in map (fdStatus).");
  }
  if(s.fdStatus.count(fd2) != 0){
    throw runtime_error("dettrace runtime exception: Value already in map (fdStatus).");
  }

  return make_pair(fd1, fd2);
}
// =======================================================================================
