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

#include <climits>
#include <cstring>

#include <sys/time.h>
#include <sys/resource.h>
#include <sys/sysinfo.h>
#include <sys/uio.h>
#include <linux/futex.h>
#include <linux/fs.h>
#include <sys/types.h>
#include <utime.h>

#include<unordered_map>

#include "dettraceSystemCall.hpp"
#include "ptracer.hpp"

using namespace std;
// =======================================================================================
// Prototypes for common functions.
void zeroOutStatfs(struct statfs& stats);
void handleStatFamily(globalState& gs, state& s, ptracer& t, string syscallName);
void printInfoString(uint64_t addressOfCString, globalState& gs, state& s,
                     string postFix = " path: ");
void injectFstat(globalState& gs, state& s, ptracer& t, int fd);
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

// =======================================================================================
bool accessSystemCall::handleDetPre(globalState& gs, state& s, ptracer& t, scheduler& sched){
  printInfoString(t.arg1(), gs, s);
  return false;
}
// =======================================================================================
bool chdirSystemCall::handleDetPre(globalState& gs, state& s, ptracer& t, scheduler& sched){
  printInfoString(t.arg1(), gs, s);

  return false;
}
// =======================================================================================
bool chmodSystemCall::handleDetPre(globalState& gs, state& s, ptracer& t, scheduler& sched){
  printInfoString(t.arg1(), gs, s);
  return false;
}
// =======================================================================================
bool chownSystemCall::handleDetPre(globalState& gs, state& s, ptracer& t, scheduler& sched){
  printInfoString(t.arg1(), gs, s);
  return false;
}
// =======================================================================================
void clock_gettimeSystemCall::handleDetPost(globalState& gs, state& s, ptracer& t, scheduler& sched) {
  struct timespec* tp = (struct timespec*) t.arg2();

  if (tp != nullptr) {
    struct timespec myTp = {};
    // TODO: One day, unify time.
    myTp.tv_sec = s.getLogicalTime();
    myTp.tv_nsec = 0;

    ptracer::writeToTracee(tp, myTp, t.getPid());
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
  printInfoString(t.arg1(), gs, s);
  return true;
}

void creatSystemCall::handleDetPost(globalState& gs, state& s, ptracer& t, scheduler& sched){
  // Nothing for us to do skip the post hook!
  if((int) t.getReturnValue() < 0){
    return;
  }

  // Inject fstat, creat always make a new file with write permissions.
  s.prevRegisterState = t.getRegs();
  injectFstat(gs, s, t, t.getReturnValue());
  return;
}
// =======================================================================================
bool execveSystemCall::handleDetPre(globalState& gs, state& s, ptracer& t, scheduler& sched){
  printInfoString(t.arg1(), gs, s);

  char** argv = (char**) t.arg2();
  string execveArgs {};

  // Print all arguments to execve!
  if(argv != nullptr){
    // Remeber these are addresses in the tracee. We must explicitly read them
    // ourselves!
    for(int i = 0; true; i++){
      // Make sure it's non null before reading to string.
      char* address = ptracer::readFromTracee<char*>(&(argv[i]), t.getPid());
      if(address == nullptr){
	break;
      }

      execveArgs += " \"" + ptracer::readTraceeCString(address, t.getPid()) + "\" ";
    }

    auto msg = "Args: " + gs.log.makeTextColored(Color::green, execveArgs) + "\n";
    gs.log.writeToLog(Importance::extra, msg);
  }

  return false;
}
// =======================================================================================
bool fchownatSystemCall::handleDetPre(globalState& gs, state& s, ptracer& t, scheduler& sched){
  printInfoString(t.arg2(), gs, s);

  // int dirfd = t.arg1();
  // uid_t owner = t.arg3();
  // gid_t group = t.arg4();
  // int flags = t.arg5();
  // string fchowatStr = "fchownat(fd = %d, _, owner = %d, group = %d, flags = %d)\n";
  // s.log.writeToLog(Importance::extra, fchowatStr, dirfd, owner, group, flags);
  return false;
}
// =======================================================================================
bool faccessatSystemCall::handleDetPre(globalState& gs, state& s, ptracer& t,
                                       scheduler& sched){
  printInfoString(t.arg2(), gs, s);

  return false;
}
// =======================================================================================
void fgetxattrSystemCall::handleDetPost(globalState& gs, state& s, ptracer& t,
                                        scheduler& sched){
  printInfoString(t.arg2(), gs, s);

  return;
}
// =======================================================================================
void flistxattrSystemCall::handleDetPost(globalState& gs, state& s, ptracer& t,
                                         scheduler& sched){
  printInfoString(t.arg2(), gs, s);

  return;
}
// =======================================================================================
void fstatSystemCall::handleDetPost(globalState& gs, state& s, ptracer& t, scheduler& sched){

  // This isn't a natural call fstat from the tracee we injected this call ourselves!
  if(s.fstatMtimeInjection){
    gs.log.writeToLog(Importance::info, "This fstat was inject for mtime puposes.\n");
    if((int) t.getReturnValue() < 0){
      throw runtime_error("Unable to properly inject fstat call to tracee!"
                          "fstat call returned: " + to_string(t.getReturnValue()) + "\n");
    }
    s.fstatMtimeInjection = false;
    struct stat myStat = ptracer::readFromTracee((struct stat*) t.arg2(), s.traceePid);

    // Add an entry for this new file to our inode with a newer modified date.
    if( ! gs.mtimeMap.realValueExists(myStat.st_ino) ){
      gs.mtimeMap.addRealValue(myStat.st_ino);
    }

    // Previous state that should have been set by system call that created this fstat
    // injection.
    t.setRegs(s.prevRegisterState);
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

  // Read values written to by system call.
  struct statfs myStatfs = ptracer::readFromTracee(statfsPtr, s.traceePid);

  if(t.getReturnValue() == 0){
    // Assume we're using this file sytem?
    zeroOutStatfs(myStatfs);

    // Write back result for child.
    ptracer::writeToTracee(statfsPtr, myStatfs, s.traceePid);
  }

  return;
}
// =======================================================================================
bool futexSystemCall::handleDetPre(globalState& gs, state& s, ptracer& t, scheduler& sched){
  // If operation is a FUTEX_WAIT, set timeout to zero. That is, immediately return
  // instead of blocking.
  int futexOp = t.arg2();
  timespec* timeoutPtr = (timespec*) t.arg4();

  gs.log.writeToLog(Importance::extra, "Futex operation: %d.\n", futexOp);

  // See definitions of variables here.
  // https://github.com/spotify/linux/blob/master/include/linux/futex.h
  int futexCmd = futexOp & FUTEX_CMD_MASK;
  if(futexCmd == FUTEX_WAIT ||
     futexCmd == FUTEX_WAIT_BITSET ||
     futexCmd == FUTEX_WAIT_REQUEUE_PI
     ){
    gs.log.writeToLog(Importance::extra, "Futex wait operation.\n");
    // Overwrite the current value with our value. Restore value in post hook.
    s.originalArg4 = (uint64_t) timeoutPtr;
    // Our timespec value to copy over.
    timespec ourTimeout = {0};

    if(timeoutPtr == nullptr){
      // We need somewhere to store timespec. We will write this data below the current
      // stack pointer accounting for the red zone, known to be 128 bytes.
      gs.log.writeToLog(Importance::extra,
  		       "timeout null, writing our data below the current stack frame...\n");

      uint64_t rsp = t.getRsp();
      // Enough space for timespec struct.
      timespec* newAddress = (timespec*) (rsp - 128 - sizeof(struct timespec));

      ptracer::writeToTracee(newAddress, ourTimeout, s.traceePid);

      // Point system call to new address.
      t.writeArg4((uint64_t) newAddress);
    }else{
      timespec timeout = ptracer::readFromTracee(timeoutPtr, t.getPid());
      gs.log.writeToLog(Importance::extra,
                       "Writing over original timeout value: (s = %d, ns = %d)\n",
                       timeout.tv_sec, timeout.tv_nsec);
      ptracer::writeToTracee(timeoutPtr, ourTimeout, s.traceePid);
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
    // Restore register state.
    t.writeArg4(s.originalArg4);

    replaySyscallIfBlocked(gs, s, t, sched, ETIMEDOUT);
  }
  return;
}
// =======================================================================================
void getcwdSystemCall::handleDetPost(globalState& gs, state& s, ptracer& t,
                                     scheduler& sched){
  printInfoString(t.arg1(), gs, s);

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
    throw runtime_error("Call to getpeername with network socket not suported.\n");
  }
  return;
}
// =======================================================================================
void getrandomSystemCall::handleDetPost(globalState& gs, state& s, ptracer& t, scheduler& sched){
  // Fill buffer with our own deterministic values.
  char* buf = (char*) t.arg1();
  size_t bufLength = (size_t) t.arg2();

  const int flags = 0;
  char constValues[bufLength];
  for(size_t i = 0; i < bufLength; i++){
    constValues[i] = i;
  }

  // Ptrace write is way too slow as it works at word granularity. Time to use
  // process_vm_writev!
  const iovec local = {constValues, // Starting address
			bufLength,   // number of bytes to transfer.
  };

  const iovec traceeMem = {buf, // Starting address
			   bufLength,   // number of bytes to transfer.
  };

  doWithCheck(process_vm_writev(t.getPid(), &local, 1, &traceeMem, 1, flags),
	      "process_vm_writev");

  return;
}
// =======================================================================================
void getrlimitSystemCall::handleDetPost(globalState& gs, state& s, ptracer& t, scheduler& sched){
  struct rlimit* rp = (struct rlimit*) t.arg2();
  if (rp != nullptr) {
    struct rlimit noLimits = {};
    // TODO See prlimit64SystemCall
    // noLimits.rlim_cur = RLIM_INFINITY;
    // noLimits.rlim_max = RLIM_INFINITY;

    // ptracer::writeToTracee(rp, noLimits, t.getPid());
  }

  return;
}
// =======================================================================================
void getrusageSystemCall::handleDetPost(globalState& gs, state& s, ptracer& t, scheduler& sched){
  struct rusage* usagePtr = (struct rusage*) t.arg2();

  if(usagePtr == nullptr){
    gs.log.writeToLog(Importance::info, "getrusage pointer null.");
  }else{
    struct rusage usage = ptracer::readFromTracee(usagePtr, t.getPid());
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

    ptracer::writeToTracee(usagePtr, usage, t.getPid());
  }

  s.incrementTime();
  return;
}
// =======================================================================================
void gettimeofdaySystemCall::handleDetPost(globalState& gs, state& s, ptracer& t, scheduler& sched){
  struct timeval* tp = (struct timeval*) t.arg1();
  if (nullptr != tp) {
    struct timeval myTv = {};
    myTv.tv_sec = s.getLogicalTime();
    myTv.tv_usec = 0;

    ptracer::writeToTracee(tp, myTv, t.getPid());
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
    throw runtime_error("Unsupported ioctl call: fd=" + to_string(t.arg1()) +
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

bool nanosleepSystemCall::handleDetPre(globalState& gs, state& s, ptracer& t, scheduler& sched){
  return true;
}

void nanosleepSystemCall::handleDetPost(globalState& gs, state& s, ptracer& t, scheduler& sched){
  // TODO: Turn nano sleep into a no op.

  return;
}
// =======================================================================================
bool mkdirSystemCall::handleDetPre(globalState& gs, state& s, ptracer& t,
                                   scheduler& sched){
  printInfoString(t.arg1(), gs, s);

  return false;
}
// =======================================================================================
bool mkdiratSystemCall::handleDetPre(globalState& gs, state& s, ptracer& t,
                                     scheduler& sched){
  printInfoString(t.arg2(), gs, s);

  return false;
}
// =======================================================================================
void newfstatatSystemCall::handleDetPost(globalState& gs, state& s, ptracer& t,
                                         scheduler& sched){
  printInfoString(t.arg2(), gs, s);

  handleStatFamily(gs, s, t, "newfstatat");
  return;
}
// =======================================================================================
bool lstatSystemCall::handleDetPre(globalState& gs, state& s, ptracer& t, scheduler& sched){
  printInfoString(t.arg1(), gs, s);

  return true;
}

void lstatSystemCall::handleDetPost(globalState& gs, state& s, ptracer& t, scheduler& sched){
  handleStatFamily(gs, s, t, "lstat");
  return;
}
// =======================================================================================
bool openSystemCall::handleDetPre(globalState& gs, state& s, ptracer& t, scheduler& sched){
  printInfoString(t.arg1(), gs, s);

  return true;
}

void openSystemCall::handleDetPost(globalState& gs, state& s, ptracer& t, scheduler& sched){
  // Nothing for us to do skip the post hook!
  if((int) t.getReturnValue() < 0){
    return;
  }

  s.prevRegisterState = t.getRegs();
  int flags = t.arg2();

  // Check if this file is modifiable by tracee.
  if(flags & (O_WRONLY | O_RDWR | O_APPEND | O_TRUNC | O_CREAT)){
    injectFstat(gs, s, t, t.getReturnValue());
  }
}
// =======================================================================================
bool openatSystemCall::handleDetPre(globalState& gs, state& s, ptracer& t, scheduler& sched){
  printInfoString(t.arg2(), gs, s);

  return true;
}

void openatSystemCall::handleDetPost(globalState& gs, state& s, ptracer& t, scheduler& sched){
   // Nothing for us to do skip the post hook!
  if((int) t.getReturnValue() < 0){
    return;
  }

  s.prevRegisterState = t.getRegs();
  int flags = t.arg3();

  // Check if this file is modifiable by tracee.
  if(flags & (O_WRONLY | O_RDWR | O_APPEND | O_TRUNC | O_CREAT)){
    injectFstat(gs, s, t, t.getReturnValue());
  }
}
// =======================================================================================
bool pipeSystemCall::handleDetPre(globalState& gs, state& s, ptracer& t, scheduler& sched){
  gs.log.writeToLog(Importance::info, "Making this pipe non-blocking\n");
  // Convert pipe call to pipe2 to set O_NONBLOCK.
  t.changeSystemCall(SYS_pipe2);
  s.originalArg2 = t.arg2();
  t.writeArg2(O_NONBLOCK);

  return true;
}

void pipeSystemCall::handleDetPost(globalState& gs, state& s, ptracer& t, scheduler& sched){
  // Restore original registers.
  t.writeArg2(s.originalArg2);
}
// =======================================================================================
bool pipe2SystemCall::handleDetPre(globalState& gs, state& s, ptracer& t, scheduler& sched){
  gs.log.writeToLog(Importance::info, "Making this pipe2 non-blocking\n");
  // Convert pipe call to pipe2 to set O_NONBLOCK.
  s.originalArg2 = t.arg2();
  t.writeArg2(t.arg2() | O_NONBLOCK);

  return true;
}

void pipe2SystemCall::handleDetPost(globalState& gs, state& s, ptracer& t, scheduler& sched){
  // Restore original registers.
  t.writeArg2(s.originalArg2);
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
  t.writeArg3(0);
  return true;
}

void pollSystemCall::handleDetPost(globalState& gs, state& s, ptracer& t, scheduler& sched){
  bool replay = replaySyscallIfBlocked(gs, s, t, sched, 0);
  // Restore state of argument 3.
  if(replay){
    t.writeArg3(s.originalArg3);
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
    throw runtime_error("prlimit64: We do not support prlimit64 on other processes.\n "
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
    // ptracer::writeToTracee(rp, noLimits, t.getPid());
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
  bool replay = replaySyscallIfBlocked(gs, s, t, sched, EAGAIN);
  if(replay){
    return;
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
    // readVmTracee((void*) t.arg2(), buffer, bytes_read, s.traceePid);
    // gs.log.writeToLog(Importance::extra, "Read output: \"\n");
    // for(int i = 0; i < bytes_read; i++){
      // gs.log.writeToLog(Importance::extra, "%d", (int) buffer[i]);
    // }
    // gs.log.writeToLog(Importance::extra, "\"\n");
  }

  // Replay system call if not enought bytes were read.
  s.totalBytes += bytes_read;

  if(s.firstTryReadWrite){
    gs.log.writeToLog(Importance::info, "First time seeing this read!\n");
    s.firstTryReadWrite = false;
    s.beforeRetry = t.getRegs();
  }

  if(bytes_read == 0  || // EOF
     s.totalBytes == s.beforeRetry.rdx  // original bytes requested
     ) {
    gs.log.writeToLog(Importance::info, "EOF or read all bytes.\n");
    // EOF, or read returned everything we asked for.
    // Restore user regs so that it appears as if only one syscall occurred
    t.setReturnRegister(s.totalBytes);
    t.writeArg2(s.beforeRetry.rsi);
    t.writeArg3(s.beforeRetry.rdx);

    // reset for next syscall that we may have to retry
    s.firstTryReadWrite = true;
    s.totalBytes = 0;
  } else {
    gs.log.writeToLog(Importance::info, "Got less bytes than requested.\n");
    t.writeArg2(t.arg2() + bytes_read);
    t.writeArg3(t.arg3() - bytes_read);

    replaySystemcall(t);
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
  printInfoString(t.arg1(), gs, s);

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
  printInfoString(t.arg1(), gs, s, " renaming-ing path: ");
  printInfoString(t.arg2(), gs, s, " to path: ");

  return false;

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
  // Nothing to do for now. (Until fixed)
  return false;

	static bool first = true;
	// Set the timeout to zero.
  timespec* timeoutPtr = (timespec*) t.arg5();
  s.originalArg5 = (uint64_t) timeoutPtr;
  timespec ourTimeout = {0};
  ourTimeout.tv_sec = 5;

  if(timeoutPtr == nullptr){
    // Has to be created in memory.
    uint64_t rsp = t.getRsp();
    timespec* newAddr = (timespec*) (rsp - 128 - sizeof(struct timespec));
if(first){
    ptracer::writeToTracee(newAddr, ourTimeout, s.traceePid);
 t.writeArg5((uint64_t) newAddr);
 first = false;
}
}else{
    // Already exists in memory.
  //  ptracer::writeToTracee(timeoutPtr, ourTimeout, s.traceePid);
  }

  return true;
}

void selectSystemCall::handleDetPost(globalState& gs, state& s, ptracer& t, scheduler& sched){
  //uint64_t retVal = t.getReturnValue();
  // restore return val todo
  replaySyscallIfBlocked(gs, s, t, sched, 0);
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
  printInfoString(t.arg1(), gs, s);

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

  // Read values written to by system call.
  struct statfs stats = ptracer::readFromTracee(statfsPtr, s.traceePid);
  if(t.getReturnValue() == 0){
    // Assume we're using this file sytem?
    zeroOutStatfs(stats);

    // Write back result for child.
    ptracer::writeToTracee(statfsPtr, stats, s.traceePid);
  }

  return;
}
// =======================================================================================
void sysinfoSystemCall::handleDetPost(globalState& gs, state& s, ptracer& t, scheduler& sched){
  struct sysinfo* infoPtr = (struct sysinfo *) t.arg1();
  if(infoPtr == nullptr){
    return;
  }

  struct sysinfo info = {0};
  info.uptime = LONG_MAX;
  info.totalram = LONG_MAX;
  info.freeram = LONG_MAX;
  info.sharedram = LONG_MAX;
  info.bufferram = LONG_MAX;
  info.totalswap = LONG_MAX;
  info.freeswap = LONG_MAX;
  info.procs = SHRT_MAX;
  info.totalhigh = LONG_MAX;
  info.freehigh = LONG_MAX;


  info.loads[0] = LONG_MAX;
  info.loads[1] = LONG_MAX;
  info.loads[2] = LONG_MAX;

  ptracer::writeToTracee(infoPtr, info, t.getPid());
  return;
}
// =======================================================================================
bool symlinkSystemCall::handleDetPre(globalState& gs, state& s, ptracer& t, scheduler& sched){
  printInfoString(t.arg1(), gs, s, " target: ");
  printInfoString(t.arg2(), gs, s, " linkpath: ");
  return false;
}
// =======================================================================================
bool tgkillSystemCall::handleDetPre(globalState& gs, state& s, ptracer& t, scheduler& sched){
  int tgid = (int) t.arg1();
  int tid = (int) t.arg2();
  int signal = (int) t.arg3();
  gs.log.writeToLog(Importance::info, "tgkill(tgid = %d, tid = %d, signal = %d)\n",
		   tgid, tid, signal);
  return true;
}

void tgkillSystemCall::handleDetPost(globalState& gs, state& s, ptracer& t, scheduler& sched){
  return;
}
// =======================================================================================
void timeSystemCall::handleDetPost(globalState& gs, state& s, ptracer& t, scheduler& sched){
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

  ptracer::writeToTracee(timePtr, (time_t) s.getLogicalTime(), s.traceePid);
  // Tick up time.
  s.incrementTime();
  return;
}
// =======================================================================================
void timesSystemCall::handleDetPost(globalState& gs, state& s, ptracer& t, scheduler& sched){
  // Failure nothing for us to do.
  if((int) t.getReturnValue() < 0){
    return;
  }

  tms* bufPtr = (tms*) t.arg1();
  gs.log.writeToLog(Importance::info, "times: buf is null.");
  if(bufPtr != nullptr){
    tms myTms = {
      .tms_utime = 0,
      .tms_stime = 0,
      .tms_cutime = 0,
      .tms_cstime = 0,
    };

    ptracer::writeToTracee(bufPtr, myTms, s.traceePid);
  }

  t.writeRax(0);
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
      throw runtime_error("unameSystemCall::handleDetPost: struct utsname members too small!");
    }

    // NB: this is our standard environment
    strncpy(myUts.sysname, "Linux", MEMBER_LENGTH);
    strncpy(myUts.release, "4.0", MEMBER_LENGTH);
    strncpy(myUts.version, "#1", MEMBER_LENGTH);
    strncpy(myUts.machine, "x86_64", MEMBER_LENGTH);

    ptracer::writeToTracee(utsnamePtr, myUts, t.getPid());
  }
  return;
}
// =======================================================================================
bool unlinkSystemCall::handleDetPre(globalState& gs, state& s, ptracer& t, scheduler& sched){
  printInfoString(t.arg1(), gs, s);

  return false;
}

// =======================================================================================
bool unlinkatSystemCall::handleDetPre(globalState& gs, state& s, ptracer& t, scheduler& sched){
  printInfoString(t.arg2(), gs, s);

  return true;
}

// =======================================================================================
bool utimeSystemCall::handleDetPre(globalState& gs, state& s, ptracer& t, scheduler& sched){
  // Set times to our own logical time for deterministic time only if times is null.
  if((const struct utimbuf*) t.arg2() != nullptr){
    // user specified his/her own time which should be deterministic.
    return false;
  }
  s.originalArg2 = t.arg2();

  // Enough space for 2 timespec structs.
  utimbuf* ourUtimbuf = (utimbuf*) (t.getRsp() - 128 - sizeof(utimbuf));

  // Create our own struct with our time.
  // TODO: In the future we might want to unify this with our mtimeMapper.
  utimbuf clockTime = {
    .actime = 0,
    .modtime = 0,
  };

  // Write our struct to the tracee's memory.
  ptracer::writeToTracee(ourUtimbuf, clockTime, s.traceePid);

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
  // Set times to our own logical time for deterministic time only if times is null.
  if((const struct timeval*) t.arg2() != nullptr){
    // user specified his/her own time which should be deterministic.
    return false;
  }

  // We need somewhere to store a timespec struct if our struct is null. We will write
  // this data below the current stack pointer accounting for the red zone, known to be
  // 128 bytes.
  s.originalArg2 = t.arg2();
  uint64_t rsp = t.getRsp();
  // Enough space for 2 timeval structs.
  timeval* ourTimeval = (timeval*) (rsp - 128 - 2 * sizeof(timeval));

  // Create our own struct with our time.
  // TODO: In the future we might want to unify this with our mtimeMapper.
  timeval clockTime = {
    .tv_sec = 0,
    .tv_usec = 0,
  };

  // Write our struct to the tracee's memory.
  ptracer::writeToTracee(& (ourTimeval[0]), clockTime, s.traceePid);
  ptracer::writeToTracee(& (ourTimeval[1]), clockTime, s.traceePid);

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
  uint64_t rsp = t.getRsp();
  // Enough space for 2 timespec structs.
  timespec* ourTimespec = (timespec*) (rsp - 128 - 2 * sizeof(timespec));

  // Create our own struct with our time.
  // TODO: In the future we might want to unify this with our mtimeMapper.
  timespec clockTime = {
    .tv_sec = 0,// (time_t) s.getLogicalTime(),
    .tv_nsec = 0, //(time_t) s.getLogicalTime()
  };

  // Write our struct to the tracee's memory.
  ptracer::writeToTracee(& (ourTimespec[0]), clockTime, s.traceePid);
  ptracer::writeToTracee(& (ourTimespec[1]), clockTime, s.traceePid);

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
  auto replay = replaySyscallIfBlocked(gs, s, t, sched, EAGAIN);
  if(replay){
    return;
  }

  size_t bytes_written = t.getReturnValue();
  gs.log.writeToLog(Importance::info, "bytesWritten: %d.\n", bytes_written);

  if((int) bytes_written < 0){
    gs.log.writeToLog(Importance::info, "Returned negative: %d.\n",
                     bytes_written);
    return;
  }



  s.totalBytes += bytes_written;
  if(s.firstTryReadWrite){
    s.firstTryReadWrite = false;
    s.beforeRetry = t.getRegs();
  }

  // Finally wrote all bytes user wanted.

  // The zero case should not really happen. But our fuse tests allow for this
  // behavior so we catch it here. Otherwise we forever try to read 0 bytes.
  // https://stackoverflow.com/questions/41904221/can-write2-return-0-bytes-written-and-what-to-do-if-it-does?utm_medium=organic&utm_source=google_rich_qa&utm_campaign=google_rich_qa
  if(s.totalBytes == s.beforeRetry.rdx ||
     bytes_written == 0){
    // Nothing left to write.
    gs.log.writeToLog(Importance::info, "All bytes written.\n");
    t.setReturnRegister(s.totalBytes);

    t.writeArg2(s.beforeRetry.rsi);
    t.writeArg3(s.beforeRetry.rdx);

    s.firstTryReadWrite = true;
    s.totalBytes = 0;
  }else{
    gs.log.writeToLog(Importance::info, "Not all bytes written: Replaying system call!\n");
    t.writeArg2(t.arg2() + bytes_written);
    t.writeArg3(t.arg3() - bytes_written);
    replaySystemcall(t);
  }

  return;
}
// =======================================================================================
bool wait4SystemCall::handleDetPre(globalState& gs, state& s, ptracer& t, scheduler& sched){
  gs.log.writeToLog(Importance::info, "Making this a non-blocking wait4\n");

  // Make this a non blocking hang!
  s.originalArg3 = t.arg3();
  t.writeArg3(s.originalArg3 | WNOHANG);
  return true;
}
void wait4SystemCall::handleDetPost(globalState& gs, state& s, ptracer& t, scheduler& sched){
  bool replayed = replaySyscallIfBlocked(gs, s, t, sched, 0);
  if(!replayed){
    t.writeArg3(s.originalArg3);
  }

  return;
}
// =======================================================================================
bool writevSystemCall::handleDetPre(globalState& gs, state& s, ptracer& t, scheduler& sched){
  return true;
}

void writevSystemCall::handleDetPost(globalState& gs, state& s, ptracer& t, scheduler& sched){
  // TODO: Handle bytes written.
  int retVal = t.getReturnValue();
  if (retVal < 0) {
    throw runtime_error("Write failed with: " + string{ strerror(- retVal) });
  }

  // //uint16_t minus2 = t.readFromTracee((uint16_t*) (t.regs.rip - 2), s.traceePid);
  // uint16_t minus2 = t.readFromTracee((uint16_t*) (t.getRip() - 2), s.traceePid);
  // if (!(minus2 == 0x80CD || minus2 == 0x340F || minus2 == 0x050F)) {
  //   throw runtime_error("Write failed with: non syscall insn");
  // }
  // ssize_t bytes_written = retVal;
  // s.totalBytes += bytes_written;
  // //ssize_t bytes_requested = t.arg3();

  // if (s.firstTryReadWrite) {
  //   s.firstTryReadWrite = false;
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
  //    s.firstTryReadWrite = true;
  //    s.totalBytes = 0;
  //  }
  return;
}
// =======================================================================================
bool replaySyscallIfBlocked(globalState& gs, state& s, ptracer& t, scheduler& sched, int64_t errornoValue){
  if(- errornoValue == (int64_t) t.getReturnValue()){
    gs.log.writeToLog(Importance::info,
                     s.systemcall->syscallName + " would have blocked!\n");

    sched.preemptAndScheduleNext(s.traceePid);
    replaySystemcall(t);
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
void replaySystemcall(ptracer& t){
  uint16_t minus2 = t.readFromTracee((uint16_t*) (t.getRip() - 2), t.getPid());
  if (!(minus2 == 0x80CD || minus2 == 0x340F || minus2 == 0x050F)) {
    throw runtime_error("IP does not point to system call instruction!\n");
  }

  // Replay system call!
  t.writeRax(t.getSystemCallNumber());
  t.writeIp(t.getRip() - 2);
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
    struct stat myStat = ptracer::readFromTracee(statPtr, s.traceePid);
    ino_t inode = myStat.st_ino;
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

    // inode virtualization
    if( ! gs.inodeMap.realValueExists(inode) ){
      gs.inodeMap.addRealValue(inode);
    }
    myStat.st_ino = gs.inodeMap.getVirtualValue(inode);

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

    // s.incrementTime();

    // Write back result for child.
    ptracer::writeToTracee(statPtr, myStat, s.traceePid);
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
void printInfoString(uint64_t addressOfCString, globalState& gs, state& s, string postFix){
  if((char*) addressOfCString != nullptr){
    string path = ptracer::readTraceeCString((char*) addressOfCString, s.traceePid);
    string msg = s.systemcall->syscallName + postFix +
      gs.log.makeTextColored(Color::green, path) + "\n";
    gs.log.writeToLog(Importance::info, msg);
  }else{
    gs.log.writeToLog(Importance::info, "Null path given to system call.\n");
  }

  return;
}
// =======================================================================================
// Inject fstat system call. struct stat is written belows the stack and can be fetched
// by ptrace read.
void injectFstat(globalState& gs, state& s, ptracer& t, int fd){
  gs.log.writeToLog(Importance::info, "Injecting fstat call to tracee!\n");
  // Save current register state to restore in fstat.
  s.prevRegisterState = t.getRegs();

  // Inject fstat system call to perform!
  s.fstatMtimeInjection = true;

  uint64_t rsp = t.getRsp();
  struct stat* traceesMem = (struct stat*) (rsp - 128 - sizeof(struct stat));

  // This does most of the work, but it will try to replay open! Change it to fstat.
  replaySystemcall(t);

  // This should NOT be moved before "replaySystemCall"!
  t.writeRax(SYS_fstat);
  t.writeArg1(fd); // file descriptor.
  t.writeArg2((uint64_t )traceesMem);

  gs.log.writeToLog(Importance::info, "fstat(%d, %p)!\n", fd, traceesMem);
}
// =======================================================================================
