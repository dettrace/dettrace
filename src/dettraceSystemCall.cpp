#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/utsname.h>
#include <sys/ioctl.h>
#include <fcntl.h>              /* Obtain O_* constant definitions */
#include <inttypes.h>

#include <climits>
#include <cstring>

#include <sys/time.h>
#include <sys/resource.h>
#include <sys/sysinfo.h>
#include <sys/uio.h>
#include <linux/futex.h>
#include <linux/fs.h>

#include "dettraceSystemCall.hpp"
#include "ptracer.hpp"

using namespace std;
// =======================================================================================
// Prototypes for common functions.
void zeroOutStatfs(struct statfs& stats);
void handleStatFamily(state& s, ptracer& t, string syscallName);
void printInfoString(uint64_t addressOfCString, state& s, string postFix = " path: ");

/**
 *
 * Replays system call if the value of errnoValue is equal to the errno value that the libc
 * call would have returned. Also logs event in logger. For example for read:
 *   replaySyscallIfBlocked(s, t, sched, EAGAIN);
 *
 * @return: true if call was replayed, else false.
 */
bool replaySyscallIfBlocked(state& s, ptracer& t, scheduler& sched, int64_t errnoValue);

// =======================================================================================
bool accessSystemCall::handleDetPre(state& s, ptracer& t, scheduler& sched){
  printInfoString(t.arg1(), s);
  return false;
}
// =======================================================================================
bool chdirSystemCall::handleDetPre(state& s, ptracer& t, scheduler& sched){
  printInfoString(t.arg1(), s);

  return false;
}
// =======================================================================================
bool chmodSystemCall::handleDetPre(state& s, ptracer& t, scheduler& sched){
  printInfoString(t.arg1(), s);
  return false;
}
// =======================================================================================
bool chownSystemCall::handleDetPre(state& s, ptracer& t, scheduler& sched){
  printInfoString(t.arg1(), s);
  return false;
}
// =======================================================================================
void clock_gettimeSystemCall::handleDetPost(state& s, ptracer& t, scheduler& sched) {
  struct timespec* tp = (struct timespec*) t.arg2();

  if (tp != nullptr) {
    struct timespec myTp = {};
    myTp.tv_sec = s.getLogicalTime();
    myTp.tv_nsec = 0;

    ptracer::writeToTracee(tp, myTp, t.getPid());
    s.incrementTime();
  }
  return;
}
// =======================================================================================
// TODO
bool connectSystemCall::handleDetPre(state& s, ptracer& t, scheduler& sched){
  return true;
}

void connectSystemCall::handleDetPost(state& s, ptracer& t, scheduler& sched){
  return;
}
// =======================================================================================
bool creatSystemCall::handleDetPre(state& s, ptracer& t, scheduler& sched){
  printInfoString(t.arg1(), s);
  return false;
}
// =======================================================================================
bool execveSystemCall::handleDetPre(state& s, ptracer& t, scheduler& sched){
  printInfoString(t.arg1(), s);

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

    auto msg = "Args: " + logger::makeTextColored(Color::green, execveArgs) + "\n";
    s.log.writeToLog(Importance::extra, msg);
  }

  return false;
}
// =======================================================================================
bool fchownatSystemCall::handleDetPre(state& s, ptracer& t, scheduler& sched){
  printInfoString(t.arg2(), s);

  // int dirfd = t.arg1();
  // uid_t owner = t.arg3();
  // gid_t group = t.arg4();
  // int flags = t.arg5();
  // string fchowatStr = "fchownat(fd = %d, _, owner = %d, group = %d, flags = %d)\n";
  // s.log.writeToLog(Importance::extra, fchowatStr, dirfd, owner, group, flags);
  return false;
}
// =======================================================================================
bool faccessatSystemCall::handleDetPre(state& s, ptracer& t, scheduler& sched){
   printInfoString(t.arg2(), s);

  return false;
}
// =======================================================================================
void fgetxattrSystemCall::handleDetPost(state& s, ptracer& t, scheduler& sched){
  printInfoString(t.arg2(), s);

  return;
}
// =======================================================================================
void flistxattrSystemCall::handleDetPost(state& s, ptracer& t, scheduler& sched){
  printInfoString(t.arg2(), s);

  return;
}
// =======================================================================================
void fstatSystemCall::handleDetPost(state& s, ptracer& t, scheduler& sched){
  handleStatFamily(s, t, "fstat");
  return;
}
// =======================================================================================
void fstatfsSystemCall::handleDetPost(state& s, ptracer& t, scheduler& sched){
  struct statfs* statfsPtr = (struct statfs*) t.arg2();

  if(statfsPtr == nullptr){
    s.log.writeToLog(Importance::info, "fstatfs: statfsbuf null.\n");
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
bool futexSystemCall::handleDetPre(state& s, ptracer& t, scheduler& sched){
  // If operation is a FUTEX_WAIT, set timeout to zero. That is, immediately return
  // instead of blocking.
  int futexOp = t.arg2();
  timespec* timeoutPtr = (timespec*) t.arg4();

  s.log.writeToLog(Importance::extra, "Futex operation: %d.\n", futexOp);

  // See definitions of variables here.
  // https://github.com/spotify/linux/blob/master/include/linux/futex.h
  int futexCmd = futexOp & FUTEX_CMD_MASK;
  if(futexCmd == FUTEX_WAIT ||
     futexCmd == FUTEX_WAIT_BITSET ||
     futexCmd == FUTEX_WAIT_REQUEUE_PI
     ){
    s.log.writeToLog(Importance::extra, "Futex wait operation.\n");
    // Overwrite the current value with our value. Restore value in post hook.
    s.originalArg4 = (uint64_t) timeoutPtr;
    // Our timespec value to copy over.
    timespec ourTimeout = {0};

    if(timeoutPtr == nullptr){
      // We need somewhere to store timespec. We will write this data below the current
      // stack pointer accounting for the red zone, known to be 128 bytes.
      s.log.writeToLog(Importance::extra,
  		       "timeout null, writing our data below the current stack frame...\n");

      uint64_t rsp = t.getRsp();
      // Enough space for timespec struct.
      timespec* newAddress = (timespec*) (rsp - 128 - sizeof(struct timespec));

      ptracer::writeToTracee(newAddress, ourTimeout, s.traceePid);

      // Point system call to new address.
      t.writeArg4((uint64_t) newAddress);
    }else{
      timespec timeout = ptracer::readFromTracee(timeoutPtr, t.getPid());
      s.log.writeToLog(Importance::extra,
                       "Writing over original timeout value: (s = %d, ns = %d)\n",
                       timeout.tv_sec, timeout.tv_nsec);
      ptracer::writeToTracee(timeoutPtr, ourTimeout, s.traceePid);
    }
  }

  return true;
}

void futexSystemCall::handleDetPost(state& s, ptracer& t, scheduler& sched){
  int futexOp = t.arg2();
  int futexCmd = futexOp & FUTEX_CMD_MASK;
  if(futexCmd == FUTEX_WAIT ||
     futexCmd == FUTEX_WAIT_BITSET ||
     futexCmd == FUTEX_WAIT_REQUEUE_PI
     ){
    // Restore register state.
    t.writeArg4(s.originalArg4);

    replaySyscallIfBlocked(s, t, sched, ETIMEDOUT);
  }
  return;
}
// =======================================================================================
bool getcwdSystemCall::handleDetPre(state& s, ptracer& t, scheduler& sched){
  printInfoString(t.arg1(), s);

  return false;
}
// =======================================================================================
// TODO Virtualize inodes!
bool getdentsSystemCall::handleDetPre(state& s, ptracer& t, scheduler& sched){
  return true;
}

void getdentsSystemCall::handleDetPost(state& s, ptracer& t, scheduler& sched){
  return;
}
// =======================================================================================
void getpeernameSystemCall::handleDetPost(state& s, ptracer& t, scheduler& sched){
  int ret = t.getReturnValue();
  if(ret == 0){
    throw runtime_error("Call to getpeername with network socket not suported.\n");
  }
  return;
}
// =======================================================================================
void getrandomSystemCall::handleDetPost(state& s, ptracer& t, scheduler& sched){
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
void getrlimitSystemCall::handleDetPost(state& s, ptracer& t, scheduler& sched){
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
void getrusageSystemCall::handleDetPost(state& s, ptracer& t, scheduler& sched){
  struct rusage* usagePtr = (struct rusage*) t.arg2();

  if(usagePtr == nullptr){
    s.log.writeToLog(Importance::info, "getrusage pointer null.");
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
void gettimeofdaySystemCall::handleDetPost(state& s, ptracer& t, scheduler& sched){
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
void ioctlSystemCall::handleDetPost(state& s, ptracer& t, scheduler& sched){
  int fd = t.arg1();
  const uint64_t request = t.arg2();
  s.log.writeToLog(Importance::info, "fd %d\n", fd);
  s.log.writeToLog(Importance::info, "Request %" PRId64 "\n", request);

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

bool nanosleepSystemCall::handleDetPre(state& s, ptracer& t, scheduler& sched){
  return true;
}

void nanosleepSystemCall::handleDetPost(state& s, ptracer& t, scheduler& sched){
  // TODO: Turn nano sleep into a no op.

  return;
}
// =======================================================================================
bool mkdirSystemCall::handleDetPre(state& s, ptracer& t, scheduler& sched){
  printInfoString(t.arg1(), s);

  return false;
}
// =======================================================================================
bool mkdiratSystemCall::handleDetPre(state& s, ptracer& t, scheduler& sched){
  printInfoString(t.arg2(), s);

  return false;
}
// =======================================================================================
void newfstatatSystemCall::handleDetPost(state& s, ptracer& t, scheduler& sched){
  printInfoString(t.arg2(), s);

  handleStatFamily(s, t, "newfstatat");
  return;
}
// =======================================================================================
bool lstatSystemCall::handleDetPre(state& s, ptracer& t, scheduler& sched){
  printInfoString(t.arg1(), s);

  return true;
}

void lstatSystemCall::handleDetPost(state& s, ptracer& t, scheduler& sched){
  handleStatFamily(s, t, "lstat");
  return;
}
// =======================================================================================
bool openSystemCall::handleDetPre(state& s, ptracer& t, scheduler& sched){
  printInfoString(t.arg1(), s);

  return false;
}
// =======================================================================================
bool openatSystemCall::handleDetPre(state& s, ptracer& t, scheduler& sched){
  printInfoString(t.arg2(), s);

  return false;
}
// =======================================================================================
// TODO
bool pipeSystemCall::handleDetPre(state& s, ptracer& t, scheduler& sched){
  s.log.writeToLog(Importance::info, "Making this pipe non-blocking\n");
  // Convert pipe call to pipe2 to set O_NONBLOCK.
  t.changeSystemCall(SYS_pipe2);
  s.originalArg2 = t.arg2();
  t.writeArg2(O_NONBLOCK);

  return true;
}

void pipeSystemCall::handleDetPost(state& s, ptracer& t, scheduler& sched){
  // Restore original registers.
  t.writeArg2(s.originalArg2);
}
// =======================================================================================
bool pipe2SystemCall::handleDetPre(state& s, ptracer& t, scheduler& sched){
  s.log.writeToLog(Importance::info, "Making this pipe2 non-blocking\n");
  // Convert pipe call to pipe2 to set O_NONBLOCK.
  s.originalArg2 = t.arg2();
  t.writeArg2(t.arg2() | O_NONBLOCK);

  return true;
}

void pipe2SystemCall::handleDetPost(state& s, ptracer& t, scheduler& sched){
  // Restore original registers.
  t.writeArg2(s.originalArg2);
}
// =======================================================================================
bool pselect6SystemCall::handleDetPre(state& s, ptracer& t, scheduler& sched){
  return true;
}

void pselect6SystemCall::handleDetPost(state& s, ptracer& t, scheduler& sched){
  return;
}
// =======================================================================================
bool pollSystemCall::handleDetPre(state& s, ptracer& t, scheduler& sched){
  s.originalArg3 = t.arg3();
  // Make this call non blocking by setting timeout to zero!
  t.writeArg3(0);
  return true;
}

void pollSystemCall::handleDetPost(state& s, ptracer& t, scheduler& sched){
  bool replay = replaySyscallIfBlocked(s, t, sched, 0);
  // Restore state of argument 3.
  if(replay){
    t.writeArg3(s.originalArg3);
  }
  return;
}
// =======================================================================================
// for reference, here's the prlimit() prototype
// int prlimit(pid_t pid, int resource, const struct rlimit *new_limit, struct rlimit *old_limit);
bool prlimit64SystemCall::handleDetPre(state& s, ptracer& t, scheduler& sched){
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

void prlimit64SystemCall::handleDetPost(state& s, ptracer& t, scheduler& sched){
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

    //s.log.writeToLog(Importance::info, "rp=" + to_string(t.arg4()), t.getPid());
    // ptracer::writeToTracee(rp, noLimits, t.getPid());
  }

  return;
}
// =======================================================================================
bool readSystemCall::handleDetPre(state& s, ptracer& t, scheduler& sched){
  size_t fd = (size_t) t.arg1();
  s.log.writeToLog(Importance::info, "File descriptor: %d\n", fd);
  size_t count = (size_t) t.arg3();
  s.log.writeToLog(Importance::info, "Bytes to read %d\n", count);
  
  return true;
}

void readSystemCall::handleDetPost(state& s, ptracer& t, scheduler& sched){
  bool replay = replaySyscallIfBlocked(s, t, sched, EAGAIN);

  return;

}
// =======================================================================================
bool readvSystemCall::handleDetPre(state& s, ptracer& t, scheduler& sched){
  return true;
}

void readvSystemCall::handleDetPost(state& s, ptracer& t, scheduler& sched){
  return;
}
// =======================================================================================
bool readlinkSystemCall::handleDetPre(state& s, ptracer& t, scheduler& sched){
  printInfoString(t.arg1(), s);

  return false;
}
// =======================================================================================
bool recvmsgSystemCall::handleDetPre(state& s, ptracer& t, scheduler& sched){
  return true;
}

void recvmsgSystemCall::handleDetPost(state& s, ptracer& t, scheduler& sched){
  return;
}

// =======================================================================================
bool renameSystemCall::handleDetPre(state& s, ptracer& t, scheduler& sched){
  printInfoString(t.arg1(), s, " renaming-ing path: ");
  printInfoString(t.arg2(), s, " to path: ");

  return false;

}
// =======================================================================================
// TODO
bool sendtoSystemCall::handleDetPre(state& s, ptracer& t, scheduler& sched){
  return true;
}

void sendtoSystemCall::handleDetPost(state& s, ptracer& t, scheduler& sched){
  return;
}
// =======================================================================================
bool selectSystemCall::handleDetPre(state& s, ptracer& t, scheduler& sched){
  return true;
}

void selectSystemCall::handleDetPost(state& s, ptracer& t, scheduler& sched){
  return;
}
// =======================================================================================
// TODO

bool set_robust_listSystemCall::handleDetPre(state& s, ptracer& t, scheduler& sched){
  return true;
}

void set_robust_listSystemCall::handleDetPost(state& s, ptracer& t, scheduler& sched){
  return;
}
// =======================================================================================
bool statSystemCall::handleDetPre(state& s, ptracer& t, scheduler& sched){
  printInfoString(t.arg1(), s);

  return true;
}

void statSystemCall::handleDetPost(state& s, ptracer& t, scheduler& sched){
  handleStatFamily(s, t, "stat");
  return;
}
// =======================================================================================
void statfsSystemCall::handleDetPost(state& s, ptracer& t, scheduler& sched){
  struct statfs* statfsPtr = (struct statfs*) t.arg2();
  if(statfsPtr == nullptr){
    s.log.writeToLog(Importance::info, "statfs: statbuf null.\n");
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
void sysinfoSystemCall::handleDetPost(state& s, ptracer& t, scheduler& sched){
  struct sysinfo* infoPtr = (struct sysinfo *) t.arg1();
  if(infoPtr == nullptr){
    return;
  }

  struct sysinfo info;
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
bool symlinkSystemCall::handleDetPre(state& s, ptracer& t, scheduler& sched){
  printInfoString(t.arg1(), s, " target: ");
  printInfoString(t.arg2(), s, " linkpath: ");
  return false;
}
// =======================================================================================
bool tgkillSystemCall::handleDetPre(state& s, ptracer& t, scheduler& sched){
  int tgid = (int) t.arg1();
  int tid = (int) t.arg2();
  int signal = (int) t.arg3();
  s.log.writeToLog(Importance::info, "tgkill(tgid = %d, tid = %d, signal = %d)\n",
		   tgid, tid, signal);
  return true;
}

void tgkillSystemCall::handleDetPost(state& s, ptracer& t, scheduler& sched){
  return;
}
// =======================================================================================
void timeSystemCall::handleDetPost(state& s, ptracer& t, scheduler& sched){
  int retVal = (int) t.getReturnValue();
  if(retVal < 0){
    s.log.writeToLog(Importance::info,
		     "Time call failed: \n" + string { strerror(- retVal)});
    return;
  }

  time_t* timePtr = (time_t*) t.arg1();
  s.log.writeToLog(Importance::info, "time: tloc is null.");
  if(timePtr == nullptr){
    return;
  }

  ptracer::writeToTracee(timePtr, (time_t) s.getLogicalTime(), s.traceePid);
  // Tick up time.
  s.incrementTime();
  return;
}
// =======================================================================================
void unameSystemCall::handleDetPost(state& s, ptracer& t, scheduler& sched){
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
bool unlinkSystemCall::handleDetPre(state& s, ptracer& t, scheduler& sched){
  printInfoString(t.arg1(), s);

  return false;
}

// =======================================================================================
bool unlinkatSystemCall::handleDetPre(state& s, ptracer& t, scheduler& sched){
  printInfoString(t.arg2(), s);

  return true;
}

// =======================================================================================
bool utimesSystemCall::handleDetPre(state& s, ptracer& t, scheduler& sched){
  // TODO? See class declaration.
  return false;
}
// =======================================================================================
bool utimensatSystemCall::handleDetPre(state& s, ptracer& t, scheduler& sched){
  // Set times to our own logical time for deterministic time only if times is null.
  if((const struct timespec*) t.arg3() != nullptr){
    // Nothing to do, user specified his/her own time which should be deterministic.
    return true;
  }

  // We need somewhere to store a timespec struct if our struct is null. We will write
  // this data below the current stack pointer accounting for the red zone, known to be
  // 128 bytes.
  //uint64_t rsp = t.regs.rsp;
  uint64_t rsp = t.getRsp();
  // Enough space for 2 timespec structs.
  timespec* ourTimespec = (timespec*) (rsp - 128 - 2 * sizeof(timespec));

  // Create our own struct with our time.
  timespec clockTime = {
    .tv_sec = (time_t) s.getLogicalTime(),
    .tv_nsec = (time_t) s.getLogicalTime()
  };

  // Write our struct to the tracee's memory.
  ptracer::writeToTracee(& (ourTimespec[0]), clockTime, s.traceePid);
  ptracer::writeToTracee(& (ourTimespec[1]), clockTime, s.traceePid);

  // Point system call to new address.
  t.writeArg3((uint64_t) ourTimespec);
  s.incrementTime();
  return false;
}

void utimensatSystemCall::handleDetPost(state& s, ptracer& t, scheduler& sched){
  // Restore value of register.
  t.writeArg3(0);
}
// =======================================================================================
bool writeSystemCall::handleDetPre(state& s, ptracer& t, scheduler& sched){
  s.log.writeToLog(Importance::info, "fd: %d\n", t.arg1());
  size_t count = (size_t) t.arg3();
  s.log.writeToLog(Importance::info, "Bytes to write %d\n", count);
  return true;
}

void writeSystemCall::handleDetPost(state& s, ptracer& t, scheduler& sched){
  replaySyscallIfBlocked(s, t, sched, EAGAIN);
  return;
}
// =======================================================================================
bool wait4SystemCall::handleDetPre(state& s, ptracer& t, scheduler& sched){
  s.log.writeToLog(Importance::info, "Making this a non-blocking wait4\n");

  // Make this a non blocking hang!
  s.originalArg3 = t.arg3();
  t.writeArg3(s.originalArg3 | WNOHANG);
  return true;
}
void wait4SystemCall::handleDetPost(state& s, ptracer& t, scheduler& sched){
  bool replayed = replaySyscallIfBlocked(s, t, sched, 0);
  if(!replayed){
    t.writeArg3(s.originalArg3);
  }

  return;
}
// =======================================================================================
bool writevSystemCall::handleDetPre(state& s, ptracer& t, scheduler& sched){
  return true;
}

void writevSystemCall::handleDetPost(state& s, ptracer& t, scheduler& sched){
  // TODO: Handle bytes written.
  int retVal = t.getReturnValue();
  if (retVal < 0) {
    throw runtime_error("Write failed with: " + string{ strerror(- retVal) });
  }

  //uint16_t minus2 = t.readFromTracee((uint16_t*) (t.regs.rip - 2), s.traceePid);
  uint16_t minus2 = t.readFromTracee((uint16_t*) (t.getRip() - 2), s.traceePid);
  if (!(minus2 == 0x80CD || minus2 == 0x340F || minus2 == 0x050F)) {
    throw runtime_error("Write failed with: non syscall insn");
  }
  ssize_t bytes_written = retVal;
  s.totalBytes += bytes_written;
  //ssize_t bytes_requested = t.arg3();

  if (s.firstTryReadWrite) {
    s.firstTryReadWrite = false;
    //s.beforeRetry = t.regs;
    s.beforeRetry = t.getRegs();
  }

  // 0 indicates nothing was written.
  if (bytes_written != 0) {
    t.writeArg2(t.arg2() + bytes_written);
    t.writeArg3(t.arg3() - bytes_written);
    //t.regs.rax = t.getSystemCallNumber();
    t.writeRax(t.getSystemCallNumber());
    //t.writeIp(t.regs.rip - 2);
    t.writeIp(t.getRip() - 2);
   } else { // Nothing left to write.
     t.setReturnRegister(s.totalBytes);
     t.writeArg1(s.beforeRetry.rdi);
     t.writeArg2(s.beforeRetry.rsi);
     t.writeArg3(s.beforeRetry.rdx);
     s.firstTryReadWrite = true;
     s.totalBytes = 0;
   }
  return;
}
// =======================================================================================
bool replaySyscallIfBlocked(state& s, ptracer& t, scheduler& sched, int64_t errornoValue){
  if(- errornoValue == (int64_t) t.getReturnValue()){
    auto msg = s.systemcall->syscallName + " would have blocked!\n";
    s.log.writeToLog(Importance::info, msg);

    sched.preemptAndScheduleNext(s.traceePid);

    uint16_t minus2 = t.readFromTracee((uint16_t*) (t.getRip() - 2), s.traceePid);
    if (!(minus2 == 0x80CD || minus2 == 0x340F || minus2 == 0x050F)) {
      throw runtime_error("IP does not point to system call instruction!\n");
    }

    // Replay system call!

    t.writeRax(t.getSystemCallNumber());
    t.writeIp(t.getRip() - 2);
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
void handleStatFamily(state& s, ptracer& t, string syscallName){
  struct stat* statPtr;

  if(syscallName == "newfstatat"){
    statPtr = (struct stat*) t.arg3();
  }else{
    statPtr = (struct stat*) t.arg2();
  }

  if(statPtr == nullptr){
    s.log.writeToLog(Importance::info, syscallName + ": statbuf null.\n");
    return;
  }

  int retVal = t.getReturnValue();
  if(retVal == 0){
    struct stat myStat = ptracer::readFromTracee(statPtr, s.traceePid);

    myStat.st_atim = timespec { .tv_sec =  0,
                                .tv_nsec = 0 };  /* user CPU time used */
    myStat.st_mtim = timespec { .tv_sec =  0,
				.tv_nsec = 0 };
    myStat.st_ctim = timespec { .tv_sec = 0,
                                .tv_nsec = 0 };  /* user CPU time used */

    myStat.st_dev = 1;         /* ID of device containing file */

    // inode virtualization
    const ino_t realInodeNum = myStat.st_ino;
    if (!s.inodeMap.realValueExists(realInodeNum)) {
      s.inodeMap.addRealValue(realInodeNum);
    }
    myStat.st_ino = s.inodeMap.getVirtualValue(realInodeNum);

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
void printInfoString(uint64_t addressOfCString, state& s, string postFix){
  if((char*) addressOfCString != nullptr){
    string path = ptracer::readTraceeCString((char*) addressOfCString, s.traceePid);
    string msg = s.systemcall->syscallName + postFix +
      logger::makeTextColored(Color::green, path) + "\n";
    s.log.writeToLog(Importance::info, msg);
  }else{
    s.log.writeToLog(Importance::info, "Null path given to system call.\n");
  }

  return;
}
// =======================================================================================
