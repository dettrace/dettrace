#include <errno.h>

#include "dettraceSystemCall.hpp"
#include "ptracer.hpp"

// =======================================================================================
// Prototypes for common functions.
void zeroOutStatfs(struct statfs& stats);


// =======================================================================================
accessSystemCall::accessSystemCall(long syscallNumber, string syscallName):
  systemCall(syscallNumber, syscallName){
  return;
}

bool accessSystemCall::handleDetPre(state &s, ptracer &t){
  return true;
}

void accessSystemCall::handleDetPost(state &s, ptracer &t){
  return;
}
// =======================================================================================
arch_prctlSystemCall::arch_prctlSystemCall(long syscallNumber, string syscallName):
  systemCall(syscallNumber, syscallName){
  return;
}

bool arch_prctlSystemCall::handleDetPre(state &s, ptracer &t){
  return true;
}

void arch_prctlSystemCall::handleDetPost(state &s, ptracer &t){
  return;
}

// =======================================================================================
brkSystemCall::brkSystemCall(long syscallNumber, string syscallName):
  systemCall(syscallNumber, syscallName){
  return;
}

bool brkSystemCall::handleDetPre(state &s, ptracer &t){
  return true;
}

void brkSystemCall::handleDetPost(state &s, ptracer &t){
  return;
}
// =======================================================================================
cloneSystemCall::cloneSystemCall(long syscallNumber, string syscallName):
  systemCall(syscallNumber, syscallName){
  return;
}

bool cloneSystemCall::handleDetPre(state &s, ptracer &t){
  // TODO: Figure out how to ignore threads, vforks, for now.
  return true;
}

void cloneSystemCall::handleDetPost(state &s, ptracer &t){
  s.log.writeToLog(Importance::info, "IN CLONE!\n");
  // Non deterministic failure due to signal.
  pid_t returnPid = t.getReturnValue();
  if(returnPid == -1){
    if(errno == EINTR){
      throw runtime_error("Clone system call failed:\n" + string { strerror(errno) });
    }
  }

  // The ptrace option for fork handles most of the logic for forking. We merely need
  // to make sure to return the correct value here!
  pid_t vpid = s.pidMap.getVirtualValue(returnPid);
  t.setReturnRegister(vpid);

  // In older versions of ptrace, the tid value was cached to skip getpid calls. This
  // is no longer done as it creates inconsistencies between process related system calls
  // done through libc and those done directly. Long story short, nothing for us to do.

  return;
}
// =======================================================================================
closeSystemCall::closeSystemCall(long syscallNumber, string syscallName):
  systemCall(syscallNumber, syscallName){
  return;
}

bool closeSystemCall::handleDetPre(state &s, ptracer &t){
  return true;
}

void closeSystemCall::handleDetPost(state &s, ptracer &t){
  // Non deterministic failure due to signal.
  if((int64_t) t.getReturnValue() == -1){
    if(errno == EINTR){
      throw runtime_error("Close system call failed:\n" + string { strerror(errno) });
    }
  }

  return;
}
// =======================================================================================
dup2SystemCall::dup2SystemCall(long syscallNumber, string syscallName):
  systemCall(syscallNumber, syscallName){
  return;
}

bool dup2SystemCall::handleDetPre(state &s, ptracer &t){
  return true;
}

void dup2SystemCall::handleDetPost(state &s, ptracer &t){
  return;
}
// =======================================================================================
execveSystemCall::execveSystemCall(long syscallNumber, string syscallName):
  systemCall(syscallNumber, syscallName){
  return;
}

bool execveSystemCall::handleDetPre(state &s, ptracer &t){
  char* filenameAddr = (char*) t.arg1();
  string filename = t.readTraceeCString(filenameAddr, s.traceePid);
  s.log.writeToLog(Importance::extra, "Execve on: %s\n", filename.c_str());

  return true;
}

void execveSystemCall::handleDetPost(state &s, ptracer &t){
  return;
}
// =======================================================================================
exit_groupSystemCall::exit_groupSystemCall(long syscallNumber, string syscallName):
  systemCall(syscallNumber, syscallName){
  return;
}

bool exit_groupSystemCall::handleDetPre(state &s, ptracer &t){
  return true;
}

void exit_groupSystemCall::handleDetPost(state &s, ptracer &t){
  return;
}
// =======================================================================================

// =======================================================================================
fstatSystemCall::fstatSystemCall(long syscallNumber, string syscallName):
  systemCall(syscallNumber, syscallName){
  return;
}

bool fstatSystemCall::handleDetPre(state &s, ptracer &t){
  return true;
}

void fstatSystemCall::handleDetPost(state &s, ptracer &t){
  return;
}
// =======================================================================================
fstatfsSystemCall::fstatfsSystemCall(long syscallNumber, string syscallName):
  systemCall(syscallNumber, syscallName){
  return;
}

bool fstatfsSystemCall::handleDetPre(state &s, ptracer &t){
  return true;
}

void fstatfsSystemCall::handleDetPost(state &s, ptracer &t){
  // Read values written to by system call.
  struct statfs stats = ptracer::readFromTracee((struct statfs*) t.arg2(), s.traceePid);


  if(t.getReturnValue() == 0){
    // Assume we're using this file sytem?

    zeroOutStatfs(stats);

    // Write back result for child.
    ptracer::writeToTracee<struct statfs>((struct statfs*) t.arg2(), stats, s.traceePid);
  }else{
    s.log.writeToLog(Importance::info, "Negative number returned from fstatfs call\n" );
  }

  return;
}
// =======================================================================================
futexSystemCall::futexSystemCall(long syscallNumber, string syscallName):
  systemCall(syscallNumber, syscallName){
  return;
}

bool futexSystemCall::handleDetPre(state &s, ptracer &t){
  return true;
}

void futexSystemCall::handleDetPost(state &s, ptracer &t){
  return;
}
// =======================================================================================
getdentsSystemCall::getdentsSystemCall(long syscallNumber, string syscallName):
  systemCall(syscallNumber, syscallName){
  return;
}

bool getdentsSystemCall::handleDetPre(state &s, ptracer &t){
  return true;
}

void getdentsSystemCall::handleDetPost(state &s, ptracer &t){
  return;
}
// =======================================================================================
getpidSystemCall::getpidSystemCall(long syscallNumber, string syscallName):
  systemCall(syscallNumber, syscallName){
  return;
}

bool getpidSystemCall::handleDetPre(state &s, ptracer &t){
  return true;
}

void getpidSystemCall::handleDetPost(state &s, ptracer &t){
  pid_t realPid = t.getPid();
  s.log.writeToLog(Importance::info, "Process real pid: %d\n", realPid);

  pid_t vPid = s.pidMap.getVirtualValue(realPid);

  if(vPid == -1){
    throw runtime_error("Real pid " + to_string(realPid) + " not in map!\n");
  }

  s.log.writeToLog(Importance::info, "Process vPid: %d\n", vPid);

  t.setReturnRegister(vPid);
  return;
}
// =======================================================================================
getppidSystemCall::getppidSystemCall(long syscallNumber, string syscallName):
  systemCall(syscallNumber, syscallName){
  return;
}

bool getppidSystemCall::handleDetPre(state &s, ptracer &t){
  return true;
}

void getppidSystemCall::handleDetPost(state &s, ptracer &t){
  pid_t parentPid = s.ppid;
  s.log.writeToLog(Importance::info, "Process real ppid: %d\n", parentPid);

  pid_t vppid = s.pidMap.getVirtualValue(parentPid);

  if(vppid == -1){
    throw runtime_error("Real pid " + to_string(parentPid) + " not in map!\n");
  }

  s.log.writeToLog(Importance::info, "Process vppid: %d\n", vppid);

  t.setReturnRegister(vppid);
  return;
}
// =======================================================================================
getuidSystemCall::getuidSystemCall(long syscallNumber, string syscallName):
  systemCall(syscallNumber, syscallName){
  return;
}

bool getuidSystemCall::handleDetPre(state &s, ptracer &t){
  return true;
}

void getuidSystemCall::handleDetPost(state &s, ptracer &t){
  int nobodyUid = 65534;
  t.setReturnRegister(nobodyUid);
  return;
}
// =======================================================================================
ioctlSystemCall::ioctlSystemCall(long syscallNumber, string syscallName):
  systemCall(syscallNumber, syscallName){
  return;
}

bool ioctlSystemCall::handleDetPre(state &s, ptracer &t){
  return true;
}

void ioctlSystemCall::handleDetPost(state &s, ptracer &t){
  return;
}
// =======================================================================================
munmapSystemCall::munmapSystemCall(long syscallNumber, string syscallName):
  systemCall(syscallNumber, syscallName){
  return;
}

bool munmapSystemCall::handleDetPre(state &s, ptracer &t){
  return true;
}

void munmapSystemCall::handleDetPost(state &s, ptracer &t){
  return;
}
// =======================================================================================
openSystemCall::openSystemCall(long syscallNumber, string syscallName):
  systemCall(syscallNumber, syscallName){
  return;
}

bool openSystemCall::handleDetPre(state &s, ptracer &t){
  return true;
}

void openSystemCall::handleDetPost(state &s, ptracer &t){
  // Deterministic file descriptors?
  return;
}
// =======================================================================================
openatSystemCall::openatSystemCall(long syscallNumber, string syscallName):
  systemCall(syscallNumber, syscallName){
  return;
}

bool openatSystemCall::handleDetPre(state &s, ptracer &t){
  return true;
}

void openatSystemCall::handleDetPost(state &s, ptracer &t){
  // Deterministic file descriptors?
  return;
}
// =======================================================================================
mmapSystemCall::mmapSystemCall(long syscallNumber, string syscallName):
  systemCall(syscallNumber, syscallName){
  return;
}

bool mmapSystemCall::handleDetPre(state &s, ptracer &t){
  return true;
}

void mmapSystemCall::handleDetPost(state &s, ptracer &t){
  return;
}
// =======================================================================================
mprotectSystemCall::mprotectSystemCall(long syscallNumber, string syscallName):
  systemCall(syscallNumber, syscallName){
  return;
}

bool mprotectSystemCall::handleDetPre(state &s, ptracer &t){
  return true;
}

void mprotectSystemCall::handleDetPost(state &s, ptracer &t){
  return;
}
// =======================================================================================
prlimit64SystemCall::prlimit64SystemCall(long syscallNumber, string syscallName):
  systemCall(syscallNumber, syscallName){
  return;
}

bool prlimit64SystemCall::handleDetPre(state &s, ptracer &t){
  /* Check if first argument (pid) is non-zero. If so fail. */
  int pid = (pid_t) t.arg1();
  if(pid != 0){
    throw runtime_error("prlimit64: We do not support prlimit64 on other processes.\n "
			"(pid: " + to_string(pid));
  }

  return true;
}

void prlimit64SystemCall::handleDetPost(state &s, ptracer &t){
  return;
}

// =======================================================================================
readSystemCall::readSystemCall(long syscallNumber, string syscallName):
  systemCall(syscallNumber, syscallName){
  return;
}

bool readSystemCall::handleDetPre(state &s, ptracer &t){
  return true;
}

void readSystemCall::handleDetPost(state &s, ptracer &t){
  // Handle number of bytest read.
  return;
}
// =======================================================================================
rt_sigprocmaskSystemCall::rt_sigprocmaskSystemCall(long syscallNumber, string syscallName):
  systemCall(syscallNumber, syscallName){
  return;
}

bool rt_sigprocmaskSystemCall::handleDetPre(state &s, ptracer &t){
  return true;
}

void rt_sigprocmaskSystemCall::handleDetPost(state &s, ptracer &t){

  return;
}
// =======================================================================================
rt_sigactionSystemCall::rt_sigactionSystemCall(long syscallNumber, string syscallName):
  systemCall(syscallNumber, syscallName){
  return;
}

bool rt_sigactionSystemCall::handleDetPre(state &s, ptracer &t){
  return true;
}

void rt_sigactionSystemCall::handleDetPost(state &s, ptracer &t){

  return;
}
// =======================================================================================
set_robust_listSystemCall::set_robust_listSystemCall(long syscallNumber, string syscallName):
  systemCall(syscallNumber, syscallName){
  return;
}

bool set_robust_listSystemCall::handleDetPre(state &s, ptracer &t){
  return true;
}

void set_robust_listSystemCall::handleDetPost(state &s, ptracer &t){
  return;
}

// =======================================================================================
set_tid_addressSystemCall::set_tid_addressSystemCall(long syscallNumber, string syscallName):
  systemCall(syscallNumber, syscallName){
  return;
}

bool set_tid_addressSystemCall::handleDetPre(state &s, ptracer &t){
  return true;
}

void set_tid_addressSystemCall::handleDetPost(state &s, ptracer &t){
  return;
}
// =======================================================================================
sigaltstackSystemCall::sigaltstackSystemCall(long syscallNumber, string syscallName):
  systemCall(syscallNumber, syscallName){
  return;
}

bool sigaltstackSystemCall::handleDetPre(state &s, ptracer &t){
  return true;
}

void sigaltstackSystemCall::handleDetPost(state &s, ptracer &t){
  return;
}
// =======================================================================================
statfsSystemCall::statfsSystemCall(long syscallNumber, string syscallName):
  systemCall(syscallNumber, syscallName){
  return;
}

bool statfsSystemCall::handleDetPre(state &s, ptracer &t){
  return true;
}

void statfsSystemCall::handleDetPost(state &s, ptracer &t){
  // Read values written to by system call.
  struct statfs stats = ptracer::readFromTracee((struct statfs*) t.arg2(), s.traceePid);


  if(t.getReturnValue() == 0){
    // Assume we're using this file sytem?

    zeroOutStatfs(stats);

    // Write back result for child.
    ptracer::writeToTracee<struct statfs>((struct statfs*) t.arg2(), stats, s.traceePid);
  }else{
    s.log.writeToLog(Importance::info, "Negative number returned from statfs call:\n.");
  }

  return;
}
// =======================================================================================
timeSystemCall::timeSystemCall(long syscallNumber, string syscallName):
  systemCall(syscallNumber, syscallName){
  return;
}

bool timeSystemCall::handleDetPre(state &s, ptracer &t){
  return true;
}

void timeSystemCall::handleDetPost(state &s, ptracer &t){
  // Write new value.
  // CHECK IF NULL TODO.
  ptracer::writeToTracee<time_t>((time_t*) t.arg1(), (time_t) s.clock, s.traceePid);

  return;
}
// =======================================================================================
utimensatSystemCall::utimensatSystemCall(long syscallNumber, string syscallName):
  systemCall(syscallNumber, syscallName){
  return;
}

bool utimensatSystemCall::handleDetPre(state &s, ptracer &t){
  // int utimensat(int dirfd, const char *pathname,
  //               const struct timespec times[2], int flags);
  // Set times to our own logical time for deterministic time.

  // We need somewhere to store a timespec struct if our struct is null. We will write
  // this data below the current stack pointer accounting for the red zone, known to be
  // 128 bytes.
  uint64_t rsp = t.regs.rsp;
  // Enough space for 2 timespec structs.
  timespec* ourTimespec = (timespec*) (rsp - 128 - 2 * sizeof(timespec));

  // Create our own struct with our time.
  timespec clockTime = {
    .tv_sec = (time_t) s.clock,
    .tv_nsec = (time_t) s.clock,
  };

  // Write our struct to the tracee's memory.
  ptracer::writeToTracee(& (ourTimespec[0]), clockTime, s.traceePid);
  ptracer::writeToTracee(& (ourTimespec[1]), clockTime, s.traceePid);

  // Point system call to new address.
  t.writeArg3((uint64_t) ourTimespec);

  return true;
}

void utimensatSystemCall::handleDetPost(state &s, ptracer &t){
  return;
}
// =======================================================================================
wait4SystemCall::wait4SystemCall(long syscallNumber, string syscallName):
  systemCall(syscallNumber, syscallName){
  return;
}

bool wait4SystemCall::handleDetPre(state &s, ptracer &t){
  pid_t vpid = t.arg1();
  // Figure out what to do based on vpid value passed. (See man waitpid 2):

  // (< -1) wait for any child process whose process group ID  is  equal  to  the
  // absolute value of pid.
  // TODO: Nondeterministic based on scheduling of processes? Is there any guarantee
  // on which one will be returned?
  if(vpid < -1){
    throw runtime_error("wait4 error: unimplemented case for pid < -1!");
  }

  // (== -1) wait for any child process.
  // TODO: Same issue as case above.
  if(vpid == -1){
    throw runtime_error("wait4 error: unimplemented case for pid == -1!");
  }

  // (== 0) wait for any child process whose process group ID is equal to that of
  // the calling process.
  // TODO: Same issue as case above.
  if(vpid == 0){
    throw runtime_error("wait4 error: unimplemented case for pid == 0!");
  }

  // (> 0) wait for the child whose process ID is equal to the value of pid.
  // Most common case. Map pid from virtual to real.
  int realPid = s.pidMap.getRealValue(vpid);
  if(realPid == -1){
    throw runtime_error("wait4 error: requested for vpid does not exist: " +
			to_string(vpid));
  }

  // Set realPid as value for system call to use for wait.
  t.writeArg1(realPid);
  return true;
}

void wait4SystemCall::handleDetPost(state &s, ptracer &t){
  return;
}
// =======================================================================================
writeSystemCall::writeSystemCall(long syscallNumber, string syscallName):
  systemCall(syscallNumber, syscallName){
  return;
}

bool writeSystemCall::handleDetPre(state &s, ptracer &t){
  return true;
}

void writeSystemCall::handleDetPost(state &s, ptracer &t){
  return;
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
