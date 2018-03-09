#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/utsname.h>
#include <sys/ioctl.h>

#include <climits>
#include <cstring>

#include <sys/time.h>
#include <sys/resource.h>
#include <sys/sysinfo.h>
#include <sys/uio.h>

#include "dettraceSystemCall.hpp"
#include "ptracer.hpp"

using namespace std;
// =======================================================================================
// Prototypes for common functions.
void zeroOutStatfs(struct statfs& stats);
void handleStatFamily(state& s, ptracer& t, string syscallName);
bool isPrefix(const string& data, const string& prefix);
// =======================================================================================
accessSystemCall::accessSystemCall(long syscallNumber, string syscallName):
  systemCall(syscallNumber, syscallName){
  return;
}

bool accessSystemCall::handleDetPre(state &s, ptracer &t){
  string path = ptracer::readTraceeCString((const char*)t.arg1(), t.getPid());
  string msg = "Access-ing path: " + logger::makeTextColored(Color::green, path) + "\n";
  s.log.writeToLog(Importance::info, msg);

  return true;
}

void accessSystemCall::handleDetPost(state &s, ptracer &t){
  return;
}
// =======================================================================================
alarmSystemCall::alarmSystemCall(long syscallNumber, string syscallName):
  systemCall(syscallNumber, syscallName){
  return;
}

bool alarmSystemCall::handleDetPre(state &s, ptracer &t){
  throw runtime_error("Unsupported system call: alarm()\n");
  return true;
}

void alarmSystemCall::handleDetPost(state &s, ptracer &t){
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
chdirSystemCall::chdirSystemCall(long syscallNumber, string syscallName):
  systemCall(syscallNumber, syscallName){
  return;
}

bool chdirSystemCall::handleDetPre(state &s, ptracer &t){
  string path = ptracer::readTraceeCString((const char*)t.arg1(), t.getPid());
  string msg = "chdir-ing to path: " + logger::makeTextColored(Color::green, path) + "\n";
  s.log.writeToLog(Importance::info, msg);
  return true;
}

void chdirSystemCall::handleDetPost(state &s, ptracer &t){
  return;
}
// =======================================================================================
chmodSystemCall::chmodSystemCall(long syscallNumber, string syscallName):
  systemCall(syscallNumber, syscallName){
  return;
}

bool chmodSystemCall::handleDetPre(state &s, ptracer &t){
  return true;
}

void chmodSystemCall::handleDetPost(state &s, ptracer &t){
  return;
}
// =======================================================================================
clock_gettimeSystemCall::clock_gettimeSystemCall(long syscallNumber, string syscallName):
  systemCall(syscallNumber, syscallName){
  return;
}

bool clock_gettimeSystemCall::handleDetPre(state &s, ptracer &t) {
  return true;
}

void clock_gettimeSystemCall::handleDetPost(state &s, ptracer &t) {
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
cloneSystemCall::cloneSystemCall(long syscallNumber, string syscallName):
  systemCall(syscallNumber, syscallName){
  return;
}

bool cloneSystemCall::handleDetPre(state &s, ptracer &t){
  // TODO: Figure out how to ignore threads, vforks, for now.
  return true;
}

void cloneSystemCall::handleDetPost(state &s, ptracer &t){
  // Non deterministic failure due to signal.
  pid_t returnPid = t.getReturnValue();
  if(returnPid < 0){
      throw runtime_error("Clone system call failed:\n" + string { strerror(- returnPid) });
  }

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
  int returnVal = t.getReturnValue();
  if(returnVal < 0){
      throw runtime_error("Close system call failed:\n" + string { strerror(- returnVal) });
  }

  return;
}
// =======================================================================================
connectSystemCall::connectSystemCall(long syscallNumber, string syscallName):
  systemCall(syscallNumber, syscallName){
  return;
}

bool connectSystemCall::handleDetPre(state &s, ptracer &t){
  return true;
}

void connectSystemCall::handleDetPost(state &s, ptracer &t){
  return;
}
// =======================================================================================
dupSystemCall::dupSystemCall(long syscallNumber, string syscallName):
  systemCall(syscallNumber, syscallName){
  return;
}

bool dupSystemCall::handleDetPre(state &s, ptracer &t){
  return true;
}

void dupSystemCall::handleDetPost(state &s, ptracer &t){
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
  string path = ptracer::readTraceeCString((const char*)t.arg1(), t.getPid());
  string msg = "execve-ing path: " + logger::makeTextColored(Color::green, path) + "\n";
  s.log.writeToLog(Importance::info, msg);

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
faccessatSystemCall::faccessatSystemCall(long syscallNumber, string syscallName):
  systemCall(syscallNumber, syscallName){
  return;
}

bool faccessatSystemCall::handleDetPre(state &s, ptracer &t){
  return true;
}

void faccessatSystemCall::handleDetPost(state &s, ptracer &t){
  return;
}
// =======================================================================================
fcntlSystemCall::fcntlSystemCall(long syscallNumber, string syscallName):
  systemCall(syscallNumber, syscallName){
  return;
}

bool fcntlSystemCall::handleDetPre(state &s, ptracer &t){
  return true;
}

void fcntlSystemCall::handleDetPost(state &s, ptracer &t){
  return;
}
// =======================================================================================
fstatSystemCall::fstatSystemCall(long syscallNumber, string syscallName):
  systemCall(syscallNumber, syscallName){
  return;
}

bool fstatSystemCall::handleDetPre(state &s, ptracer &t){
  return true;
}

void fstatSystemCall::handleDetPost(state &s, ptracer &t){
  handleStatFamily(s, t, "fstat");
  return;
}
// =======================================================================================
newfstatatSystemCall::newfstatatSystemCall(long syscallNumber, string syscallName):
  systemCall(syscallNumber, syscallName){
  return;
}

bool newfstatatSystemCall::handleDetPre(state &s, ptracer &t){
  return true;
}

void newfstatatSystemCall::handleDetPost(state &s, ptracer &t){
  string path = ptracer::readTraceeCString((const char*)t.arg2(), t.getPid());
  string msg = "newfstatat-ing path: " + logger::makeTextColored(Color::green, path) + "\n";
  s.log.writeToLog(Importance::info, msg);
  handleStatFamily(s, t, "newfstatat");
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
getcwdSystemCall::getcwdSystemCall(long syscallNumber, string syscallName):
  systemCall(syscallNumber, syscallName){
  return;
}

bool getcwdSystemCall::handleDetPre(state &s, ptracer &t){
  return true;
}

void getcwdSystemCall::handleDetPost(state &s, ptracer &t){
  s.log.writeToLog(Importance::info, "getcwd: cwd=" + t.readTraceeCString((const char*)t.arg1(), t.getPid()));
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
geteuidSystemCall::geteuidSystemCall(long syscallNumber, string syscallName):
  systemCall(syscallNumber, syscallName){
  return;
}

bool geteuidSystemCall::handleDetPre(state &s, ptracer &t){
  return true;
}

void geteuidSystemCall::handleDetPost(state &s, ptracer &t){
  return;
}
// =======================================================================================
getgidSystemCall::getgidSystemCall(long syscallNumber, string syscallName):
  systemCall(syscallNumber, syscallName){
  return;
}

bool getgidSystemCall::handleDetPre(state &s, ptracer &t){
  return true;
}

void getgidSystemCall::handleDetPost(state &s, ptracer &t){
  return;
}
// =======================================================================================
getegidSystemCall::getegidSystemCall(long syscallNumber, string syscallName):
  systemCall(syscallNumber, syscallName){
  return;
}

bool getegidSystemCall::handleDetPre(state &s, ptracer &t){
  return true;
}

void getegidSystemCall::handleDetPost(state &s, ptracer &t){
  return;
}
// =======================================================================================
getgroupsSystemCall::getgroupsSystemCall(long syscallNumber, string syscallName):
  systemCall(syscallNumber, syscallName){
  return;
}

bool getgroupsSystemCall::handleDetPre(state &s, ptracer &t){
  return true;
}

void getgroupsSystemCall::handleDetPost(state &s, ptracer &t){
  return;
}
// =======================================================================================
getpeernameSystemCall::getpeernameSystemCall(long syscallNumber, string syscallName):
  systemCall(syscallNumber, syscallName){
  return;
}

bool getpeernameSystemCall::handleDetPre(state &s, ptracer &t){
  return true;
}

void getpeernameSystemCall::handleDetPost(state &s, ptracer &t){
  int ret = t.getReturnValue();
  if(ret == 0){
    throw runtime_error("Call to getpeername with network socket not suported.\n");
  }
  return;
}
// =======================================================================================
getpgrpSystemCall::getpgrpSystemCall(long syscallNumber, string syscallName):
  systemCall(syscallNumber, syscallName){
  return;
}

bool getpgrpSystemCall::handleDetPre(state &s, ptracer &t){
  return true;
}

void getpgrpSystemCall::handleDetPost(state &s, ptracer &t){
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
  return;
}
// =======================================================================================
getrandomSystemCall::getrandomSystemCall(long syscallNumber, string syscallName):
  systemCall(syscallNumber, syscallName){
  return;
}

bool getrandomSystemCall::handleDetPre(state &s, ptracer &t){
  // TODO Ignore system call we don't actually care to do it!
  return true;
}

void getrandomSystemCall::handleDetPost(state &s, ptracer &t){
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

  int ret = process_vm_writev(t.getPid(), &local, 1, &traceeMem, 1, flags);
  if(ret == -1){
    throw runtime_error("Clone system call failed:\n" + string { strerror(errno) });
  }

  return;
}
// =======================================================================================
getrlimitSystemCall::getrlimitSystemCall(long syscallNumber, string syscallName):
  systemCall(syscallNumber, syscallName){
  return;
}

bool getrlimitSystemCall::handleDetPre(state& s, ptracer& t){
  return true;
}

void getrlimitSystemCall::handleDetPost(state &s, ptracer &t){
  struct rlimit* rp = (struct rlimit*) t.arg2();
  if (rp != nullptr) {
    struct rlimit noLimits = {};
    noLimits.rlim_cur = RLIM_INFINITY;
    noLimits.rlim_max = RLIM_INFINITY;

    ptracer::writeToTracee(rp, noLimits, t.getPid());
  }

  return;
}
// =======================================================================================
getrusageSystemCall::getrusageSystemCall(long syscallNumber, string syscallName):
  systemCall(syscallNumber, syscallName){
  return;
}

bool getrusageSystemCall::handleDetPre(state &s, ptracer &t){
  return true;
}

void getrusageSystemCall::handleDetPost(state &s, ptracer &t){
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
gettidSystemCall::gettidSystemCall(long syscallNumber, string syscallName):
  systemCall(syscallNumber, syscallName){
  return;
}
bool gettidSystemCall::handleDetPre(state &s, ptracer &t){
  return true;
}
void gettidSystemCall::handleDetPost(state &s, ptracer &t){
  return;
}
// =======================================================================================
gettimeofdaySystemCall::gettimeofdaySystemCall(long syscallNumber, string syscallName):
  systemCall(syscallNumber, syscallName){
  return;
}
bool gettimeofdaySystemCall::handleDetPre(state &s, ptracer &t){
  return true;
}
void gettimeofdaySystemCall::handleDetPost(state &s, ptracer &t){
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
getxattrSystemCall::getxattrSystemCall(long syscallNumber, string syscallName):
  systemCall(syscallNumber, syscallName){
  return;
}

bool getxattrSystemCall::handleDetPre(state &s, ptracer &t){
  return true;
}

void getxattrSystemCall::handleDetPost(state& s, ptracer &t){
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
  const uint64_t request = t.arg2();
  if (TCGETS == request ||
      TIOCGWINSZ == request || // Window size of terminal.
      TIOCGPGRP == request // group pid of foreground process.
      ) {
    t.setReturnRegister((uint64_t) -ENOTTY);
  } else {
    throw runtime_error("Unsupported ioctl call: fd="+to_string(t.arg1())+" request=" + to_string(request));
  }
  return;
}
// =======================================================================================
lgetxattrSystemCall::lgetxattrSystemCall(long syscallNumber, string syscallName):
  systemCall(syscallNumber, syscallName){
  return;
}

bool lgetxattrSystemCall::handleDetPre(state &s, ptracer &t){
  return true;
}

void lgetxattrSystemCall::handleDetPost(state &s, ptracer &t){
  return;
}
// =======================================================================================
madviseSystemCall::madviseSystemCall(long syscallNumber, string syscallName):
  systemCall(syscallNumber, syscallName){
  return;
}

bool madviseSystemCall::handleDetPre(state &s, ptracer &t){
  return true;
}

void madviseSystemCall::handleDetPost(state &s, ptracer &t){
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
mremapSystemCall::mremapSystemCall(long syscallNumber, string syscallName):
  systemCall(syscallNumber, syscallName){
  return;
}

bool mremapSystemCall::handleDetPre(state &s, ptracer &t){
  return true;
}

void mremapSystemCall::handleDetPost(state &s, ptracer &t){
  // TODO: Turn nano sleep into a no op.

  return;
}

// =======================================================================================
nanosleepSystemCall::nanosleepSystemCall(long syscallNumber, string syscallName):
  systemCall(syscallNumber, syscallName){
  return;
}

bool nanosleepSystemCall::handleDetPre(state &s, ptracer &t){
  return true;
}

void nanosleepSystemCall::handleDetPost(state &s, ptracer &t){
  // TODO: Turn nano sleep into a no op.

  return;
}
// =======================================================================================
lseekSystemCall::lseekSystemCall(long syscallNumber, string syscallName):
  systemCall(syscallNumber, syscallName){
  return;
}

bool lseekSystemCall::handleDetPre(state &s, ptracer &t){
  return true;
}

void lseekSystemCall::handleDetPost(state &s, ptracer &t){
  return;
}
// =======================================================================================
lstatSystemCall::lstatSystemCall(long syscallNumber, string syscallName):
  systemCall(syscallNumber, syscallName){
  return;
}

bool lstatSystemCall::handleDetPre(state &s, ptracer &t){
  const char* filenameAddr = (const char*) t.arg1();
  string filename = ptracer::readTraceeCString(filenameAddr, s.traceePid);
  string coloredMsg = "lstat-ing path: " +
    logger::makeTextColored(Color::green, filename);
  s.log.writeToLog(Importance::extra, coloredMsg);

  return true;
}

void lstatSystemCall::handleDetPost(state &s, ptracer &t){
  handleStatFamily(s, t, "lstat");
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
  // TODO: In the future I hope to replace these brittle path checks with some filesystem
  // containerization support.
  const char* pathnamePtr = (const char*)t.arg1();
  string pathname = ptracer::readTraceeCString(pathnamePtr, t.getPid());

  s.log.writeToLog(Importance::info, "Openat-ing path: " +
		   logger::makeTextColored(Color::green, pathname) + "\n");

  char linkArray[PATH_MAX];
  // Assume symlink.
  ssize_t ret = readlink(pathname.c_str(), linkArray, PATH_MAX);
  // Null is not automatically placed.
  linkArray[ret] = '\0';
  const string zoneinfo { "/usr/share/zoneinfo/"};
  string link { linkArray };

  // Write our own string to bottom of stack.

  // This is a symbolic link!
  if(ret != -1){
    if(isPrefix(link, zoneinfo)){
      t.setReturnRegister(-1);
    }
  }

  return;
}
// =======================================================================================
pipeSystemCall::pipeSystemCall(long syscallNumber, string syscallName):
  systemCall(syscallNumber, syscallName){
  return;
}

bool pipeSystemCall::handleDetPre(state &s, ptracer &t){
  return true;
}

void pipeSystemCall::handleDetPost(state &s, ptracer &t){
  return;
}
// =======================================================================================
pselect6SystemCall::pselect6SystemCall(long syscallNumber, string syscallName):
  systemCall(syscallNumber, syscallName){
  return;
}

bool pselect6SystemCall::handleDetPre(state &s, ptracer &t){
  return true;
}

void pselect6SystemCall::handleDetPost(state &s, ptracer &t){
  return;
}

// =======================================================================================
openatSystemCall::openatSystemCall(long syscallNumber, string syscallName):
  systemCall(syscallNumber, syscallName){
  return;
}

bool openatSystemCall::handleDetPre(state &s, ptracer &t){
  // TODO. The same work done in open should be done here!
  const char* pathnamePtr = (const char*)t.arg2();

  if(pathnamePtr != nullptr){
    string pathname = ptracer::readTraceeCString(pathnamePtr, t.getPid());

    s.log.writeToLog(Importance::info, "Openat-ing path: " +
		     logger::makeTextColored(Color::green, pathname) + "\n");

  }

  return true;
}

void openatSystemCall::handleDetPost(state &s, ptracer &t){
  // Deterministic file descriptors?
  return;
}
// =======================================================================================
pollSystemCall::pollSystemCall(long syscallNumber, string syscallName):
  systemCall(syscallNumber, syscallName){
  return;
}

bool pollSystemCall::handleDetPre(state &s, ptracer &t){
  return true;
}

void pollSystemCall::handleDetPost(state &s, ptracer &t){
  return;
}
// =======================================================================================
fadvise64SystemCall::fadvise64SystemCall(long syscallNumber, string syscallName):
  systemCall(syscallNumber, syscallName){
  return;
}

bool fadvise64SystemCall::handleDetPre(state &s, ptracer &t){
  return true;
}

void fadvise64SystemCall::handleDetPost(state &s, ptracer &t){
  return;
}
// =======================================================================================
prlimit64SystemCall::prlimit64SystemCall(long syscallNumber, string syscallName):
  systemCall(syscallNumber, syscallName){
  return;
}

// for reference, here's the prlimit() prototype
// int prlimit(pid_t pid, int resource, const struct rlimit *new_limit, struct rlimit *old_limit);
bool prlimit64SystemCall::handleDetPre(state &s, ptracer &t){
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

void prlimit64SystemCall::handleDetPost(state &s, ptracer &t){
  /* To bypass the complexity of this system call (lots of different resources,
   * dynamic limits, ...) we just always say everything is unlimited, and ignore
   * requests from the application to try to increase the soft limit.
   *
   * Alternatively, we could track limits dynamically per-process and preserve
   * the illusion that they can be changed. It may be possible to actually
   * change limits deterministically in many cases, if need be, so long as the
   * starting limits are deterministic.
  */
  struct rlimit* rp = (struct rlimit*) t.arg4();
  if (rp != nullptr) {
    struct rlimit noLimits = {};
    noLimits.rlim_cur = RLIM_INFINITY;
    noLimits.rlim_max = RLIM_INFINITY;

    //s.log.writeToLog(Importance::info, "rp=" + to_string(t.arg4()), t.getPid());
    ptracer::writeToTracee(rp, noLimits, t.getPid());
  }

  return;
}
// =======================================================================================
readSystemCall::readSystemCall(long syscallNumber, string syscallName):
  systemCall(syscallNumber, syscallName){
  return;
}

bool readSystemCall::handleDetPre(state &s, ptracer &t){
  s.preIp = t.regs.rip;
  return true;
}

void readSystemCall::handleDetPost(state &s, ptracer &t){
  // TODO:
  int retVal = t.getReturnValue();
  if(retVal < 0) {
    throw runtime_error("Read failed with: " + string{ strerror(- retVal) });
  }
  ssize_t bytes_read = retVal;
  ssize_t bytes_requested = t.arg3();
  if (bytes_read != bytes_requested && bytes_read != 0) {
    t.writeArg2(t.arg2() + bytes_read);
    t.writeArg3(t.arg3() - bytes_read);
    t.writeIp(s.preIp);
    s.preIp = 0;
  }
  return;
}
// =======================================================================================
readlinkSystemCall::readlinkSystemCall(long syscallNumber, string syscallName):
  systemCall(syscallNumber, syscallName){
  return;
}

bool readlinkSystemCall::handleDetPre(state &s, ptracer &t){
  return true;
}

void readlinkSystemCall::handleDetPost(state &s, ptracer &t){
  // Nothing for now.
  return;
}
// ========================================================================================
readvSystemCall::readvSystemCall(long syscallNumber, string syscallName):
  systemCall(syscallNumber, syscallName){
  return;
}

bool readvSystemCall::handleDetPre(state &s, ptracer &t){
  return true;
}

void readvSystemCall::handleDetPost(state &s, ptracer &t){
  return;
}
// ========================================================================================
recvmsgSystemCall::recvmsgSystemCall(long syscallNumber, string syscallName):
  systemCall(syscallNumber, syscallName){
  return;
}

bool recvmsgSystemCall::handleDetPre(state &s, ptracer &t){
  return true;
}

void recvmsgSystemCall::handleDetPost(state &s, ptracer &t){
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
sendtoSystemCall::sendtoSystemCall(long syscallNumber, string syscallName):
  systemCall(syscallNumber, syscallName){
  return;
}

bool sendtoSystemCall::handleDetPre(state &s, ptracer &t){
  return true;
}

void sendtoSystemCall::handleDetPost(state &s, ptracer &t){
  return;
}
// =======================================================================================
selectSystemCall::selectSystemCall(long syscallNumber, string syscallName):
  systemCall(syscallNumber, syscallName){
  return;
}

bool selectSystemCall::handleDetPre(state &s, ptracer &t){
  return true;
}

void selectSystemCall::handleDetPost(state &s, ptracer &t){
  return;
}
// =======================================================================================

setpgidSystemCall::setpgidSystemCall(long syscallNumber, string syscallName):
  systemCall(syscallNumber, syscallName){
  return;
}

bool setpgidSystemCall::handleDetPre(state &s, ptracer &t){
  return true;
}

void setpgidSystemCall::handleDetPost(state &s, ptracer &t){
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
rt_sigreturnSystemCall::rt_sigreturnSystemCall(long syscallNumber, string syscallName):
  systemCall(syscallNumber, syscallName){
  return;
}

bool rt_sigreturnSystemCall::handleDetPre(state &s, ptracer &t){
  return true;
}

void rt_sigreturnSystemCall::handleDetPost(state &s, ptracer &t){
  return;
}
// =======================================================================================
socketSystemCall::socketSystemCall(long syscallNumber, string syscallName):
  systemCall(syscallNumber, syscallName){
  return;
}

bool socketSystemCall::handleDetPre(state &s, ptracer &t){
  return true;
}

void socketSystemCall::handleDetPost(state &s, ptracer &t){
  return;
}
// =======================================================================================
statSystemCall::statSystemCall(long syscallNumber, string syscallName):
  systemCall(syscallNumber, syscallName){
  return;
}

bool statSystemCall::handleDetPre(state &s, ptracer &t){
  string path = ptracer::readTraceeCString((const char*)t.arg1(), t.getPid());
  string msg = "stat-ing path: " + logger::makeTextColored(Color::green, path) + "\n";
  s.log.writeToLog(Importance::info, msg);

  return true;
}

void statSystemCall::handleDetPost(state &s, ptracer &t){
  handleStatFamily(s, t, "stat");
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
  }else{
    s.log.writeToLog(Importance::info, "Negative number returned from statfs call:\n.");
  }

  return;
}
// =======================================================================================
sysinfoSystemCall::sysinfoSystemCall(long syscallNumber, string syscallName):
  systemCall(syscallNumber, syscallName){
  return;
}

bool sysinfoSystemCall::handleDetPre(state &s, ptracer &t){
  return true;
}

void sysinfoSystemCall::handleDetPost(state &s, ptracer &t){
  // TODO. Mask out the stuff we don't want the user to see.
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
tgkillSystemCall::tgkillSystemCall(long syscallNumber, string syscallName):
  systemCall(syscallNumber, syscallName){
  return;
}

bool tgkillSystemCall::handleDetPre(state &s, ptracer &t){
  return true;
}

void tgkillSystemCall::handleDetPost(state &s, ptracer &t){
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
umaskSystemCall::umaskSystemCall(long syscallNumber, string syscallName):
  systemCall(syscallNumber, syscallName){
  return;
}

bool umaskSystemCall::handleDetPre(state &s, ptracer &t){
  return true;
}

void umaskSystemCall::handleDetPost(state &s, ptracer &t){
  return;
}
// =======================================================================================
unameSystemCall::unameSystemCall(long syscallNumber, string syscallName):
  systemCall(syscallNumber, syscallName){
  return;
}

bool unameSystemCall::handleDetPre(state &s, ptracer &t){
  return true;
}

void unameSystemCall::handleDetPost(state &s, ptracer &t){
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
unlinkSystemCall::unlinkSystemCall(long syscallNumber, string syscallName):
  systemCall(syscallNumber, syscallName){
  return;
}

bool unlinkSystemCall::handleDetPre(state &s, ptracer &t){
  string path = ptracer::readTraceeCString((const char*)t.arg1(), t.getPid());
  string msg = "unlink-ing path: " + logger::makeTextColored(Color::green, path) + "\n";
  s.log.writeToLog(Importance::info, msg);
  return true;
}

void unlinkSystemCall::handleDetPost(state &s, ptracer &t){
  return;
}
// =======================================================================================
unlinkatSystemCall::unlinkatSystemCall(long syscallNumber, string syscallName):
  systemCall(syscallNumber, syscallName){
  return;
}

bool unlinkatSystemCall::handleDetPre(state &s, ptracer &t){
  string path = ptracer::readTraceeCString((const char*)t.arg2(), t.getPid());
  string msg = "unlinkat-ing path: " + logger::makeTextColored(Color::green, path) + "\n";
  s.log.writeToLog(Importance::info, msg);
  return true;
}

void unlinkatSystemCall::handleDetPost(state &s, ptracer &t){
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
  // Set times to our own logical time for deterministic time only if times is null.
  if((const struct timespec*) t.arg3() != nullptr){
    // Nothing to do, user specified his/her own time which should be deterministic.
    return true;
  }

  // We need somewhere to store a timespec struct if our struct is null. We will write
  // this data below the current stack pointer accounting for the red zone, known to be
  // 128 bytes.
  uint64_t rsp = t.regs.rsp;
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
  return true;
}

void utimensatSystemCall::handleDetPost(state &s, ptracer &t){
  return;
}
// =======================================================================================
vforkSystemCall::vforkSystemCall(long syscallNumber, string syscallName):
  systemCall(syscallNumber, syscallName){
  return;
}

bool vforkSystemCall::handleDetPre(state &s, ptracer &t){
  return true;
}

void vforkSystemCall::handleDetPost(state &s, ptracer &t){
  // The ptrace option for fork handles most of the logic for forking.
  return;
}
// =======================================================================================
wait4SystemCall::wait4SystemCall(long syscallNumber, string syscallName):
  systemCall(syscallNumber, syscallName){
  return;
}

bool wait4SystemCall::handleDetPre(state &s, ptracer &t){
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
  // TODO: Handle bytes written.
  return;
}
// =======================================================================================
writevSystemCall::writevSystemCall(long syscallNumber, string syscallName):
  systemCall(syscallNumber, syscallName){
  return;
}

bool writevSystemCall::handleDetPre(state &s, ptracer &t){
  return true;
}

void writevSystemCall::handleDetPost(state &s, ptracer &t){
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

    myStat.st_atim = timespec { .tv_sec =  s.getLogicalTime(),
                                .tv_nsec = s.getLogicalTime() };  /* user CPU time used */
    // myStat.st_mtim = timespec { .tv_sec =  s.getLogicalTime(),
                                // .tv_nsec = s.getLogicalTime() };
    myStat.st_mtim = timespec { .tv_sec =  0,
				.tv_nsec = 0 };
    myStat.st_ctim = timespec { .tv_sec = s.getLogicalTime(),
                                .tv_nsec = s.getLogicalTime() };  /* user CPU time used */

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
    myStat.st_uid = 65534;         /* User ID of owner */
    myStat.st_gid = 1;         /* Group ID of owner */
    myStat.st_rdev = 1;        /* Device ID (if special file) */

    // Program will stall if we put some arbitrary value here: TODO.
    // myStat.st_size = 512;        /* Total size, in bytes */

    myStat.st_blksize = 512;     /* Block size for filesystem I/O */

    // TODO: could return actual value here?
    myStat.st_blocks = 1;      /* Number of 512B blocks allocated */

    // s.incrementTime();

    // Write back result for child.
    ptracer::writeToTracee(statPtr, myStat, s.traceePid);
  } else {
    s.log.writeToLog(Importance::info, "Error in "
		     + syscallName + ":\n" + string { strerror(- retVal)} + "\n");
  }
  return;
}
// =======================================================================================
bool isPrefix(const string& data, const string& prefix){
    auto mismatch = std::mismatch(data.begin(),   data.end(),
                                  prefix.begin(), prefix.end()).second;
    return mismatch == prefix.end();
}
// =======================================================================================
