#include <arpa/inet.h>
#include <asm/prctl.h>
#include <errno.h>
#include <fcntl.h> /* Obtain O_* constant definitions */
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/timerfd.h>
#include <sys/times.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <unistd.h>

#include <cstring>
#include <limits>
#include <optional>

#include <linux/fiemap.h>
#include <linux/fs.h>
#include <linux/futex.h>
#include <linux/rtc.h>
#include <sys/resource.h>
#include <sys/sysinfo.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <utime.h>
#include <unordered_map>

#include <optional>

#include "dettraceSystemCall.hpp"
#include "execution.hpp"
#include "ptracer.hpp"
#include "utilSystemCalls.hpp"

// Enable tracee reads that are not strictly necessary for functionality, but
// are enabled for instrumentation or sanity checking. For example, verify,
// before system call replay, that RIP points at a valid system call insn.
// #define EXTRANEOUS_TRACEE_READS 0

using namespace std;

static bool fd_is_nonblocking(state& s, int fd);

// =======================================================================================
bool accessSystemCall::handleDetPre(
    globalState& gs, state& s, ptracer& t, scheduler& sched) {
  printInfoString(t.arg1(), gs.log, s.traceePid, t);
  return true;
}
void accessSystemCall::handleDetPost(
    globalState& gs, state& s, ptracer& t, scheduler& sched) {
  return;
}
// =======================================================================================
bool arch_prctlSystemCall::handleDetPre(
    globalState& gs, state& s, ptracer& t, scheduler& sched) {
  gs.log.writeToLog(
      Importance::info,
      "pre-hook for arch_prctl(%d, 0) == ARCH_SET_CPUID? %d\n", t.arg1(),
      t.arg1() == ARCH_SET_CPUID);

  // System call injected due to us needing CPUID interception added to this
  // process!
  if (s.syscallInjected) {
    return true;
  }

  return false;
}
void arch_prctlSystemCall::handleDetPost(
    globalState& gs, state& s, ptracer& t, scheduler& sched) {
  if (!s.syscallInjected) {
    // This should be impossible.
    runtimeError("Got to arch_prctl post-hook without it being injected.");
  }

  gs.log.writeToLog(
      Importance::info, "post-hook for arch_prctl, returning %d\n",
      t.getReturnValue());

  if (s.CPUIDTrapSet) {
    // This should be impossible.
    runtimeError(
        "Got to arch_prctl post-hook without it needing to have CPUID trap "
        "set.");
  }

  // arch_prctl could return ENODEV when `cpuid_fault` flag is absent (cpuinfo).
  if (0 != t.getReturnValue()) {
    string errmsg("cpuid interception (cpuid_fault) via arch_prctl failed: ");
    errmsg += strerror(-t.getReturnValue());
    errmsg += "\nPlease check `cpuid_fault` flag from `cat /proc/cpuinfo`";
    gs.log.writeToLog(Importance::inter, errmsg);
    gs.allow_trapCPUID = false;
  } else {
    s.CPUIDTrapSet = true;
  }

  s.syscallInjected = false;
  // I don't believe arch_prctl(ARCH_SET_CPUID) writes to tracee memory at all.
  t.setRegs(s.regSaver.popRegisterState());

  gs.log.writeToLog(
      Importance::info, "restored register state from arch_prctl post-hook\n");
  replaySystemCall(gs, t, t.getSystemCallNumber());
}
// =======================================================================================
bool alarmSystemCall::handleDetPre(
    globalState& gs, state& s, ptracer& t, scheduler& sched) {
  gs.log.writeToLog(
      Importance::info, "alarm pre-hook, requesting alarm in %u second(s)\n",
      t.arg1());
  // run post-hook if necessary
  return sendTraceeSignalNow(SIGALRM, gs, s, t, sched);
}

void alarmSystemCall::handleDetPost(
    globalState& gs, state& s, ptracer& t, scheduler& sched) {
  return;
}
// =======================================================================================
bool chdirSystemCall::handleDetPre(
    globalState& gs, state& s, ptracer& t, scheduler& sched) {
  printInfoString(t.arg1(), gs.log, s.traceePid, t);

  return false;
}

void chdirSystemCall::handleDetPost(
    globalState& gs, state& s, ptracer& t, scheduler& sched) {
  return;
}
// =======================================================================================
bool chmodSystemCall::handleDetPre(
    globalState& gs, state& s, ptracer& t, scheduler& sched) {
  printInfoString(t.arg1(), gs.log, s.traceePid, t);
  return false;
}

void chmodSystemCall::handleDetPost(
    globalState& gs, state& s, ptracer& t, scheduler& sched) {
  return;
}
// =======================================================================================
bool clock_gettimeSystemCall::handleDetPre(
    globalState& gs, state& s, ptracer& t, scheduler& sched) {
  return true;
}

void clock_gettimeSystemCall::handleDetPost(
    globalState& gs, state& s, ptracer& t, scheduler& sched) {
  gs.timeCalls++;
  struct timespec* tp = (struct timespec*)t.arg2();

  if (tp != nullptr) {
    const auto myTp = logical_clock::to_timespec(s.getLogicalTime());
    t.writeToTracee(traceePtr<struct timespec>(tp), myTp, t.getPid());
    s.incrementTime();
    // preempt current task avoid some task busy checking current time
    // Since preemption can happen any place in Linux, we are not really
    // breaking any assumptions..
    sched.preemptAndScheduleNext();
  }

  return;
}
// =======================================================================================
bool closeSystemCall::handleDetPre(
    globalState& gs, state& s, ptracer& t, scheduler& sched) {
  return true;
}

void closeSystemCall::handleDetPost(
    globalState& gs, state& s, ptracer& t, scheduler& sched) {
  int fd = (int)t.arg1();
  gs.log.writeToLog(Importance::info, "close(%d)\n", fd);
  // Remove entry from our dirEntries.
  auto result = s.dirEntries.find(fd);
  // Exists.
  if (result != s.dirEntries.end()) {
    gs.log.writeToLog(
        Importance::info, "Removing directory entries for fd: %d!\n", fd);
    s.dirEntries.erase(result);
  }

  // Remove entry from our fd set for pipes.
  if (s.countFdStatus(fd) != 0) {
    gs.log.writeToLog(Importance::info, "Removing pipe fd: %d!\n", fd);
    s.fdStatus.get()->erase(fd);
  }

  if (s.fd_is_remote(fd)) {
    s.remote_sockfds->erase(fd);
  }
  if (s.fd_is_timerfd(fd)) {
    s.timerfds->erase(fd);
  }
  if (s.fd_is_signalfd(fd)) {
    s.signalfds->erase(fd);
  }
}
// =======================================================================================
// TODO
bool connectSystemCall::handleDetPre(
    globalState& gs, state& s, ptracer& t, scheduler& sched) {
  int sockfd = t.arg1();
  socklen_t len = t.arg3();
  char* buff;
  char dst[128] = {
      0,
  };

  if (len == INET6_ADDRSTRLEN) {
    auto sockaddr = t.readFromTracee(
        traceePtr<struct sockaddr_in6>((struct sockaddr_in6*)t.arg2()),
        t.getPid());
    asprintf(
        &buff, "connect to sock fd %u %s#%u\n", sockfd,
        inet_ntop(AF_INET6, &sockaddr.sin6_addr, dst, 128),
        ntohs(sockaddr.sin6_port));
  } else {
    auto sockaddr = t.readFromTracee(
        traceePtr<struct sockaddr_in>((struct sockaddr_in*)t.arg2()),
        t.getPid());
    asprintf(
        &buff, "connect to sock fd %u %s#%u\n", sockfd,
        inet_ntop(AF_INET, &sockaddr.sin_addr, dst, 128),
        ntohs(sockaddr.sin_port));
  }
  gs.log.writeToLog(Importance::info, buff);
  free(buff);

  return true;
}

void connectSystemCall::handleDetPost(
    globalState& gs, state& s, ptracer& t, scheduler& sched) {
  return;
}
// =======================================================================================
bool creatSystemCall::handleDetPre(
    globalState& gs, state& s, ptracer& t, scheduler& sched) {
  printInfoString(t.arg1(), gs.log, s.traceePid, t);
  return true;
}

void creatSystemCall::handleDetPost(
    globalState& gs, state& s, ptracer& t, scheduler& sched) {
  if (t.getReturnValue() < 0) {
    return;
  }

  // Add an entry for this new file to our inode with a newer modified date.
  // If the file already exists, creat truncates it since:
  // create == open(O_CREATE | O_WRONLY | O_TRUNC)
  // The inode is reused though, this is based on emperical observation, and I
  // do not thin the POSIX semantics say this must happen, so we read the inode
  // here to be safe. (Not sure how we could use this information to optimze
  // anyways.)
  auto inode = readInodeFor(gs.log, s.traceePid, t.getReturnValue());
  gs.mtimeMap[inode] = s.getLogicalTime();
  gs.inodeMap.addRealValue(inode);
  s.incrementTime();

  return;
}
// =======================================================================================
bool dupSystemCall::handleDetPre(
    globalState& gs, state& s, ptracer& t, scheduler& sched) {
  return true;
}

void dupSystemCall::handleDetPost(
    globalState& gs, state& s, ptracer& t, scheduler& sched) {
  int newfd = t.getReturnValue();
  int fd = t.arg1();
  if (newfd < 0) {
    return;
  }

  // dup succeeded.
  if (s.countFdStatus(fd) != 0) { // Only for pipes
    s.setFdStatus(newfd, s.getFdStatus(fd)); // copy over status.
    if (s.fd_is_remote(fd)) {
      s.remote_sockfds->insert(newfd);
    }
    gs.log.writeToLog(Importance::info, "%d = dup(%d)\n", newfd, fd);
  }
}
// =======================================================================================
bool dup2SystemCall::handleDetPre(
    globalState& gs, state& s, ptracer& t, scheduler& sched) {
  return true;
}

void dup2SystemCall::handleDetPost(
    globalState& gs, state& s, ptracer& t, scheduler& sched) {
  int newfd = t.getReturnValue();
  int fd = t.arg1();
  gs.log.writeToLog(Importance::info, "dup2(%d) returned %d\n", fd, newfd);
  if (newfd < 0) {
    return;
  }

  // dup2 succeeded.
  if (s.countFdStatus(fd) != 0) { // Only for pipes

    // Semantics of dup2 say old fd could be closed and overwritten, we do that
    // implicitly here!
    s.setFdStatus(newfd, s.getFdStatus(fd));
    if (s.fd_is_remote(fd)) {
      s.remote_sockfds->insert(newfd);
    }
    if (s.fd_is_timerfd(fd)) {
      auto it = (*s.timerfds)[fd];
      s.timerfds->insert({newfd, it});
    }
    if (s.fd_is_signalfd(fd)) {
      s.signalfds->insert(newfd);
    }
    gs.log.writeToLog(Importance::info, "%d = dup2(%d)\n", newfd, fd);
  }
}

static const char* epoll_op(int op) {
  switch (op) {
  case EPOLL_CTL_ADD:
    return "EPOLL_CTL_ADD";
  case EPOLL_CTL_MOD:
    return "EPOLL_CTL_MOD";
  case EPOLL_CTL_DEL:
    return "EPOLL_CTL_DEL";
  default:
    return "EPOLL_CTL_<ERROR>";
  }
}

// =======================================================================================
bool epoll_ctlSystemCall::handleDetPre(
    globalState& gs, state& s, ptracer& t, scheduler& sched) {
  struct epoll_event* traceeEvent = (struct epoll_event*)t.arg4();
  struct epoll_event epev = {
      0,
  };

  string op = epoll_op((int)t.arg2());

  gs.log.writeToLog(
      Importance::info, "epoll_ctl(" + to_string(t.arg1()) + "..)\n");

  readVmTraceeRaw(
      traceePtr<struct epoll_event>(traceeEvent), &epev, sizeof(epev),
      s.traceePid);
  if ((epev.events & EPOLLONESHOT) == EPOLLONESHOT) {
    runtimeError("epoll_ctl call used EPOLLONESHOT flag!");
  }
  if ((epev.events & EPOLLIN) == EPOLLIN) {
    gs.log.writeToLog(
        Importance::info, op + " EPOLLIN " + to_string(epev.data.u64) + "\n");
  }
  if ((epev.events & EPOLLOUT) == EPOLLOUT) {
    gs.log.writeToLog(
        Importance::info, op + " EPOLLOUT " + to_string(epev.data.u64) + "\n");
  }
  if ((epev.events & EPOLLPRI) == EPOLLERR) {
    gs.log.writeToLog(
        Importance::info, op + " EPOLLERR " + to_string(epev.data.u64) + "\n");
  }
  if ((epev.events & EPOLLPRI) == EPOLLPRI) {
    gs.log.writeToLog(
        Importance::info, op + " EPOLLPRI " + to_string(epev.data.u64) + "\n");
  }

  return false;
}

void epoll_ctlSystemCall::handleDetPost(
    globalState& gs, state& s, ptracer& t, scheduler& sched) {
  return;
}

static void epoll_log_event(globalState& gs, ptracer& t) {
  int epoll_fd = (int)t.arg1();
  int maxevents = min(t.getReturnValue(), (int)t.arg3());

  const int size = 8192;
  char buffer[8192], *p = buffer;
  int n = 0;

  p += snprintf(p + n, size - n, "epoll_wait(%u, [", epoll_fd);
  for (int i = 0; i < maxevents; i++) {
    auto rptr =
        traceePtr<struct epoll_event>((struct epoll_event*)t.arg2() + i);
    struct epoll_event ev = t.readFromTracee(rptr, t.getPid());
    p += snprintf(
        p + n, size - n, " (%s, %lu)", epoll_op(ev.events), ev.data.u64);
  }
  snprintf(p + n, size - n, "]\n");
  gs.log.writeToLogNoFormat(Importance::extra, buffer);
}

// =======================================================================================
bool epoll_waitSystemCall::handleDetPre(
    globalState& gs, state& s, ptracer& t, scheduler& sched) {
  // Set the timeout to zero.
  s.originalArg4 = t.arg4();
  if ((int)s.originalArg4 != 0) {
    t.writeArg4(0);
  }

  gs.log.writeToLog(
      Importance::info, "epoll_wait on fd: " + to_string(t.arg1()) + "\n");
  return true;
}

void epoll_waitSystemCall::handleDetPost(
    globalState& gs, state& s, ptracer& t, scheduler& sched) {
  if ((int)t.getReturnValue() > 0) {
    epoll_log_event(gs, t);
  }

  if ((int)s.originalArg4 < 0) {
    gs.log.writeToLog(Importance::info, "Blocking epoll_wait found\n");
    bool replay = replaySyscallIfBlocked(gs, s, t, sched, 0);
    if (replay) {
      t.writeArg4(s.originalArg4);
    }
  } else {
    gs.log.writeToLog(Importance::info, "Non-blocking epoll found\n");
    sched.preemptAndScheduleNext();
  }
  return;
}
// =======================================================================================
bool epoll_pwaitSystemCall::handleDetPre(
    globalState& gs, state& s, ptracer& t, scheduler& sched) {
  // Set the timeout to zero.
  s.originalArg4 = t.arg4();
  if ((int)s.originalArg4 != 0) {
    t.writeArg4(0);
  }
  return true;
}

void epoll_pwaitSystemCall::handleDetPost(
    globalState& gs, state& s, ptracer& t, scheduler& sched) {
  if ((int)s.originalArg4 < 0) {
    gs.log.writeToLog(Importance::info, "Blocking epoll_wait found\n");
    bool replay = replaySyscallIfBlocked(gs, s, t, sched, 0);
    if (replay) {
      t.writeArg4(s.originalArg4);
    }
  } else {
    gs.log.writeToLog(Importance::info, "Non-blocking epoll found\n");
    sched.preemptAndScheduleNext();
  }
  return;
}
// =======================================================================================
bool execveSystemCall::handleDetPre(
    globalState& gs, state& s, ptracer& t, scheduler& sched) {
  printInfoString(t.arg1(), gs.log, s.traceePid, t);

  auto tgNumber = gs.threadGroupNumber.at(s.traceePid);
  if (gs.threadGroups.count(tgNumber) != 1) {
    runtimeError("We do not support exec from threaded process groups!");
  }

  char** argv = (char**)t.arg2();
  char** envp = (char**)t.arg3();
  string execveArgs{};
  string execveEnvp{};

  // Print all arguments to execve!
  if (gs.log.getDebugLevel() > 0) {
    // Remeber these are addresses in the tracee. We must explicitly read them
    // ourselves!
    if (argv != nullptr) {
      for (int i = 0; true; i++) {
        // Make sure it's non null before reading to string.
        char* address =
            t.readFromTracee(traceePtr<char*>(&(argv[i])), t.getPid());
        if (address == nullptr) {
          break;
        }
        execveArgs +=
            " \"" + t.readTraceeCString(traceePtr<char>(address), t.getPid()) +
            "\" ";
      }
    }

    if (envp != nullptr) {
      for (int i = 0; true; i++) {
        // Make sure it's non null before reading to string.
        char* address =
            t.readFromTracee(traceePtr<char*>(&(envp[i])), t.getPid());
        if (address == nullptr) {
          break;
        }
        execveEnvp +=
            " \"" + t.readTraceeCString(traceePtr<char>(address), t.getPid()) +
            "\" ";
      }
    }

    auto msg =
        "Args: " + gs.log.makeTextColored(Color::green, execveArgs) + "\n";
    gs.log.writeToLogNoFormat(Importance::info, msg);
    auto msg2 =
        "Envp: " + gs.log.makeTextColored(Color::green, execveEnvp) + "\n";
    gs.log.writeToLogNoFormat(Importance::info, msg2);
  }

  // WARNING: Never change this, there is no execve post-hook event. You will
  // end up and the next system call. In the past, we have seen a brk.
  return false;
}

// =======================================================================================
bool exit_groupSystemCall::handleDetPre(
    globalState& gs, state& s, ptracer& t, scheduler& sched) {
  gs.log.writeToLog(Importance::info, "Saw exit group!!\n");
  s.isExitGroup = true;
  return false;
}

void exit_groupSystemCall::handleDetPost(
    globalState& gs, state& s, ptracer& t, scheduler& sched) {
  gs.log.writeToLog(Importance::info, "Saw exit group post hook!!\n");
}
// =======================================================================================
bool fchownatSystemCall::handleDetPre(
    globalState& gs, state& s, ptracer& t, scheduler& sched) {
  printInfoString(t.arg2(), gs.log, s.traceePid, t);
  if (t.arg3() != 0) {
    t.writeArg3(0);
  }
  if (t.arg4() != 0) {
    t.writeArg4(0);
  }

  return false;
}

void fchownatSystemCall::handleDetPost(
    globalState& gs, state& s, ptracer& t, scheduler& sched) {
  runtimeError("fchownat post hook shold never be called.");
  return;
}
// =======================================================================================
bool fchownSystemCall::handleDetPre(
    globalState& gs, state& s, ptracer& t, scheduler& sched) {
  if (t.arg2() != 0) {
    t.writeArg2(0);
  }
  if (t.arg3() != 0) {
    t.writeArg3(0);
  }
  return false;
}

void fchownSystemCall::handleDetPost(
    globalState& gs, state& s, ptracer& t, scheduler& sched) {
  runtimeError("fchownat post hook shold never be called.");
  return;
}
// =======================================================================================
bool chownSystemCall::handleDetPre(
    globalState& gs, state& s, ptracer& t, scheduler& sched) {
  if (t.arg2() != 0) {
    t.writeArg2(0);
  }
  if (t.arg3() != 0) {
    t.writeArg3(0);
  }
  return false;
}

void chownSystemCall::handleDetPost(
    globalState& gs, state& s, ptracer& t, scheduler& sched) {
  runtimeError("fchownat post hook shold never be called.");
  return;
}
// =======================================================================================
bool lchownSystemCall::handleDetPre(
    globalState& gs, state& s, ptracer& t, scheduler& sched) {
  if (t.arg2() != 0) {
    t.writeArg2(0);
  }
  if (t.arg3() != 0) {
    t.writeArg3(0);
  }
  return false;
}

void lchownSystemCall::handleDetPost(
    globalState& gs, state& s, ptracer& t, scheduler& sched) {
  runtimeError("fchownat post hook shold never be called.");
  return;
}
// =======================================================================================
bool fcntlSystemCall::handleDetPre(
    globalState& gs, state& s, ptracer& t, scheduler& sched) {
  int cmd = t.arg2();

  if (cmd == F_GETFD) {
    return false;
  }
  return true;
}

void fcntlSystemCall::handleDetPost(
    globalState& gs, state& s, ptracer& t, scheduler& sched) {
  int retval = t.getReturnValue();
  int fd = t.arg1();
  int cmd = t.arg2();
  int arg = t.arg3();

  gs.log.writeToLog(
      Importance::extra, "fcntl(" + to_string(fd) + ", " + to_string(cmd) +
                             "..) = " + to_string(retval) + "\n");

  if (cmd == F_DUPFD || cmd == F_DUPFD_CLOEXEC) {
    auto str = "found fcntl(%d, FDUPFD || F_DUPFD_CLOCEXEC) = %d\n";
    int newfd = retval;
    gs.log.writeToLog(Importance::info, str, fd, newfd);
    auto it = s.fdStatus.get()->find(fd);
    auto end = s.fdStatus.get()->end();
    if (it != end) {
      // Same status as what it was duped from.
      (*s.fdStatus.get())[newfd] = s.getFdStatus(fd);
      if (s.fd_is_remote(fd)) {
        s.remote_sockfds->insert(newfd);
      }
      if (s.fd_is_timerfd(fd)) {
        auto it = (*s.timerfds)[fd];
        s.timerfds->insert({newfd, it});
      }
      if (s.fd_is_signalfd(fd)) {
        s.signalfds->insert(newfd);
      }
    }
  }

  // User attempting to change blocked status.
  if (cmd == F_SETFL && ((arg & O_NONBLOCK) != 0)) {
    gs.log.writeToLog(
        Importance::info, "found fcntl setting %d to non blocking!\n", fd);
    (*s.fdStatus.get())[fd] = descriptorType::nonBlocking;
  }
}
// =======================================================================================
bool faccessatSystemCall::handleDetPre(
    globalState& gs, state& s, ptracer& t, scheduler& sched) {
  printInfoString(t.arg2(), gs.log, s.traceePid, t);

  return false;
}

void faccessatSystemCall::handleDetPost(
    globalState& gs, state& s, ptracer& t, scheduler& sched) {
  runtimeError("faccessat post hook shold never be called.");
  return;
}
// =======================================================================================
bool fgetxattrSystemCall::handleDetPre(
    globalState& gs, state& s, ptracer& t, scheduler& sched) {
  return true;
}

void fgetxattrSystemCall::handleDetPost(
    globalState& gs, state& s, ptracer& t, scheduler& sched) {
  printInfoString(t.arg2(), gs.log, s.traceePid, t);

  return;
}
// =======================================================================================
bool flistxattrSystemCall::handleDetPre(
    globalState& gs, state& s, ptracer& t, scheduler& sched) {
  return true;
}

void flistxattrSystemCall::handleDetPost(
    globalState& gs, state& s, ptracer& t, scheduler& sched) {
  printInfoString(t.arg2(), gs.log, s.traceePid, t);

  return;
}
// =======================================================================================
bool fstatSystemCall::handleDetPre(
    globalState& gs, state& s, ptracer& t, scheduler& sched) {
  gs.log.writeToLog(Importance::info, "fstat(fd=%d)\n", t.arg1());
  return true;
}

void fstatSystemCall::handleDetPost(
    globalState& gs, state& s, ptracer& t, scheduler& sched) {
  handleStatFamily(gs, s, t, "fstat");
  return;
}

/* glibc does not exports below macros */
#define DEVFS_SUPER_MAGIC 0x1373
#define DEVPTS_SUPER_MAGIC 0x1cd1

static void interceptStatfs(traceePtr<struct statfs> rptr, ptracer& t) {
  auto st = t.readFromTracee(rptr, t.getPid());
  if (st.f_type != DEVPTS_SUPER_MAGIC && st.f_type != DEVFS_SUPER_MAGIC) {
    struct statfs stats;
    memset(&stats, 0, sizeof(stats));
    zeroOutStatfs(stats);
    t.writeToTracee(rptr, stats, t.getPid());
  }
}

// =======================================================================================
bool fstatfsSystemCall::handleDetPre(
    globalState& gs, state& s, ptracer& t, scheduler& sched) {
  return true;
}

void fstatfsSystemCall::handleDetPost(
    globalState& gs, state& s, ptracer& t, scheduler& sched) {
  struct statfs* statfsPtr = (struct statfs*)t.arg2();

  if (statfsPtr == nullptr) {
    gs.log.writeToLog(Importance::info, "fstatfs: statfsbuf null.\n");
    return;
  }

  if (t.getReturnValue() == 0) {
    interceptStatfs(traceePtr<struct statfs>(statfsPtr), t);
  } else {
    printf("statfs returned %d\n", t.getReturnValue());
  }

  return;
}

// =======================================================================================
bool futexSystemCall::handleDetPre(
    globalState& gs, state& s, ptracer& t, scheduler& sched) {
  // If operation is a FUTEX_WAIT, set timeout to zero for polling instead of
  // blocking.
  int futexOp = t.arg2();
  int futexValue = t.arg3();
  timespec* timeoutPtr = (timespec*)t.arg4();

  // See definitions of variables here.
  // https://github.com/spotify/linux/blob/master/include/linux/futex.h
  int futexCmd = futexOp & FUTEX_CMD_MASK;
  gs.log.writeToLog(
      Importance::info, "Operation: " + futexCommands.at(futexCmd) + "\n");

  if ((futexOp & FUTEX_PRIVATE_FLAG) != 0) {
    gs.log.writeToLog(Importance::info, "with: FUTEX_PRIVATE_FLAG\n");
  }
  if ((futexOp & FUTEX_CLOCK_REALTIME) != 0) {
    gs.log.writeToLog(Importance::info, "with: FUTEX_CLOCK_REALTIME\n");
  }
  if (timeoutPtr != NULL) {
    gs.log.writeToLog(Importance::info, "with: user defined timeout.\n");
  }

  // Handle wake operations by notifying scheduler of progress.
  if (futexCmd == FUTEX_WAKE || futexCmd == FUTEX_REQUEUE ||
      futexCmd == FUTEX_CMP_REQUEUE || futexCmd == FUTEX_WAKE_BITSET ||
      futexCmd == FUTEX_WAKE_OP) {
    traceePtr<int> rptr((int*)t.arg1());
    int val = t.readFromTracee(rptr, t.getPid());
    gs.log.writeToLog(
        Importance::info,
        "Waking on address: %p = %x, my pid: %u, traceesPid: %u\n", t.arg1(),
        val, t.getPid(), s.traceePid);
    gs.log.writeToLog(
        Importance::info, "Trying to wake up to %d threads.\n", futexValue);

    /*
    auto waiters = futex_remove_waiters(s, t.arg1(), futexValue);
    for (auto pidToWakeup: waiters) {
      if (pidToWakeup != t.getPid()) {
        gs.log.writeToLog(Importance::info, "Scheduling task %d.\n",
    pidToWakeup); sched.addAndScheduleNext(pidToWakeup); } else {
        gs.log.writeToLog(Importance::info, "Scheduling task %d ignored (already
    running)\n", pidToWakeup);
      }
    }
    */
    // No need to go into the post hook.
    return false;
  }

  // Handle wait operations, by setting our timeout to zero, and seeing if time
  // runs out.
  if (futexCmd == FUTEX_WAIT || futexCmd == FUTEX_WAIT_BITSET ||
      futexCmd == FUTEX_WAIT_REQUEUE_PI) {
    gs.log.writeToLog(
        Importance::info, "Waiting on value at address: %p.\n", t.arg1());
    gs.log.writeToLog(
        Importance::info, "Against value: " + to_string(futexValue) + "\n");
    if (gs.log.getDebugLevel() > 0) {
      int actualValue =
          (int)t.readFromTracee(traceePtr<int>((int*)t.arg1()), t.getPid());
      gs.log.writeToLog(
          Importance::info, "Actual value: " + to_string(actualValue) + "\n");
    }

    // Overwrite the current value with our value. Restore value in post hook.
    s.originalArg4 = (uint64_t)timeoutPtr;
    // Our timespec value to copy over.

    timespec ourTimeout = {0};
    if (timeoutPtr == nullptr) {
      gs.log.writeToLog(
          Importance::extra,
          "timeout null, writing our data to mmaped page...\n");
      timespec* newAddress = (timespec*)s.mmapMemory.getAddr().ptr;
      t.writeToTracee(traceePtr<timespec>(newAddress), ourTimeout, s.traceePid);

      // Point system call to new address.
      t.writeArg4((uint64_t)newAddress);
      s.userDefinedTimeout = false;
    } else {
      if (gs.log.getDebugLevel() > 0) {
        timespec timeout =
            t.readFromTracee(traceePtr<timespec>(timeoutPtr), t.getPid());
        gs.log.writeToLog(
            Importance::info,
            "Using original timeout value: (s = %d, ns = %d)\n", timeout.tv_sec,
            timeout.tv_nsec);
      }
      t.writeToTracee(traceePtr<timespec>(timeoutPtr), ourTimeout, s.traceePid);
      s.userDefinedTimeout = true;
    }
  }

  return true;
}

void futexSystemCall::handleDetPost(
    globalState& gs, state& s, ptracer& t, scheduler& sched) {
  int futexOp = t.arg2();
  int futexCmd = futexOp & FUTEX_CMD_MASK;
  if (futexCmd == FUTEX_WAIT || futexCmd == FUTEX_WAIT_BITSET ||
      futexCmd == FUTEX_WAIT_REQUEUE_PI) {
    gs.log.writeToLog(
        Importance::info, "Futex post-hook, handling wait operation.\n");

    // *uaddr != val
    if (t.getReturnValue() == -EAGAIN) {
      return;
    }

    if (s.userDefinedTimeout) {
      // Only preempt if we would have timeout out. Othewise let if continue
      // running!
      if (t.getReturnValue() == -ETIMEDOUT) {
        sched.preemptAndScheduleNext();
      }
      s.userDefinedTimeout = false;
      return;
    } else {
      gs.log.writeToLog(Importance::info, "Replaying futex system call.\n");
      t.writeArg4(s.originalArg4);
      replaySyscallIfBlocked(gs, s, t, sched, ETIMEDOUT);
    }
  }

  return;
}
// =======================================================================================
bool getcwdSystemCall::handleDetPre(
    globalState& gs, state& s, ptracer& t, scheduler& sched) {
  return true;
}
void getcwdSystemCall::handleDetPost(
    globalState& gs, state& s, ptracer& t, scheduler& sched) {
  printInfoString(t.arg1(), gs.log, s.traceePid, t);

  return;
}
// =======================================================================================
bool getdentsSystemCall::handleDetPre(
    globalState& gs, state& s, ptracer& t, scheduler& sched) {
  return true;
}
void getdentsSystemCall::handleDetPost(
    globalState& gs, state& s, ptracer& t, scheduler& sched) {
  handleDents<linux_dirent>(gs, s, t, sched);
  return;
}
// =======================================================================================
bool getdents64SystemCall::handleDetPre(
    globalState& gs, state& s, ptracer& t, scheduler& sched) {
  return true;
}
void getdents64SystemCall::handleDetPost(
    globalState& gs, state& s, ptracer& t, scheduler& sched) {
  handleDents<linux_dirent64>(gs, s, t, sched);
  return;
}
// =======================================================================================
bool getpeernameSystemCall::handleDetPre(
    globalState& gs, state& s, ptracer& t, scheduler& sched) {
  return true;
}
void getpeernameSystemCall::handleDetPost(
    globalState& gs, state& s, ptracer& t, scheduler& sched) {
  // int ret = t.getReturnValue();
  /*
  if(ret == 0){
    runtimeError("Call to getpeername with network socket not suported.\n");
  }
  */
  return;
}
// =======================================================================================
bool getrandomSystemCall::handleDetPre(
    globalState& gs, state& s, ptracer& t, scheduler& sched) {
  return true;
}

void getrandomSystemCall::handleDetPost(
    globalState& gs, state& s, ptracer& t, scheduler& sched) {
  gs.getRandomCalls++;

  char* buf = (char*)t.arg1();
  size_t bufLength = (size_t)t.arg2();

  char prngValues[128];

  // write batches of pseudorandom bytes to the tracee
  for (size_t traceeByteIdx = 0; traceeByteIdx < bufLength;
       traceeByteIdx += sizeof(prngValues)) {
    // Fill buffer with deterministic pseudorandom values
    for (size_t i = 0; i < sizeof(prngValues) / sizeof(uint16_t); i++) {
      uint16_t* prngValues16b = (uint16_t*)prngValues;
      prngValues16b[i] = gs.prng.get();
    }

    // Copy buffer contents to tracee
    size_t amountToWrite = min(sizeof(prngValues), bufLength - traceeByteIdx);
    auto traceeMem = traceePtr<char>{buf + traceeByteIdx};
    writeVmTraceeRaw(prngValues, traceeMem, amountToWrite, t.getPid());
    // Explicitly increase counter.
    t.writeVmCalls++;
  }

  return;
}
// =======================================================================================
bool getrlimitSystemCall::handleDetPre(
    globalState& gs, state& s, ptracer& t, scheduler& sched) {
  return true;
}

void getrlimitSystemCall::handleDetPost(
    globalState& gs, state& s, ptracer& t, scheduler& sched) {
  struct rlimit* rp = (struct rlimit*)t.arg2();
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
bool getrusageSystemCall::handleDetPre(
    globalState& gs, state& s, ptracer& t, scheduler& sched) {
  return true;
}
void getrusageSystemCall::handleDetPost(
    globalState& gs, state& s, ptracer& t, scheduler& sched) {
  gs.timeCalls++;
  struct rusage* usagePtr = (struct rusage*)t.arg2();

  if (usagePtr == nullptr) {
    gs.log.writeToLog(Importance::info, "getrusage pointer null.");
  } else {
    // jld; initializing usage from tracee memory seems redundant, as all fields
    // are overwritten below
    struct rusage usage; // = t.readFromTracee(traceePtr<struct
                         // rusage>(usagePtr), t.getPid());
    const auto time = logical_clock::to_timeval(s.getLogicalTime());

    /* user CPU time used */
    usage.ru_utime = time;
    usage.ru_utime = time;
    /* system CPU time used */
    usage.ru_stime = time;
    usage.ru_maxrss = LONG_MAX; /* maximum resident set size */
    usage.ru_ixrss = LONG_MAX; /* integral shared memory size */
    usage.ru_idrss = LONG_MAX; /* integral unshared data size */
    usage.ru_isrss = LONG_MAX; /* integral unshared stack size */
    usage.ru_minflt = LONG_MAX; /* page reclaims (soft page faults) */
    usage.ru_majflt = LONG_MAX; /* page faults (hard page faults) */
    usage.ru_nswap = LONG_MAX; /* swaps */
    usage.ru_inblock = LONG_MAX; /* block input operations */
    usage.ru_oublock = LONG_MAX; /* block output operations */
    usage.ru_msgsnd = LONG_MAX; /* IPC messages sent */
    usage.ru_msgrcv = LONG_MAX; /* IPC messages received */
    usage.ru_nsignals = LONG_MAX; /* signals received */
    usage.ru_nvcsw = LONG_MAX; /* voluntary context switches */
    usage.ru_nivcsw = LONG_MAX; /* involuntary context switches */

    t.writeToTracee(traceePtr<struct rusage>(usagePtr), usage, t.getPid());
  }

  s.incrementTime();
  return;
}
// =======================================================================================
bool getsidSystemCall::handleDetPre(
    globalState& gs, state& s, ptracer& t, scheduler& sched) {
  return true;
}
void getsidSystemCall::handleDetPost(
    globalState& gs, state& s, ptracer& t, scheduler& sched) {
  // NB: pretend everyone is in their own session
  pid_t sid = t.getPid();
  if (0 != t.arg1()) {
    sid = t.arg1();
  }
  t.setReturnRegister(sid);
  return;
}
// =======================================================================================
bool gettimeofdaySystemCall::handleDetPre(
    globalState& gs, state& s, ptracer& t, scheduler& sched) {
  return true;
}

void gettimeofdaySystemCall::handleDetPost(
    globalState& gs, state& s, ptracer& t, scheduler& sched) {
  gs.log.writeToLog(
      Importance::info, "Inside gettimeofday post-hook, sending tv_sec=%d\n",
      s.getLogicalTime().time_since_epoch().count());
  gs.timeCalls++;
  struct timeval* tp = (struct timeval*)t.arg1();
  if (nullptr != tp) {
    const auto myTv = logical_clock::to_timeval(s.getLogicalTime());

    t.writeToTracee(traceePtr<struct timeval>(tp), myTv, t.getPid());
    s.incrementTime();
    // preempt current task avoid some task busy checking current time
    // Since preemption can happen any place in Linux, we are not really
    // breaking any assumptions..
    sched.preemptAndScheduleNext();
  }

  return;
}
// =======================================================================================
bool ioctlSystemCall::handleDetPre(
    globalState& gs, state& s, ptracer& t, scheduler& sched) {
  long request = t.arg2();
  switch (request) {
  // non-supported rtc ops
  case RTC_AIE_ON:
  case RTC_AIE_OFF:
  case RTC_PIE_ON:
  case RTC_PIE_OFF:
  case RTC_UIE_ON:
  case RTC_UIE_OFF:
  case RTC_WKALM_RD:
  case RTC_WKALM_SET:
  case RTC_IRQP_READ:
  case RTC_IRQP_SET: {
    int err = ENOTTY;
    failSystemCall(gs, s, t, err);
    return false;
  } break;
  case TCSBRK: {
    int err = EINVAL;
    failSystemCall(gs, s, t, err);
    return false;
  } break;
  case RTC_SET_TIME:
  case RTC_EPOCH_SET: {
    int err = EPERM;
    failSystemCall(gs, s, t, err);
    return false;
  }
  case RTC_RD_TIME:
  case RTC_EPOCH_READ:
    return true;
  default:
    return true;
  }
}
void ioctlSystemCall::handleDetPost(
    globalState& gs, state& s, ptracer& t, scheduler& sched) {
  int fd = t.arg1();
  const uint64_t request = t.arg2();
  gs.log.writeToLog(Importance::info, "File descriptor: %d\n", fd);
  gs.log.writeToLog(Importance::info, "Request 0x%" PRIx64 "\n", request);

  switch (request) {
  // Even though we don't particularly like TCGETS, we will let it through as we
  // need it for some programs to work, like `more`.
  case TCGETS:
  case TCSETS:
  case TCSETSW:
  case TIOCSPGRP:
  case FIOCLEX:
  case FIONREAD:
  case TCSETSF:
  case TCGETA:
  case FIONCLEX:
  case SIOCGIFHWADDR:
  case SIOCGIFADDR:
    return;
  case TIOCGPTN:
    return;
  case TIOCSPTLCK: /* unlockpt */
    return;
  case TIOCGPTPEER:
    return;
  case TIOCSCTTY:
    return;
  // simulate vt100.
  case TIOCGWINSZ: {
    if (t.arg3() && t.getReturnValue() == 0) {
      struct winsize winsz {
        .ws_row = 24, .ws_col = 80, .ws_xpixel = 480, .ws_ypixel = 640,
      };
      auto rptr = traceePtr<struct winsize>((struct winsize*)t.arg3());
      t.writeToTracee(rptr, winsz, s.traceePid);
    }
  }
    return;
  case TIOCSWINSZ: {
  }
    return;
  case TIOCGPGRP:
  case SIOCSIFMAP:
  case FS_IOC_FIEMAP:
#ifdef FICLONE
  case FICLONE:
#endif
    return;
  case RTC_RD_TIME: {
    const auto logicalTime = logical_clock::to_time_t(s.getLogicalTime());
    struct tm tm = {};

    s.incrementTime();
    gmtime_r(&logicalTime, &tm);

    if (t.arg3()) {
      traceePtr<struct tm> rptr((struct tm*)t.arg3());
      t.writeToTracee(rptr, tm, t.getPid());
    }
  } break;
  case RTC_EPOCH_READ: {
    const auto logicalTime = logical_clock::to_time_t(s.getLogicalTime());
    s.incrementTime();

    if (t.arg3()) {
      traceePtr<time_t> rptr((time_t*)t.arg3());
      t.writeToTracee(rptr, logicalTime, t.getPid());
    }
  } break;
  case FIONBIO: {
    int flag = t.readFromTracee(traceePtr<int>((int*)t.arg3()), t.getPid());
    auto blocking_flag =
        flag ? descriptorType::nonBlocking : descriptorType::blocking;
    auto blocking_msg = flag ? "non blocking" : "blocking";
    gs.log.writeToLog(
        Importance::info, "found ioctl(%d, FIONBIO, &%d), setting %d to %s!\n",
        fd, flag, fd, blocking_msg);
    (*s.fdStatus.get())[fd] = blocking_flag;
  } break;
  default:
    runtimeError(
        "Unsupported ioctl call: fd=" + to_string(t.arg1()) +
        " request=" + to_string(request));
    break;
  }
  return;
}
// =======================================================================================
// TODO
bool llistxattrSystemCall::handleDetPre(
    globalState& gs, state& s, ptracer& t, scheduler& sched) {
  return true;
}
void llistxattrSystemCall::handleDetPost(
    globalState& gs, state& s, ptracer& t, scheduler& sched) {}
// =======================================================================================
// TODO
bool lgetxattrSystemCall::handleDetPre(
    globalState& gs, state& s, ptracer& t, scheduler& sched) {
  return true;
}

void lgetxattrSystemCall::handleDetPost(
    globalState& gs, state& s, ptracer& t, scheduler& sched) {}
// =======================================================================================
bool mmapSystemCall::handleDetPre(
    globalState& gs, state& s, ptracer& t, scheduler& sched) {
  return true;
}

void mmapSystemCall::handleDetPost(
    globalState& gs, state& s, ptracer& t, scheduler& sched) {
  // This isn't a natural call mmap from the tracee we injected this call
  // ourselves!
  if (s.syscallInjected) {
    gs.log.writeToLog(
        Importance::info,
        "This mmap was inject for use in pre and post hook purposes.\n");

    if (t.getRax().ptr == MAP_FAILED) {
      runtimeError(
          "Unable to properly inject mmap call to tracee!\n"
          "mmap call returned: " +
          to_string(t.getReturnValue()) + "\n");
    }
    s.syscallInjected = false;

    // save memory address to be used later
    s.mmapMemory.setAddr(t.getRax());

    // Inject original system call:
    // Previous state that should have been set by system call that created this
    // fstat injection.
    t.setRegs(s.regSaver.popRegisterState());
    replaySystemCall(gs, t, t.getSystemCallNumber());
  }
}
// =======================================================================================
bool nanosleepSystemCall::handleDetPre(
    globalState& gs, state& s, ptracer& t, scheduler& sched) {
  // Write 0 seconds to time. Required to skip waiting at all.
  struct timespec* req = (struct timespec*)t.arg1();
  if (req != nullptr) {
    struct timespec* myReq = (timespec*)s.mmapMemory.getAddr().ptr;
    struct timespec localReq = {0};

    t.writeToTracee(traceePtr<struct timespec>(myReq), localReq, s.traceePid);
    t.writeArg1((uint64_t)myReq);
  }
  return false;
}

void nanosleepSystemCall::handleDetPost(
    globalState& gs, state& s, ptracer& t, scheduler& sched) {
  runtimeError("nanosleep post-hook should never be called.");
}
// =======================================================================================
bool mkdirSystemCall::handleDetPre(
    globalState& gs, state& s, ptracer& t, scheduler& sched) {
  printInfoString(t.arg1(), gs.log, s.traceePid, t);

  return true;
}

void mkdirSystemCall::handleDetPost(
    globalState& gs, state& s, ptracer& t, scheduler& sched) {
  // Add/overwrite entry in our map.
  if (t.getReturnValue() == 0 && (char*)t.arg1() != nullptr) {
    string strPath =
        t.readTraceeCString(traceePtr<char>((char*)t.arg1()), s.traceePid);
    auto inode = inode_from_tracee(strPath, s.traceePid, gs.log, -1);
    if (inode != -1UL) {
      gs.mtimeMap[inode] = s.getLogicalTime();
      gs.inodeMap.addRealValue(inode);
      s.incrementTime();
    }
  }
}
// =======================================================================================
bool mkdiratSystemCall::handleDetPre(
    globalState& gs, state& s, ptracer& t, scheduler& sched) {
  printInfoString(t.arg2(), gs.log, s.traceePid, t);
  gs.log.writeToLog(Importance::info, "dirfd: %d\n", t.arg1());
  return true;
}

void mkdiratSystemCall::handleDetPost(
    globalState& gs, state& s, ptracer& t, scheduler& sched) {
  char* path = (char*)t.arg2();
  // Add/overwrite entry in our map.
  if (t.getReturnValue() == 0 && path != nullptr) {
    string strPath = t.readTraceeCString(traceePtr<char>(path), s.traceePid);
    auto inode = inode_from_tracee(strPath, s.traceePid, gs.log, t.arg1());
    if (inode != -1UL) {
      gs.mtimeMap[inode] = s.getLogicalTime();
      gs.inodeMap.addRealValue(inode);
      s.incrementTime();
    }
  }
}
// =======================================================================================
bool newfstatatSystemCall::handleDetPre(
    globalState& gs, state& s, ptracer& t, scheduler& sched) {
  return true;
}

void newfstatatSystemCall::handleDetPost(
    globalState& gs, state& s, ptracer& t, scheduler& sched) {
  printInfoString(t.arg2(), gs.log, s.traceePid, t);

  // This newfstatat was injected to get the inode belonging to a file that was
  // deleted through: unlink, unlinkat, or rmdir.
  if (s.syscallInjected) {
    gs.log.writeToLog(Importance::info, "This newfstatat was injected.\n");
    s.syscallInjected = false;

    if (t.getReturnValue() >= 0) {
      struct stat* statbufPtr = (struct stat*)t.arg3();
      struct stat statbuf =
          t.readFromTracee(traceePtr<struct stat>(statbufPtr), s.traceePid);

      gs.log.writeToLog(
          Importance::extra,
          "marking (device,inode) = (%lu,%lu) for deletion\n", statbuf.st_dev,
          statbuf.st_ino);

      s.inodeToDelete = statbuf.st_ino;
    } else {
      gs.log.writeToLog(Importance::info, "No such file, that's okay.\n");
      s.inodeToDelete = -1;
    }

    // We got what we wanted. The inode that matches the file called from either
    // unlink, unlinkat, or rmdir. Now replay that system call as we did not let
    // it though.
    t.setRegs(s.regSaver.popRegisterState());
    replaySystemCall(gs, t, t.getSystemCallNumber());
    s.firstTrySystemcall = false;
  } else {
    handleStatFamily(gs, s, t, "newfstatat");
  }

  return;
}
// =======================================================================================
bool lstatSystemCall::handleDetPre(
    globalState& gs, state& s, ptracer& t, scheduler& sched) {
  printInfoString(t.arg1(), gs.log, s.traceePid, t);

  return true;
}

void lstatSystemCall::handleDetPost(
    globalState& gs, state& s, ptracer& t, scheduler& sched) {
  handleStatFamily(gs, s, t, "lstat");
  return;
}
// =======================================================================================
bool linkSystemCall::handleDetPre(
    globalState& gs, state& s, ptracer& t, scheduler& sched) {
  printInfoString(t.arg2(), gs.log, s.traceePid, t, " hardlinking path: ");
  printInfoString(t.arg1(), gs.log, s.traceePid, t, " to path: ");

  return false;
}

void linkSystemCall::handleDetPost(
    globalState& gs, state& s, ptracer& t, scheduler& sched) {
  runtimeError("link post-hook should never be called.");
}
// =======================================================================================
bool linkatSystemCall::handleDetPre(
    globalState& gs, state& s, ptracer& t, scheduler& sched) {
  printInfoString(t.arg4(), gs.log, s.traceePid, t, " hardlinking path: ");
  printInfoString(t.arg2(), gs.log, s.traceePid, t, " to path: ");

  return false;
}

void linkatSystemCall::handleDetPost(
    globalState& gs, state& s, ptracer& t, scheduler& sched) {
  runtimeError("linkat post-hook should never be called.");
}
// =======================================================================================
bool openSystemCall::handleDetPre(
    globalState& gs, state& s, ptracer& t, scheduler& sched) {
  if ((char*)t.arg1() != nullptr) {
    handlePreOpens(gs, s, t, -1, traceePtr<char>{(char*)t.arg1()}, t.arg2());
    return true;
  }
  return false;
}

void openSystemCall::handleDetPost(
    globalState& gs, state& s, ptracer& t, scheduler& sched) {
  // Beware of unsigned numbers, can lead to wrong value if not casted!
  handlePostOpens(gs, s, t, (int)t.arg2());
}
// =======================================================================================
bool openatSystemCall::handleDetPre(
    globalState& gs, state& s, ptracer& t, scheduler& sched) {
  if ((char*)t.arg2() != nullptr) {
    handlePreOpens(
        gs, s, t, t.arg1(), traceePtr<char>{(char*)t.arg2()}, t.arg3());
    return true;
  }
  return false;
}

void openatSystemCall::handleDetPost(
    globalState& gs, state& s, ptracer& t, scheduler& sched) {
  // Beware of sign, can lead to wrong value if not casted!
  handlePostOpens(gs, s, t, (int)t.arg3());
}
// =======================================================================================
bool pauseSystemCall::handleDetPre(
    globalState& gs, state& s, ptracer& t, scheduler& sched) {
  gs.log.writeToLog(Importance::info, "pause pre-hook\n");
  return true;
}

void pauseSystemCall::handleDetPost(
    globalState& gs, state& s, ptracer& t, scheduler& sched) {
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
bool pipeSystemCall::handleDetPre(
    globalState& gs, state& s, ptracer& t, scheduler& sched) {
  gs.log.writeToLog(
      Importance::info, "Making this pipe non-blocking via pipe2\n");

  s.syscallInjected = true;
  t.changeSystemCall(SYS_pipe2);

  // Set so we can restore in pipe2 later.
  s.originalArg2 = t.arg2();
  t.writeArg2(O_NONBLOCK);

  return true;
}

void pipeSystemCall::handleDetPost(
    globalState& gs, state& s, ptracer& t, scheduler& sched) {
  // We should never get here. We always change the call to pipe to a call to
  // pipe2.
  runtimeError("did not expect to arrive a pipe post hook.");
  // Restore original register state.
  // t.writeArg2(s.originalArg2);
  // auto p = getPipeFds(gs, s, t);
  // s.fdStatus[p.first] = descriptorType::blocking;
  // s.fdStatus[p.second] = descriptorType::blocking;
}
// =======================================================================================
bool pipe2SystemCall::handleDetPre(
    globalState& gs, state& s, ptracer& t, scheduler& sched) {
  // We only see this pre-hook if the call was originally a pipe2 and not a pipe
  // that was converted into a pipe2. That's why it's okay to set s.originalArg2
  // here.
  gs.log.writeToLog(Importance::info, "Making this pipe2 non-blocking\n");
  // Convert pipe call to pipe2 to set O_NONBLOCK.
  s.originalArg2 = t.arg2();
  t.writeArg2(t.arg2() | O_NONBLOCK);

  return true;
}

void pipe2SystemCall::handleDetPost(
    globalState& gs, state& s, ptracer& t, scheduler& sched) {
  // Restore original registers.
  t.writeArg2(s.originalArg2);
  auto p = getPipeFds(gs, s, t);

  // Track this file descriptor:
  if (s.countFdStatus(p.first) != 0) {
    runtimeError("Value already in map (fdStatus): " + to_string(p.first));
  }
  if (s.countFdStatus(p.second) != 0) {
    runtimeError("Value already in map (fdStatus): " + to_string(p.second));
  }

  // This was a pipe that got converted to a pipe2.
  if (s.syscallInjected) {
    s.syscallInjected = false;
    gs.log.writeToLog(Importance::info, "This used to a pipe()!\n");
    gs.log.writeToLog(Importance::info, "Set pipe %d as blocking.\n", p.first);
    gs.log.writeToLog(Importance::info, "Set pipe %d as blocking.\n", p.second);
    s.setFdStatus(p.first, descriptorType::blocking);
    s.setFdStatus(p.second, descriptorType::blocking);
  } else {
    // Must be checked after resetting state.
    int flags = (int)t.arg2();

    // Check if set as non=blocking.
    if ((flags & O_NONBLOCK) == 0) {
      gs.log.writeToLog(
          Importance::info, "Set pipe %d as blocking.\n", p.first);
      gs.log.writeToLog(
          Importance::info, "Set pipe %d as blocking.\n", p.second);
      s.setFdStatus(p.first, descriptorType::blocking);
      s.setFdStatus(p.second, descriptorType::blocking);
    } else {
      gs.log.writeToLog(
          Importance::info, "Set pipe %d as non-blocking.\n", p.first);
      gs.log.writeToLog(
          Importance::info, "Set pipe %d as non-blocking.\n", p.second);
      s.setFdStatus(p.first, descriptorType::nonBlocking);
      s.setFdStatus(p.second, descriptorType::nonBlocking);
    }
  }
}
// =======================================================================================
bool pselect6SystemCall::handleDetPre(
    globalState& gs, state& s, ptracer& t, scheduler& sched) {
  return true;
}

void pselect6SystemCall::handleDetPost(
    globalState& gs, state& s, ptracer& t, scheduler& sched) {
  return;
}
// =======================================================================================
bool pollSystemCall::handleDetPre(
    globalState& gs, state& s, ptracer& t, scheduler& sched) {
  if (!s.originalArg3 && t.arg3() != 0) s.originalArg3 = t.arg3();

  if ((int)s.originalArg3 != 0) {
    t.writeArg3(0);
    s.userDefinedTimeout = true;

    if (s.originalArg3 > 0) s.poll_retry_maximum = s.originalArg3;
  }
  return true;
}

void pollSystemCall::handleDetPost(
    globalState& gs, state& s, ptracer& t, scheduler& sched) {
  int timeout = (int)s.originalArg3;
  int retval = t.getReturnValue();
  auto rptr = traceePtr<struct pollfd>((struct pollfd*)t.arg1());
  int nfds = (int)t.arg2();

  if (retval > 0 || rptr.ptr == NULL || nfds == 0 || timeout == 0) {
    s.originalArg3 = 0;
    s.poll_retry_count = 0;
    s.poll_retry_maximum = LONG_MAX;
    return;
  }

  if (s.poll_retry_count++ < s.poll_retry_maximum) {
    bool replay = replaySyscallIfBlocked(gs, s, t, sched, 0);
    if (replay) {
      t.writeArg3(s.originalArg3);
    }
  }
  return;
}
// =======================================================================================
// for reference, here's the prlimit() prototype
// int prlimit(pid_t pid, int resource, const struct rlimit *new_limit, struct
// rlimit *old_limit);
bool prlimit64SystemCall::handleDetPre(
    globalState& gs, state& s, ptracer& t, scheduler& sched) {
  s.originalArg3 = t.arg3();
  t.writeArg3(0 /*NULL*/); // suppress attempts to set new limits

  // Check if first argument (pid) is non-zero. If so fail.
  // TODO: could also always overwrite first argument with zero
  int pid = (pid_t)t.arg1();
  if (pid != 0) {
    runtimeError(
        "prlimit64: We do not support prlimit64 on other processes.\n "
        "(pid: " +
        to_string(pid));
  }

  return true;
}

void prlimit64SystemCall::handleDetPost(
    globalState& gs, state& s, ptracer& t, scheduler& sched) {
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
  struct rlimit* rp = (struct rlimit*)t.arg4();
  if (rp != nullptr) {
    // TODO: For memory: return correct memory used, which should be
    // deterministic.
    // TODO: Allow actual max memory through, I believe this is outside our
    // deterministic gurantee.

    // struct rlimit noLimits = {};

    // noLimits.rlim_cur =
    // noLimits.rlim_max = RLIM_INFINITY;

    // gs.log.writeToLog(Importance::info, "rp=" + to_string(t.arg4()),
    // t.getPid());
    // t.writeToTracee(rp, noLimits, t.getPid());
  }

  return;
}
// =======================================================================================
bool readSystemCall::handleDetPre(
    globalState& gs, state& s, ptracer& t, scheduler& sched) {
  int fd = t.arg1();

  gs.log.writeToLog(Importance::info, "File descriptor: %d\n", t.arg1());
  gs.log.writeToLog(
      Importance::info, "non-blocking: %d\n", (int)fd_is_nonblocking(s, fd));
  gs.log.writeToLog(Importance::info, "Bytes to read %d\n", t.arg3());

  return true;
}

void readSystemCall::handleDetPost(
    globalState& gs, state& s, ptracer& t, scheduler& sched) {
  int fd = t.arg1();
  auto resetState = [&]() {
    // Restore user regs so that it appears as if only one syscall occurred
    t.setReturnRegister(s.totalBytes);
    t.writeArg2(s.beforeRetry.rsi);
    t.writeArg3(s.beforeRetry.rdx);

    // reset for next syscall that we may have to retry
    s.firstTrySystemcall = true;
    s.totalBytes = 0;
  };

  if (s.fd_is_timerfd(fd)) {
    t.writeToTracee(
        traceePtr<unsigned long>((unsigned long*)t.arg2()), 1UL, s.traceePid);
    s.totalBytes = sizeof(unsigned long);
    resetState();
    sched.preemptAndScheduleNext();
    return;
  } else if (
      s.countFdStatus(fd) != 0 &&
      s.getFdStatus(fd) == descriptorType::nonBlocking) {
    // Pipe exists in our map and it's set to non blocking.
    gs.log.writeToLog(Importance::info, "read found with non blocking pipe!\n");
    int retval = t.getReturnValue();

    // for non-blocking io, if it returns -EAGAIN on the 1st try, let it through
    // if it returns -EAGAIN after the retry logic, return bytes already
    // read/wrote
    if (retval == -EAGAIN) {
      if (s.firstTrySystemcall) {
        resetState();
        t.setReturnRegister((uint64_t)-EAGAIN);
      } else {
        auto totalBytes = s.totalBytes;
        resetState();
        t.setReturnRegister(totalBytes);
      }
      return;
    }
  } else {
    bool preemptAndTryLater = replaySyscallIfBlocked(gs, s, t, sched, EAGAIN);
    if (preemptAndTryLater) {
      gs.readRetryEvents++;
      return;
    }
  }

  ssize_t bytes_read = t.getReturnValue();
  if (bytes_read < 0) {
    gs.log.writeToLog(Importance::info, "Returned negative: %d.", bytes_read);
    return;
  }

  if (bytes_read > 0) {
    // This operation is very expensive!
    // char buffer[bytes_read];
    // readVmTracee(traceePtr<void>((void*) t.arg2()), buffer, bytes_read,
    // s.traceePid); gs.log.writeToLog(Importance::extra, "Read output: \"\n");
    // for(int i = 0; i < bytes_read; i++){
    // gs.log.writeToLog(Importance::extra, "%d", (int) buffer[i]);
    // }
    // gs.log.writeToLog(Importance::extra, "\"\n");
  }

  // Replay system call if not enought bytes were read.
  s.totalBytes += bytes_read;

  if (s.firstTrySystemcall) {
    gs.log.writeToLog(Importance::info, "First time seeing this read!\n");
    s.firstTrySystemcall = false;
    s.beforeRetry = t.getRegs();
  }

  // EOF, or read returned everything we asked for.
  if (bytes_read == 0 || // EOF
      s.totalBytes == s.beforeRetry.rdx) { // original bytes requested
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
bool readvSystemCall::handleDetPre(
    globalState& gs, state& s, ptracer& t, scheduler& sched) {
  return true;
}

void readvSystemCall::handleDetPost(
    globalState& gs, state& s, ptracer& t, scheduler& sched) {
  return;
}
// =======================================================================================
bool readlinkSystemCall::handleDetPre(
    globalState& gs, state& s, ptracer& t, scheduler& sched) {
  printInfoString(t.arg1(), gs.log, s.traceePid, t);

  return false;
}

void readlinkSystemCall::handleDetPost(
    globalState& gs, state& s, ptracer& t, scheduler& sched) {
  runtimeError("readlink post-hook should never be called.");
}
// =======================================================================================
bool readlinkatSystemCall::handleDetPre(
    globalState& gs, state& s, ptracer& t, scheduler& sched) {
  printInfoString(t.arg2(), gs.log, s.traceePid, t);

  return false;
}

void readlinkatSystemCall::handleDetPost(
    globalState& gs, state& s, ptracer& t, scheduler& sched) {
  runtimeError("readlinkat post-hook should never be called.");
}

static bool fd_is_nonblocking(state& s, int fd) {
  auto it = s.fdStatus.get()->find(fd);
  auto end = s.fdStatus.get()->end();
  if (it != end) {
    return it->second == descriptorType::nonBlocking;
  }
  return false;
}

// =======================================================================================
bool recvmsgSystemCall::handleDetPre(
    globalState& gs, state& s, ptracer& t, scheduler& sched) {
  int flags = (int)t.arg3();
  int fd = (int)t.arg1();
  bool nonblock =
      (flags & MSG_DONTWAIT) == MSG_DONTWAIT || fd_is_nonblocking(s, fd);
  gs.log.writeToLog(
      Importance::info, "recvmsg from fd " + to_string(t.arg1()) +
                            ", nonblock: " + to_string(nonblock) + "\n");
  return true;
}

void recvmsgSystemCall::handleDetPost(
    globalState& gs, state& s, ptracer& t, scheduler& sched) {
  if (!fd_is_nonblocking(s, (int)t.arg1())) {
    replaySyscallIfBlocked(gs, s, t, sched, EAGAIN);
  }
}

// =======================================================================================
bool renameSystemCall::handleDetPre(
    globalState& gs, state& s, ptracer& t, scheduler& sched) {
  printInfoString(t.arg1(), gs.log, s.traceePid, t, " old path: ");
  printInfoString(t.arg2(), gs.log, s.traceePid, t, " new path: ");
  return true;
}

void renameSystemCall::handleDetPost(
    globalState& gs, state& s, ptracer& t, scheduler& sched) {
  // nothing to do, but return value may be useful for debugging (printed by
  // handlePostSystemCall)
  return;
}
// =======================================================================================
bool renameatSystemCall::handleDetPre(
    globalState& gs, state& s, ptracer& t, scheduler& sched) {
  printInfoString(t.arg2(), gs.log, s.traceePid, t, " renaming-ing path: ");
  printInfoString(t.arg4(), gs.log, s.traceePid, t, " to path: ");
  return true;
}

void renameatSystemCall::handleDetPost(
    globalState& gs, state& s, ptracer& t, scheduler& sched) {
  // nothing to do, but return value may be useful for debugging (printed by
  // handlePostSystemCall)
}
// =======================================================================================
bool renameat2SystemCall::handleDetPre(
    globalState& gs, state& s, ptracer& t, scheduler& sched) {
  printInfoString(t.arg2(), gs.log, s.traceePid, t, " renaming-ing path: ");
  printInfoString(t.arg4(), gs.log, s.traceePid, t, " to path: ");
  return true;
}

void renameat2SystemCall::handleDetPost(
    globalState& gs, state& s, ptracer& t, scheduler& sched) {
  // nothing to do, but return value may be useful for debugging (printed by
  // handlePostSystemCall)
}
// =======================================================================================
bool rmdirSystemCall::handleDetPre(
    globalState& gs, state& s, ptracer& t, scheduler& sched) {
  printInfoString(t.arg1(), gs.log, s.traceePid, t);
  return true;
}

void rmdirSystemCall::handleDetPost(
    globalState& gs, state& s, ptracer& t, scheduler& sched) {
  // nothing to do, but return value may be useful for debugging (printed by
  // handlePostSystemCall)
}

bool rt_sigprocmaskSystemCall::handleDetPre(
    globalState& gs, state& s, ptracer& t, scheduler& sched) {
  return true;
}

void rt_sigprocmaskSystemCall::handleDetPost(
    globalState& gs, state& s, ptracer& t, scheduler& sched) {
  if (s.syscallInjected) {
    s.syscallInjected = false;
    traceePtr<unsigned long> oldset = traceePtr<unsigned long>(
        (unsigned long*)(s.mmapMemory.getAddr().ptr) + 1);
    t.writeArg1(SIG_SETMASK);
    t.writeArg2((uint64_t)oldset.ptr);
    t.writeArg3(0);
    t.writeArg4(8);
    replaySystemCall(gs, t, SYS_rt_sigprocmask);
  }
}

// =======================================================================================
// cribbed from strace, as using the standard struct sigaction does not yield
// correct output. I guess libc internally translates from the new user-facing
// struct to this older one, and passes the older one to the kernel.
// https://github.com/strace/strace/blob/v4.23/signal.c#L297
struct kernel_sigaction {
  /* sa_handler may be a libc #define, need to use another name: */
  unsigned long sa_handler__;
  unsigned long sa_flags;
  unsigned long sa_restorer;
  unsigned long sa_mask;
};
bool rt_sigactionSystemCall::handleDetPre(
    globalState& gs, state& s, ptracer& t, scheduler& sched) {
  gs.log.writeToLog(
      Importance::info,
      "rt_sigaction pre-hook for signal " + to_string(t.arg1()) + "\n");
  const uint64_t signum = t.arg1();
  s.requestedSignalToHandle = signum;

  if (0 == t.arg2()) {
    // no need to run the post-hook since tracee is not updating signal handlers
    return false;
  }

  // figure out what kind of handler the tracee is trying to install
  struct kernel_sigaction sa = t.readFromTracee(
      traceePtr<struct kernel_sigaction>((struct kernel_sigaction*)t.arg2()),
      t.getPid());
  gs.log.writeToLog(Importance::info, "struct sigaction*: %p\n", t.arg2());
  gs.log.writeToLog(
      Importance::info, "sa_flags: " + to_string(sa.sa_flags) + " " +
                            to_string(SA_RESETHAND) + " \n");
  gs.log.writeToLog(
      Importance::info,
      "sa_handler: " + to_string((uint64_t)sa.sa_handler__) + "\n");

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
  gs.log.writeToLog(
      Importance::info, "signal " + to_string(signum) + " handler requested: " +
                            to_string(s.requestedSignalHandler) + "\n");

  // run the post-hook to see if signal handler installation was successful
  return true;
}

void rt_sigactionSystemCall::handleDetPost(
    globalState& gs, state& s, ptracer& t, scheduler& sched) {
  gs.log.writeToLog(Importance::info, "rt_sigaction post-hook\n");
  if (0 == t.getReturnValue()) {
    // signal handler installation was successful
    s.currentSignalHandlers.get()->insert(
        {s.requestedSignalToHandle, s.requestedSignalHandler});

    gs.log.writeToLog(
        Importance::info,
        "signal " + to_string(s.requestedSignalToHandle) + " handler of type " +
            to_string(s.requestedSignalHandler) + " installed\n");

    s.requestedSignalHandler = SIGHANDLER_INVALID;
    s.requestedSignalToHandle = -1;
  }
  return;
}

struct PendingSignalInfo {
  unsigned long pending;
  unsigned long blocked;
};

int getPendingSignalInfo(pid_t pid, struct PendingSignalInfo* info) {
  char fname[32];
  char buff[4096];
  snprintf(fname, 32, "/proc/%u/status", pid);
  int fd = open(fname, O_RDONLY | O_CLOEXEC);
  if (fd < 0) {
    return -1;
  }

  ssize_t n = read(fd, buff, 4096);
  if (n <= 0) {
    return -1;
  }

  char *p = NULL, *q = buff;

  while (1) {
    p = strsep(&q, "\n");
    if (!p) break;
    if (strncmp(p, "SigPnd:\t", 8) == 0) {
      info->pending = strtoul(8 + p, NULL, 16);
    } else if (strncmp(p, "SigBlk:\t", 8) == 0) {
      info->blocked = strtoul(8 + p, NULL, 16);
      break;
    }
  }
  close(fd);
  return 0;
}

// =======================================================================================
// TODO
bool rt_sigtimedwaitSystemCall::handleDetPre(
    globalState& gs, state& s, ptracer& t, scheduler& sched) {
  struct timespec ourTimeout = {0};
  if (t.arg3() != 0) {
    s.userDefinedTimeout = true;
    s.originalArg3 = t.arg3();
  }

  struct timespec* timeoutPtr = (struct timespec*)t.arg3();
  s.originalArg3 = (uint64_t)timeoutPtr;

  if (timeoutPtr == nullptr) {
    // Has to be created in memory.
    struct timespec* newAddr = (struct timespec*)s.mmapMemory.getAddr().ptr;
    t.writeToTracee(
        traceePtr<struct timespec>(newAddr), ourTimeout, s.traceePid);

    t.writeArg3((uint64_t)newAddr);
  } else {
    // Already exists in memory.
    // jld: useless read from tracee memory
    // timeval timeout = t.readFromTracee(traceePtr<timeval>(timeoutPtr),
    // t.getPid());
    t.writeToTracee(
        traceePtr<struct timespec>(timeoutPtr), ourTimeout, s.traceePid);
    s.userDefinedTimeout = true;
  }

  return true;
}

void rt_sigtimedwaitSystemCall::handleDetPost(
    globalState& gs, state& s, ptracer& t, scheduler& sched) {
  int retval = t.getReturnValue();
  bool replay;

  replay = replaySyscallIfBlocked(gs, s, t, sched, EAGAIN);
  if (replay) {
    gs.log.writeToLog(Importance::info, "replay rt_sigtimedwait\n");
    t.writeArg3(s.originalArg3);
  } else {
    gs.log.writeToLog(
        Importance::info,
        "rt_sigtimedwait returned: " + to_string(retval) + "\n");
    if (s.syscallInjected) {
      if (retval > 0) {
        kill(t.getPid(), retval);
        t.setReturnRegister((uint64_t)-EINTR);
      }
    }
  }

  return;
}

// =======================================================================================
// TODO
bool rt_sigsuspendSystemCall::handleDetPre(
    globalState& gs, state& s, ptracer& t, scheduler& sched) {
  unsigned long mask;

  traceePtr<unsigned long> rptr =
      traceePtr<unsigned long>((unsigned long*)t.arg1());
  mask = t.readFromTracee(rptr, t.getPid());
  gs.log.writeToLog(Importance::info, "rt_sigsuspend, mask = 0x%lx\n", mask);

  struct PendingSignalInfo info = {
      0,
  };

  // rt_sigsuspend would block until signal is received
  // we'll change it to something else nonblocking.
  cancelSystemCall(gs, s, t);

  getPendingSignalInfo(t.getPid(), &info);
  unsigned long unmask = info.pending & ~mask;
  if (unmask != 0) {
    s.syscallInjected = true;
    s.originalArg1 = t.arg1();
    traceePtr<unsigned long> set =
        traceePtr<unsigned long>((unsigned long*)(s.mmapMemory.getAddr().ptr));
    traceePtr<unsigned long> oldset = traceePtr<unsigned long>(
        (unsigned long*)(s.mmapMemory.getAddr().ptr) + 1);
    t.writeToTracee(set, unmask, t.getPid());
    t.writeArg1(SIG_UNBLOCK);
    t.writeArg2((uint64_t)set.ptr);
    t.writeArg3((uint64_t)oldset.ptr);
    t.writeArg4(8);

    replaySystemCall(gs, t, SYS_rt_sigprocmask);
  } else {
    sched.preemptAndScheduleNext();
    replaySystemCall(gs, t, SYS_rt_sigsuspend);
  }
  return false;
}

void rt_sigsuspendSystemCall::handleDetPost(
    globalState& gs, state& s, ptracer& t, scheduler& sched) {
  runtimeError("rt_sigsuspend is not supposed to return\n");
}

bool rt_sigpendingSystemCall::handleDetPre(
    globalState& gs, state& s, ptracer& t, scheduler& sched) {
  return true;
}
void rt_sigpendingSystemCall::handleDetPost(
    globalState& gs, state& s, ptracer& t, scheduler& sched) {}

// =======================================================================================
// TODO
bool sendtoSystemCall::handleDetPre(
    globalState& gs, state& s, ptracer& t, scheduler& sched) {
  return true;
}

void sendtoSystemCall::handleDetPost(
    globalState& gs, state& s, ptracer& t, scheduler& sched) {
  return;
}
// =======================================================================================
// TODO
bool sendmsgSystemCall::handleDetPre(
    globalState& gs, state& s, ptracer& t, scheduler& sched) {
  gs.log.writeToLog(
      Importance::info, "sendmsg to fd " + to_string(t.arg1()) + "\n");
  return true;
}

void sendmsgSystemCall::handleDetPost(
    globalState& gs, state& s, ptracer& t, scheduler& sched) {
  return;
}

bool sendmmsgSystemCall::handleDetPre(
    globalState& gs, state& s, ptracer& t, scheduler& sched) {
  gs.log.writeToLog(
      Importance::info, "sendmmsg to fd " + to_string(t.arg1()) + "\n");
  return true;
}

void sendmmsgSystemCall::handleDetPost(
    globalState& gs, state& s, ptracer& t, scheduler& sched) {
  return;
}

bool recvfromSystemCall::handleDetPre(
    globalState& gs, state& s, ptracer& t, scheduler& sched) {
  gs.log.writeToLog(
      Importance::info, "recvfrom fd " + to_string(t.arg1()) + "\n");
  return true;
}

void recvfromSystemCall::handleDetPost(
    globalState& gs, state& s, ptracer& t, scheduler& sched) {
  return;
}

// =======================================================================================
bool selectSystemCall::handleDetPre(
    globalState& gs, state& s, ptracer& t, scheduler& sched) {
  // Get the original set structs.
  // Set them in the state class.
  if ((void*)t.arg2() != NULL) {
    s.rdfsNotNull = true;
    s.origRdfs =
        t.readFromTracee(traceePtr<fd_set>((fd_set*)t.arg2()), t.getPid());
  }
  if ((void*)t.arg3() != NULL) {
    s.wrfsNotNull = true;
    s.origWrfs =
        t.readFromTracee(traceePtr<fd_set>((fd_set*)t.arg3()), t.getPid());
  }
  if ((void*)t.arg4() != NULL) {
    s.exfsNotNull = true;
    s.origExfs =
        t.readFromTracee(traceePtr<fd_set>((fd_set*)t.arg4()), t.getPid());
  }

  // Set the timeout to zero.
  timeval* timeoutPtr = (timeval*)t.arg5();
  s.originalArg5 = (uint64_t)timeoutPtr;
  timeval ourTimeout = {0};
  ourTimeout.tv_sec = 0;

  if (timeoutPtr == nullptr) {
    // Has to be created in memory.
    timeval* newAddr = (timeval*)s.mmapMemory.getAddr().ptr;
    t.writeToTracee(traceePtr<timeval>(newAddr), ourTimeout, s.traceePid);

    t.writeArg5((uint64_t)newAddr);
  } else {
    // Already exists in memory.
    // jld: useless read from tracee memory
    // timeval timeout = t.readFromTracee(traceePtr<timeval>(timeoutPtr),
    // t.getPid());
    t.writeToTracee(traceePtr<timeval>(timeoutPtr), ourTimeout, s.traceePid);
    s.userDefinedTimeout = true;
  }

  return true;
}

void selectSystemCall::handleDetPost(
    globalState& gs, state& s, ptracer& t, scheduler& sched) {
  if (s.userDefinedTimeout) {
    s.userDefinedTimeout = false;
    if (t.getReturnValue() == 0) {
      // Mark this is blocked because we don't want it to keep being picked to
      // run off the runnableHeap. It will eventually get to run when the heaps
      // switch.
      sched.preemptAndScheduleNext();
    }
  } else {
    bool replayed = replaySyscallIfBlocked(gs, s, t, sched, 0);

    if (replayed) {
      if (s.rdfsNotNull) {
        t.writeToTracee(
            traceePtr<fd_set>((fd_set*)t.arg2()), s.origRdfs, t.getPid());
      }
      if (s.wrfsNotNull) {
        t.writeToTracee(
            traceePtr<fd_set>((fd_set*)t.arg3()), s.origWrfs, t.getPid());
      }
      if (s.exfsNotNull) {
        t.writeToTracee(
            traceePtr<fd_set>((fd_set*)t.arg4()), s.origExfs, t.getPid());
      }
      s.rdfsNotNull = false;
      s.wrfsNotNull = false;
      s.exfsNotNull = false;
      t.writeArg5((uint64_t)s.originalArg5);
    }
  }
  return;
}
// =======================================================================================
// TODO

bool set_robust_listSystemCall::handleDetPre(
    globalState& gs, state& s, ptracer& t, scheduler& sched) {
  return true;
}
void set_robust_listSystemCall::handleDetPost(
    globalState& gs, state& s, ptracer& t, scheduler& sched) {
  return;
}

// =======================================================================================
bool statSystemCall::handleDetPre(
    globalState& gs, state& s, ptracer& t, scheduler& sched) {
  printInfoString(t.arg1(), gs.log, s.traceePid, t);

  return true;
}

void statSystemCall::handleDetPost(
    globalState& gs, state& s, ptracer& t, scheduler& sched) {
  handleStatFamily(gs, s, t, "stat");
  return;
}
// =======================================================================================
bool statfsSystemCall::handleDetPre(
    globalState& gs, state& s, ptracer& t, scheduler& sched) {
  return true;
}

void statfsSystemCall::handleDetPost(
    globalState& gs, state& s, ptracer& t, scheduler& sched) {
  struct statfs* statfsPtr = (struct statfs*)t.arg2();
  if (statfsPtr == nullptr) {
    gs.log.writeToLog(Importance::info, "statfs: statbuf null.\n");
    return;
  }

  if (t.getReturnValue() == 0) {
    interceptStatfs(traceePtr<struct statfs>(statfsPtr), t);
  }

  return;
}
// =======================================================================================
bool sysinfoSystemCall::handleDetPre(
    globalState& gs, state& s, ptracer& t, scheduler& sched) {
  return true;
}

void sysinfoSystemCall::handleDetPost(
    globalState& gs, state& s, ptracer& t, scheduler& sched) {
  struct sysinfo* infoPtr = (struct sysinfo*)t.arg1();
  if (infoPtr == nullptr) {
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
bool symlinkSystemCall::handleDetPre(
    globalState& gs, state& s, ptracer& t, scheduler& sched) {
  printInfoString(t.arg1(), gs.log, s.traceePid, t, " target: ");
  printInfoString(t.arg2(), gs.log, s.traceePid, t, " linkpath: ");
  return true;
}

void symlinkSystemCall::handleDetPost(
    globalState& gs, state& s, ptracer& t, scheduler& sched) {
  if (t.getReturnValue() == 0 && (char*)t.arg2() != nullptr) {
    string linkpath =
        t.readTraceeCString(traceePtr<char>((char*)t.arg2()), s.traceePid);
    auto inode = inode_from_tracee(linkpath, s.traceePid, gs.log, -1);
    if (inode != -1UL) {
      gs.mtimeMap[inode] = s.getLogicalTime();
      gs.inodeMap.addRealValue(inode);
      s.incrementTime();
    }
  }
}
// =======================================================================================
bool symlinkatSystemCall::handleDetPre(
    globalState& gs, state& s, ptracer& t, scheduler& sched) {
  printInfoString(t.arg1(), gs.log, s.traceePid, t, " target: ");
  // TODO Add newdirfd
  printInfoString(t.arg3(), gs.log, s.traceePid, t, " linkpath: ");
  return true;
}

void symlinkatSystemCall::handleDetPost(
    globalState& gs, state& s, ptracer& t, scheduler& sched) {
  if (t.getReturnValue() == 0 && (char*)t.arg3() != nullptr) {
    string linkpath =
        t.readTraceeCString(traceePtr<char>((char*)t.arg3()), s.traceePid);
    auto inode = inode_from_tracee(linkpath, s.traceePid, gs.log, t.arg2());
    if (inode != -1UL) {
      gs.mtimeMap[inode] = s.getLogicalTime();
      gs.inodeMap.addRealValue(inode);
      s.incrementTime();
    }
  }
}
// =======================================================================================
bool mknodSystemCall::handleDetPre(
    globalState& gs, state& s, ptracer& t, scheduler& sched) {
  printInfoString(t.arg1(), gs.log, s.traceePid, t);
  return true;
}

void mknodSystemCall::handleDetPost(
    globalState& gs, state& s, ptracer& t, scheduler& sched) {
  if (t.getReturnValue() == 0 && (char*)t.arg1() != nullptr) {
    string path =
        t.readTraceeCString(traceePtr<char>((char*)t.arg1()), s.traceePid);
    auto inode = inode_from_tracee(path, s.traceePid, gs.log, -1);
    if (inode != -1UL) {
      gs.mtimeMap[inode] = s.getLogicalTime();
      gs.inodeMap.addRealValue(inode);
      s.incrementTime();
    }
  }
}
// =======================================================================================
bool mknodatSystemCall::handleDetPre(
    globalState& gs, state& s, ptracer& t, scheduler& sched) {
  printInfoString(t.arg2(), gs.log, s.traceePid, t);
  return true;
}

void mknodatSystemCall::handleDetPost(
    globalState& gs, state& s, ptracer& t, scheduler& sched) {
  if (t.getReturnValue() == 0 && (char*)t.arg2() != nullptr) {
    string path =
        t.readTraceeCString(traceePtr<char>((char*)t.arg2()), s.traceePid);
    auto inode = inode_from_tracee(path, s.traceePid, gs.log, t.arg1());
    if (inode != -1UL) {
      gs.mtimeMap[inode] = s.getLogicalTime();
      gs.inodeMap.addRealValue(inode);
      s.incrementTime();
    }
  }
}
// =======================================================================================
bool tgkillSystemCall::handleDetPre(
    globalState& gs, state& s, ptracer& t, scheduler& sched) {
  int tgid = (int)t.arg1();
  int tid = (int)t.arg2();
  int signal = (int)t.arg3();
  gs.log.writeToLog(
      Importance::info, "tgkill(tgid = %d, tid = %d, signal = %d)\n", tgid, tid,
      signal);

  if (signal == SIGABRT && tgid == s.traceePid &&
      tgid == tid /* TODO: when we support threads, we should also compare against tracee's tid (from gettid) */) {
    // ok
  } else {
    gs.log.writeToLog(
        Importance::info,
        "tgkillSystemCall::handleDetPre: tracee vtgid=" + to_string(tgid) +
            " vtid=" + to_string(tid) + " ptgid=" + to_string(s.traceePid) +
            " trying to send unsupported signal=" + to_string(signal));
    // runtimeError("tgkillSystemCall::handleDetPre: tracee trying to send
    // unsupported signal");
  }

  return true;
}

void tgkillSystemCall::handleDetPost(
    globalState& gs, state& s, ptracer& t, scheduler& sched) {
  return;
}
// =======================================================================================
bool timeSystemCall::handleDetPre(
    globalState& gs, state& s, ptracer& t, scheduler& sched) {
  return true;
}

void timeSystemCall::handleDetPost(
    globalState& gs, state& s, ptracer& t, scheduler& sched) {
  if (s.noopSystemCall) {
    gs.log.writeToLog(
        Importance::info,
        "NOOP system call (getpid) setting return value to 0\n");
    s.noopSystemCall = false;
    t.setReturnRegister(
        0); // pretend like the system call (that we replaced) has succeeded
  }
  // This should be rare this is a vdso system call. It is unlikely someone will
  // call it directly.
  else {
    gs.timeCalls++;
    int retVal = t.getReturnValue();
    if (retVal < 0) {
      gs.log.writeToLog(
          Importance::info, "Time call failed: \n" + string{strerror(-retVal)});
      return;
    }

    time_t* timePtr = (time_t*)t.arg1();
    time_t secs_since_epoch = logical_clock::to_time_t(s.getLogicalTime());
    gs.log.writeToLog(
        Importance::info, "time: tloc is null, returning %d\n",
        secs_since_epoch);
    t.writeRax(secs_since_epoch);
    if (timePtr != nullptr) {
      t.writeToTracee(
          traceePtr<time_t>(timePtr), secs_since_epoch, s.traceePid);
    }
    // Tick up time.
    s.incrementTime();
    // preempt current task avoid some task busy checking current time
    // Since preemption can happen any place in Linux, we are not really
    // breaking any assumptions..
    sched.preemptAndScheduleNext();
  }
  return;
}
// =======================================================================================
bool timer_createSystemCall::handleDetPre(
    globalState& gs, state& s, ptracer& t, scheduler& sched) {
  gs.log.writeToLog(Importance::info, "timer_create syscall pre-hook\n");

  // we support any clockid, but only notification via certain signals
  // delivered to the process
  class timerInfo ti;

  traceePtr<struct sigevent> sep((struct sigevent*)t.arg2());
  if (nullptr == sep.ptr) {
    ti.sendSignal = true;
    ti.signum = SIGALRM;
    ti.signalHandlerData = nullptr;

  } else { // non-default settings, have to read tracee's struct sigevent

    struct sigevent se = t.readFromTracee(sep, t.getPid());

    switch (se.sigev_notify) {
    case SIGEV_NONE: // don't send a signal, alarm value will be read via
                     // timer_gettime()
    case SIGEV_SIGNAL: // send a signal upon timer expiration
      break;
    case SIGEV_THREAD:
      runtimeError(
          "unsupported launching a thread on timer expiration in "
          "timer_create()");
      break;
    case SIGEV_THREAD_ID:
      runtimeError(
          "unsupported sending a signal to a specific thread in "
          "timer_create()");
      break;
    default:
      runtimeError(
          "unsupported sigev_notify value in timer_create() " +
          to_string(se.sigev_notify));
      break;
    }

    // NB: we allow any signal in se.sigev_signo, since there's no harm in
    // creating a timer that's never used. We only support certain signals being
    // delivered, however, and we catch that error later in timer_settime().

    ti.sendSignal = (SIGEV_SIGNAL == se.sigev_notify);
    ti.signum = ti.sendSignal ? se.sigev_signo : -1;
    // TODO: JLD: we aren't seting siginfo_t fields si_code and si_value
    // appropriately
    ti.signalHandlerData = ti.sendSignal ? se.sigev_value.sival_ptr : nullptr;
  }

  timerID_t timerid = s.timerCreateTimers.get()->size() + 11000;
  s.timerCreateTimers.get()->insert({timerid, ti});

  gs.log.writeToLog(
      Importance::info, "created new timer " + to_string(timerid) + "\n");

  // write timerid into tracee memory
  gs.log.writeToLog(Importance::info, "writing timerid to %p\n", t.arg3());
  t.writeToTracee(
      traceePtr<uint64_t>((uint64_t*)t.arg3()), timerid, s.traceePid);

  // convert timer_create() into nop
  replaceSystemCallWithNoop(gs, s, t);
  // in getpid post-hook we set return value to 0 so tracee thinks timer_create
  // has succeeded

  // run the post-hook, which will be the getpid cleanup
  return true;
}

void timer_createSystemCall::handleDetPost(
    globalState& gs, state& s, ptracer& t, scheduler& sched) {
  runtimeError("timer_create post-hook should never be called.");
}
// =======================================================================================
bool timer_deleteSystemCall::handleDetPre(
    globalState& gs, state& s, ptracer& t, scheduler& sched) {
  timerID_t timerid = t.arg1();
  gs.log.writeToLog(
      Importance::info,
      "timer_delete pre-hook for timer " + to_string(timerid) + "\n");

  if (!s.timerCreateTimers.get()->count(timerid)) {
    runtimeError("invalid timerid " + to_string(timerid));
  }
  return true;
}

void timer_deleteSystemCall::handleDetPost(
    globalState& gs, state& s, ptracer& t, scheduler& sched) {
  t.setReturnRegister(0);
}
// =======================================================================================
bool timer_getoverrunSystemCall::handleDetPre(
    globalState& gs, state& s, ptracer& t, scheduler& sched) {
  timerID_t timerid = t.arg1();
  gs.log.writeToLog(
      Importance::info,
      "timer_getoverrun pre-hook for timer " + to_string(timerid) + "\n");
  if (!s.timerCreateTimers.get()->count(timerid)) {
    runtimeError("invalid timerid " + to_string(timerid));
  }
  return true;
}

void timer_getoverrunSystemCall::handleDetPost(
    globalState& gs, state& s, ptracer& t, scheduler& sched) {
  t.setReturnRegister(0);
}

// =======================================================================================
bool timer_gettimeSystemCall::handleDetPre(
    globalState& gs, state& s, ptracer& t, scheduler& sched) {
  timerID_t timerid = t.arg1();
  gs.log.writeToLog(
      Importance::info,
      "timer_gettime pre-hook for timer " + to_string(timerid) + "\n");

  if (!s.timerCreateTimers.get()->count(timerid)) {
    runtimeError("invalid timerid " + to_string(timerid));
  }

  struct itimerspec* isp = (struct itimerspec*)t.arg2();
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

void timer_gettimeSystemCall::handleDetPost(
    globalState& gs, state& s, ptracer& t, scheduler& sched) {
  t.setReturnRegister(0);
}
// =======================================================================================
bool timer_settimeSystemCall::handleDetPre(
    globalState& gs, state& s, ptracer& t, scheduler& sched) {
  gs.log.writeToLog(
      Importance::info,
      "timer_settime pre-hook for timer " + to_string(t.arg1()) + "\n");

  timerID_t timerid = t.arg1();

  if (!s.timerCreateTimers.get()->count(timerid)) {
    runtimeError("invalid timerid " + to_string(timerid));
  }

  timerInfo tinfo = s.timerCreateTimers.get()->at(timerid);
  if (!tinfo.sendSignal) {
    replaceSystemCallWithNoop(gs, s, t);
    return true; // run getpid post-hook
  } else {
    // run post-hook if necessary
    return sendTraceeSignalNow(tinfo.signum, gs, s, t, sched);
  }

  return true;
}

void timer_settimeSystemCall::handleDetPost(
    globalState& gs, state& s, ptracer& t, scheduler& sched) {}
// =======================================================================================
bool getitimerSystemCall::handleDetPre(
    globalState& gs, state& s, ptracer& t, scheduler& sched) {
  gs.log.writeToLog(Importance::info, "getitimer pre-hook\n");

  struct itimerval* ivp = (struct itimerval*)t.arg2();
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

void getitimerSystemCall::handleDetPost(
    globalState& gs, state& s, ptracer& t, scheduler& sched) {
  t.setReturnRegister(0);
}
// =======================================================================================
bool setitimerSystemCall::handleDetPre(
    globalState& gs, state& s, ptracer& t, scheduler& sched) {
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
    runtimeError("invalid timer for setitimer " + to_string(whichTimer));
  }

  return true;
}

void setitimerSystemCall::handleDetPost(
    globalState& gs, state& s, ptracer& t, scheduler& sched) {}

bool timerfd_createSystemCall::handleDetPre(
    globalState& gs, state& s, ptracer& t, scheduler& sched) {
  gs.log.writeToLog(Importance::info, "timerfd_create syscall pre-hook\n");

  int flags = t.arg2();
  s.originalArg2 = (unsigned long)flags;

  // make sure read does not block
  t.writeArg2(flags | TFD_NONBLOCK);

  return true;
}

void timerfd_createSystemCall::handleDetPost(
    globalState& gs, state& s, ptracer& t, scheduler& sched) {
  int fd = t.getReturnValue();
  int clockid = t.arg1();
  int flags = t.arg2();

  t.writeArg2(s.originalArg2);

  if (fd >= 0) {
    struct itimerspec it = {
        {0, 0},
        {0, 0},
    };
    s.timerfds->insert({fd, it});
    gs.log.writeToLog(
        Importance::info, "timerfd_create(%d, %d) = %d\n", clockid, flags, fd);
  }
}

bool timerfd_settimeSystemCall::handleDetPre(
    globalState& gs, state& s, ptracer& t, scheduler& sched) {
  int fd = t.arg1();
  struct itimerspec* spec = (itimerspec*)s.mmapMemory.getAddr().ptr;
  auto value = t.readFromTracee(
      traceePtr<struct itimerspec>((struct itimerspec*)t.arg3()), s.traceePid);
  (*s.timerfds)[fd] = value;
  struct itimerspec timer = {
      {0, 0},
      {0, 0},
  };
  if (value.it_interval.tv_sec != 0 || value.it_interval.tv_nsec != 0) {
    timer.it_interval.tv_sec = LONG_MAX;
    timer.it_interval.tv_nsec = 0;
  }
  if (value.it_value.tv_sec != 0 || value.it_value.tv_nsec != 0) {
    timer.it_value.tv_sec = LONG_MAX;
    timer.it_value.tv_nsec = 0;
  }

  t.writeToTracee(traceePtr<itimerspec>(spec), timer, s.traceePid);
  s.originalArg3 = t.arg3();
  t.writeArg3((unsigned long)spec);

  return true;
}

void timerfd_settimeSystemCall::handleDetPost(
    globalState& gs, state& s, ptracer& t, scheduler& sched) {
  int fd = t.arg1();
  int retval = t.getReturnValue();
  gs.log.writeToLog(Importance::info, "timerfd_setttime returned %d\n", retval);
  t.writeArg3(s.originalArg3);

  // restore old_value.
  if (retval == 0 && t.arg4() != 0) {
    auto it = s.timerfds->find(fd);
    if (it != s.timerfds->end()) {
      t.writeToTracee(
          traceePtr<struct itimerspec>((struct itimerspec*)t.arg4()),
          it->second, s.traceePid);
    }
  }
}

bool timerfd_gettimeSystemCall::handleDetPre(
    globalState& gs, state& s, ptracer& t, scheduler& sched) {
  return true;
}

void timerfd_gettimeSystemCall::handleDetPost(
    globalState& gs, state& s, ptracer& t, scheduler& sched) {
  int fd = t.arg1();
  int retval = t.getReturnValue();
  if (retval == 0 && t.arg2() != 0) {
    auto rptr = traceePtr<struct itimerspec>((struct itimerspec*)t.arg2());
    auto it = s.timerfds->find(fd);
    if (it != s.timerfds->end()) {
      auto timer = it->second;
      if (timer.it_value.tv_sec != 0 || timer.it_value.tv_nsec != 0) {
        // timer is active.
        // cannot be 0 otherwise timer is disarmed.
        timer.it_value.tv_sec = 0;
        timer.it_value.tv_nsec = 1;
      }
      t.writeToTracee(rptr, timer, s.traceePid);
    }
  }
}

// =======================================================================================
bool timesSystemCall::handleDetPre(
    globalState& gs, state& s, ptracer& t, scheduler& sched) {
  return true;
}
void timesSystemCall::handleDetPost(
    globalState& gs, state& s, ptracer& t, scheduler& sched) {
  // Failure nothing for us to do.
  if ((clock_t)t.getReturnValue() == -1) {
    return;
  }

  tms* bufPtr = (tms*)t.arg1();
  if (bufPtr != nullptr) {
    tms myTms = {
        .tms_utime = 0,
        .tms_stime = 0,
        .tms_cutime = 0,
        .tms_cstime = 0,
    };

    t.writeToTracee(traceePtr<tms>(bufPtr), myTms, s.traceePid);
  }

  t.setReturnRegister(s.getLogicalTime().time_since_epoch().count());
  s.incrementTime();
}
// =======================================================================================
bool unameSystemCall::handleDetPre(
    globalState& gs, state& s, ptracer& t, scheduler& sched) {
  return true;
}
void unameSystemCall::handleDetPost(
    globalState& gs, state& s, ptracer& t, scheduler& sched) {
  // Populate the utsname struct with our own generic data.
  struct utsname* utsnamePtr = (struct utsname*)t.arg1();

  // example struct utsname from acggrid28
  // uname({sysname="Linux", nodename="acggrid28", release="4.4.114-42-default",
  // version="#1 SMP Tue Feb 6 10:58:10 UTC 2018 (b6ee9ae)", machine="x86_64",
  // domainname="(none)"}
  if (utsnamePtr != nullptr) {
    struct utsname myUts = {}; // initializes to all zeroes

    // compiler-time check to ensure that each member is large enough
    // magic due to
    // https://stackoverflow.com/questions/3553296/c-sizeof-single-struct-member
    const uint32_t MEMBER_LENGTH = 60;
    if (sizeof(((struct utsname*)0)->sysname) < MEMBER_LENGTH ||
        sizeof(((struct utsname*)0)->release) < MEMBER_LENGTH ||
        sizeof(((struct utsname*)0)->version) < MEMBER_LENGTH ||
        sizeof(((struct utsname*)0)->machine) < MEMBER_LENGTH) {
      runtimeError(
          "unameSystemCall::handleDetPost: struct utsname members too small!");
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
bool unlinkSystemCall::handleDetPre(
    globalState& gs, state& s, ptracer& t, scheduler& sched) {
  printInfoString(t.arg1(), gs.log, s.traceePid, t);
  return true;
}

void unlinkSystemCall::handleDetPost(
    globalState& gs, state& s, ptracer& t, scheduler& sched) {
  // nothing to do, but return value may be useful for debugging (printed by
  // handlePostSystemCall)
  return;
}
// =======================================================================================
bool unlinkatSystemCall::handleDetPre(
    globalState& gs, state& s, ptracer& t, scheduler& sched) {
  printInfoString(t.arg2(), gs.log, s.traceePid, t);
  return true;
}

void unlinkatSystemCall::handleDetPost(
    globalState& gs, state& s, ptracer& t, scheduler& sched) {
  // nothing to do, but return value may be useful for debugging (printed by
  // handlePostSystemCall)
  return;
}

// =======================================================================================
bool utimeSystemCall::handleDetPre(
    globalState& gs, state& s, ptracer& t, scheduler& sched) {
  gs.timeCalls++;
  // Set times to our own logical time for deterministic time only if times is
  // null.
  if ((const struct utimbuf*)t.arg2() != nullptr) {
    // user specified his/her own time which should be deterministic.
    return false;
  }
  s.originalArg2 = t.arg2();

  // Enough space for 2 timespec structs.
  utimbuf* ourUtimbuf = (utimbuf*)s.mmapMemory.getAddr().ptr;

  // Create our own struct with our time.
  // TODO: In the future we might want to unify this with our mtimeMapper.
  const auto epoch = logical_clock::to_time_t(gs.epoch);
  utimbuf clockTime = {
      .actime = epoch,
      .modtime = epoch,
  };

  // Write our struct to the tracee's memory.
  t.writeToTracee(traceePtr<utimbuf>(ourUtimbuf), clockTime, s.traceePid);

  // Point system call to new address.
  t.writeArg2((uint64_t)ourUtimbuf);
  s.incrementTime();

  // Needed to restore the original value in register.
  return true;
}

void utimeSystemCall::handleDetPost(
    globalState& gs, state& s, ptracer& t, scheduler& sched) {
  // Restore value of register.
  t.writeArg2(s.originalArg2);
}
// =======================================================================================
bool utimesSystemCall::handleDetPre(
    globalState& gs, state& s, ptracer& t, scheduler& sched) {
  gs.timeCalls++;
  // Set times to our own logical time for deterministic time only if times is
  // null.
  if ((const struct timeval*)t.arg2() != nullptr) {
    // user specified his/her own time which should be deterministic.
    return false;
  }

  // We need somewhere to store a timespec struct if our struct is null. We will
  // write this data below the current stack pointer accounting for the red
  // zone, known to be 128 bytes.
  s.originalArg2 = t.arg2();
  // Enough space for 2 timeval structs.
  timeval* ourTimeval = (timeval*)s.mmapMemory.getAddr().ptr;

  // Create our own struct with our time.
  // TODO: In the future we might want to unify this with our mtimeMapper.
  const auto clockTime = logical_clock::to_timeval(gs.epoch);

  // Write our struct to the tracee's memory.
  t.writeToTracee(traceePtr<timeval>(&(ourTimeval[0])), clockTime, s.traceePid);
  t.writeToTracee(traceePtr<timeval>(&(ourTimeval[1])), clockTime, s.traceePid);

  // Point system call to new address.
  t.writeArg2((uint64_t)ourTimeval);
  s.incrementTime();

  // Needed to restore the original value in register.
  return true;
}

void utimesSystemCall::handleDetPost(
    globalState& gs, state& s, ptracer& t, scheduler& sched) {
  // Restore value of register.
  t.writeArg2(s.originalArg2);
}
// =======================================================================================
bool utimensatSystemCall::handleDetPre(
    globalState& gs, state& s, ptracer& t, scheduler& sched) {
  // Set times to our own logical time for deterministic time only if times is
  // null.
  const struct timespec* origTimespec = (const struct timespec*)t.arg3();
  if (origTimespec != nullptr) {
    // user specified his/her own time which should be deterministic.
    if (gs.log.getDebugLevel() > 0) {
      // log tracee-specified struct timespec for validation
      struct timespec times[2];
      readVmTraceeRaw(
          traceePtr<struct timespec>((struct timespec*)origTimespec), times,
          sizeof(times), s.traceePid);
      gs.log.writeToLog(
          Importance::info,
          "atime.tv_sec:%lu atime.tv_nsec:%ld mtime.tv_sec:%lu "
          "mtime.tv_nsec:%ld \n",
          times[0].tv_sec, times[0].tv_nsec, times[1].tv_sec, times[1].tv_nsec);
    }
    return false;
  }

  // We need somewhere to store a timespec struct if our struct is null. We will
  // write this data below the current stack pointer accounting for the red
  // zone, known to be 128 bytes.
  s.originalArg3 = t.arg3();
  // Enough space for 2 timespec structs.
  struct timespec* ourTimespec = (struct timespec*)s.mmapMemory.getAddr().ptr;

  // Create our own struct with our time.
  // TODO: In the future we might want to unify this with our mtimeMapper.
  const auto clockTime = logical_clock::to_timespec(gs.epoch);

  // Write our struct to the tracee's memory.
  t.writeToTracee(
      traceePtr<struct timespec>(&(ourTimespec[0])), clockTime, s.traceePid);
  t.writeToTracee(
      traceePtr<struct timespec>(&(ourTimespec[1])), clockTime, s.traceePid);

  // Point system call to new address.
  t.writeArg3((uint64_t)ourTimespec);
  s.incrementTime();

  // Needed to restore the original value in register.
  return true;
}

void utimensatSystemCall::handleDetPost(
    globalState& gs, state& s, ptracer& t, scheduler& sched) {
  // Restore value of register.
  t.writeArg3(s.originalArg3);
}
// =======================================================================================
bool futimesatSystemCall::handleDetPre(
    globalState& gs, state& s, ptracer& t, scheduler& sched) {
  // NB: this mapping to utimensat is fragile, and assumes struct timeval has
  // the same layout as struct timespec. I try to codify it as a compile-time
  // check here.
  static_assert(
      sizeof(struct timeval) == sizeof(struct timespec),
      "translating futimesat into utimensat is unsafe");
  s.originalArg4 = t.arg4();
  t.writeArg4(0);
  t.changeSystemCall(SYS_utimensat);
  return true;
}

void futimesatSystemCall::handleDetPost(
    globalState& gs, state& s, ptracer& t, scheduler& sched) {
  // Restore value of register.
  t.writeArg4(s.originalArg4);
}
// =======================================================================================
bool writeSystemCall::handleDetPre(
    globalState& gs, state& s, ptracer& t, scheduler& sched) {
  gs.log.writeToLog(Importance::info, "File descriptor: %d\n", t.arg1());
  gs.log.writeToLog(Importance::info, "Bytes to write %d\n", t.arg3());

  return true;
}

void writeSystemCall::handleDetPost(
    globalState& gs, state& s, ptracer& t, scheduler& sched) {
  int fd = t.arg1();
  bool preemptAndTryLater = false;

  auto resetState = [&]() {
    // Nothing left to write.
    gs.log.writeToLog(Importance::info, "All bytes written.\n");
    t.setReturnRegister(s.totalBytes);

    t.writeArg2(s.beforeRetry.rsi);
    t.writeArg3(s.beforeRetry.rdx);

    s.firstTrySystemcall = true;
    s.totalBytes = 0;
  };

  // Pipe exists in our map and it's set to non blocking.
  if (s.countFdStatus(fd) != 0 &&
      s.getFdStatus(fd) == descriptorType::nonBlocking) {
    gs.log.writeToLog(
        Importance::info, "write found with non-blocking pipe!\n");
    int retval = t.getReturnValue();
    // for non-blocking io, if it returns -EAGAIN on the 1st try, let it through
    // if it returns -EAGAIN after the retry logic, return bytes already
    // read/wrote
    if (retval == -EAGAIN) {
      if (s.firstTrySystemcall) {
        resetState();
        t.setReturnRegister((uint64_t)-EAGAIN);
      } else {
        auto totalBytes = s.totalBytes;
        resetState();
        t.setReturnRegister(totalBytes);
      }
      return;
    }
  } else {
    preemptAndTryLater = replaySyscallIfBlocked(gs, s, t, sched, EAGAIN);
    // We have not read all bytes, but pipe has nothing, set ourselves as
    // blocked and we will retry later.
    if (preemptAndTryLater) {
      gs.writeRetryEvents++;
      return;
    }
  }

  size_t bytes_written = t.getReturnValue();
  gs.log.writeToLog(Importance::info, "bytesWritten: %d.\n", bytes_written);

  if ((int)bytes_written < 0) {
    gs.log.writeToLog(
        Importance::info, "Returned negative: %d.\n", bytes_written);
    return;
  }

  s.totalBytes += bytes_written;
  if (s.firstTrySystemcall) {
    s.firstTrySystemcall = false;
    s.beforeRetry = t.getRegs();
  }
  gs.log.writeToLog(Importance::info, "total bytes: %d.\n", bytes_written);
  gs.log.writeToLog(
      Importance::info, "before retry rdx: %d.\n", s.beforeRetry.rdx);

  // Finally wrote all bytes user wanted.

  // The zero case should not really happen. But our fuse tests allow for this
  // behavior so we catch it here. Otherwise we forever try to read 0 bytes.
  // https://stackoverflow.com/questions/41904221/can-write2-return-0-bytes-written-and-what-to-do-if-it-does?utm_medium=organic&utm_source=google_rich_qa&utm_campaign=google_rich_qa
  if (s.totalBytes == s.beforeRetry.rdx || bytes_written == 0) {
    resetState();
  } else {
    gs.log.writeToLog(
        Importance::info, "Not all bytes written: Replaying system call!\n");
    t.writeArg2(t.arg2() + bytes_written);
    t.writeArg3(t.arg3() - bytes_written);
    replaySystemCall(gs, t, t.getSystemCallNumber());
  }

  return;
}
// =======================================================================================
bool wait4SystemCall::handleDetPre(
    globalState& gs, state& s, ptracer& t, scheduler& sched) {
  s.wait4Blocking = (t.arg3() & WNOHANG) == 0;
  gs.log.writeToLog(Importance::info, "wait4(%d)\n", (int)t.arg1());
  gs.log.writeToLog(Importance::info, "Making this a non-blocking wait4\n");

  // Make this a non blocking hang!
  s.originalArg3 = t.arg3();
  t.writeArg3(s.originalArg3 | WNOHANG);
  return true;
}
void wait4SystemCall::handleDetPost(
    globalState& gs, state& s, ptracer& t, scheduler& sched) {
  if (s.wait4Blocking) {
    gs.log.writeToLog(Importance::info, "Blocking wait4 found\n");
    replaySyscallIfBlocked(gs, s, t, sched, 0);
  } else {
    gs.log.writeToLog(Importance::info, "Non-blocking wait4 found\n");
    preemptIfBlocked(gs, s, t, sched, EAGAIN);
  }
  // Reset.
  t.writeArg3(s.originalArg3);

  return;
}
// =======================================================================================
bool waitidSystemCall::handleDetPre(
    globalState& gs, state& s, ptracer& t, scheduler& sched) {
  s.wait4Blocking = (t.arg4() & WNOHANG) == 0;
  gs.log.writeToLog(Importance::info, "waitid(%d)\n", (int)t.arg1());
  gs.log.writeToLog(Importance::info, "Making this a non-blocking waitid\n");

  // Make this a non blocking hang!
  s.originalArg4 = t.arg4();
  t.writeArg4(s.originalArg4 | WNOHANG);
  return true;
}
void waitidSystemCall::handleDetPost(
    globalState& gs, state& s, ptracer& t, scheduler& sched) {
  if (s.wait4Blocking) {
    gs.log.writeToLog(Importance::info, "Blocking waitid found\n");
    replaySyscallIfBlocked(gs, s, t, sched, 0);
  } else {
    gs.log.writeToLog(Importance::info, "Non-blocking waitid found\n");
    preemptIfBlocked(gs, s, t, sched, EAGAIN);
  }
  // Reset.
  t.writeArg4(s.originalArg4);

  return;
}
// =======================================================================================
bool writevSystemCall::handleDetPre(
    globalState& gs, state& s, ptracer& t, scheduler& sched) {
  return true;
}

void writevSystemCall::handleDetPost(
    globalState& gs, state& s, ptracer& t, scheduler& sched) {
  // TODO: Handle bytes written.
  return;
}
// =======================================================================================

// =======================================================================================
bool socketSystemCall::handleDetPre(
    globalState& gs, state& s, ptracer& t, scheduler& sched) {
  int domain = t.arg1();

  if (domain == AF_INET || domain == AF_INET6) {
    if (!gs.allow_network) {
      gs.log.writeToLog(
          Importance::inter,
          "socket syscall disabled, add `--allow-network` to enable socket "
          "syscall\n");
      cancelSystemCall(gs, s, t);
      t.setReturnRegister(-ENOSYS);
      return false;
    }
  }

  return true;
}

void socketSystemCall::handleDetPost(
    globalState& gs, state& s, ptracer& t, scheduler& sched) {
  int fd = (int)t.getReturnValue();
  if (fd < 0) {
    return;
  }

  int domain = t.arg1();
  int type = t.arg2();

  if (domain == AF_INET || domain == AF_INET6) {
    s.remote_sockfds->insert(fd);
  }

  if (type & SOCK_NONBLOCK) {
    (*s.fdStatus)[fd] = descriptorType::nonBlocking;
  }

  gs.log.writeToLog(
      Importance::info, "socket returned " + to_string(fd) + "\n");
}
// =======================================================================================

// =======================================================================================
bool listenSystemCall::handleDetPre(
    globalState& gs, state& s, ptracer& t, scheduler& sched) {
  return true;
}

void listenSystemCall::handleDetPost(
    globalState& gs, state& s, ptracer& t, scheduler& sched) {
  int retval = (int)t.getReturnValue();

  gs.log.writeToLog(
      Importance::info, "listen returned " + to_string(retval) + "\n");

  return;
}
// =======================================================================================

// =======================================================================================
bool acceptSystemCall::handleDetPre(
    globalState& gs, state& s, ptracer& t, scheduler& sched) {
  cancelSystemCall(gs, s, t);
  t.writeArg4(0);
  replaySystemCall(gs, t, SYS_accept4);

  gs.log.writeToLog(Importance::info, "change syscall accept => accept4\n");
  return false;
}

void acceptSystemCall::handleDetPost(
    globalState& gs, state& s, ptracer& t, scheduler& sched) {
  runtimeError("should never run into SYS_accept posthook");
}
// =======================================================================================

static int get_proc_fd_flags(pid_t pid, int pid_fd) {
  char path[64];
  snprintf(path, 64, "/proc/%d/fdinfo/%d", pid, pid_fd);

  int fd = open(path, O_RDONLY);
  if (fd < 0) return 0;

  char buff[4096] = {
      0,
  };

  while (1) {
    ssize_t n = read(fd, buff, 4096);
    if (n < 0) {
      if (errno == EINTR) {
        continue;
      } else {
        close(fd);
        return 0;
      }
    }
    break;
  }

  close(fd);

  char* q = (char*)buff;

  const char prefix[] = "flags:";
  int prefix_len = strlen(prefix);
  while (1) {
    const char* p = strsep(&q, "\n");
    if (!p) break;
    if (strncmp(prefix, p, prefix_len) == 0) {
      p += prefix_len;
      while (p) {
        if (*p == ' ' || *p == '\t') ++p;
        break;
      }
      return (int)strtoul(p, NULL, 8);
    }
  }
  return 0;
}

// =======================================================================================
bool accept4SystemCall::handleDetPre(
    globalState& gs, state& s, ptracer& t, scheduler& sched) {
  int fd = t.arg1();
  int flags = t.arg4();

  gs.log.writeToLog(Importance::info, "accept4(%d), flags = %d\n", fd, flags);

  auto it = s.fdStatus.get()->find(fd);
  if (it != s.fdStatus.get()->end()) {
    if (it->second == descriptorType::nonBlocking) {
      return true;
    }
  }

  int fd_flags = get_proc_fd_flags(t.getPid(), fd);
  /* blocking accept4, simulating nonblocking io */
  s.userDefinedTimeout = true; // XXX: we have no timeout, borrow a variable
  s.originalArg1 = fd_flags;
  gs.log.writeToLog(
      Importance::info, "fd %d flags = 0x%x, nonblocking?: %d\n", fd, fd_flags,
      (fd_flags & O_NONBLOCK) == O_NONBLOCK);

  return true;
}

void accept4SystemCall::handleDetPost(
    globalState& gs, state& s, ptracer& t, scheduler& sched) {
  int fd = (int)t.arg1();
  int flags = (int)t.arg4();
  int retval = (int)t.getReturnValue();

  if (retval >= 0) {
    if ((flags & SOCK_NONBLOCK) == SOCK_NONBLOCK) {
      (*s.fdStatus.get())[retval] = descriptorType::nonBlocking;
    } else {
      (*s.fdStatus.get())[retval] = descriptorType::blocking;
    }
    gs.log.writeToLog(
        Importance::info, "accept4(%d) returned new fd %d\n", fd, retval);
    return;
  }

  if (s.userDefinedTimeout) {
    /* both EAGAIN/EWOULDBLOCK are valid return values for nonblocking mode */
    if (retval == -EAGAIN || retval == -EWOULDBLOCK) {
      gs.log.writeToLog(
          Importance::info, "accetp4 would have blocked! Replaying\n");
      gs.replayDueToBlocking++;
      sched.preemptAndScheduleNext();
      replaySystemCall(gs, t, t.getSystemCallNumber());
    }
    s.userDefinedTimeout = false;
    t.writeArg4(s.originalArg4);
  }
  return;
}
// =======================================================================================
bool shutdownSystemCall::handleDetPre(
    globalState& gs, state& s, ptracer& t, scheduler& sched) {
  gs.log.writeToLog(Importance::info, "shutdown(%d, %d)\n", t.arg1(), t.arg2());

  return true;
}

void shutdownSystemCall::handleDetPost(
    globalState& gs, state& s, ptracer& t, scheduler& sched) {
  int retval = (int)t.getReturnValue();

  gs.log.writeToLog(
      Importance::info, "shutdown returned " + to_string(retval) + "\n");

  if (retval == 0) {
    int fd = t.arg1();
    int how = t.arg2();
    if (how == SHUT_RDWR) {
      s.remote_sockfds->erase(fd);
    }
  }

  return;
}
