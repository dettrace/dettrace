extern "C" {
#include <stdint.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/reg.h> /* For constants ORIG_EAX, etc */
#include <sys/syscall.h> /* For SYS_write, etc */
#include <sys/types.h>
#include <sys/user.h>
#include <sys/vfs.h>
#include <sys/wait.h>
}
#include <algorithm>
#include <cstddef>
#include <experimental/optional>
#include <iostream>
#include <memory>
#include <set>
#include <tuple>

#include "dettraceSystemCall.hpp"
#include "ptracer.hpp"

using namespace std;

ptracer::ptracer(pid_t pid) {
  traceePid = pid;

  int startingStatus;
  if (-1 == waitpid(pid, &startingStatus, 0)) {
    throw runtime_error(
        "Unable to start first process: " + string{strerror(errno)});
  }
}

uint64_t ptracer::arg1() { return regs.rdi; }
uint64_t ptracer::arg2() { return regs.rsi; }
uint64_t ptracer::arg3() { return regs.rdx; }
uint64_t ptracer::arg4() { return regs.r10; }
uint64_t ptracer::arg5() { return regs.r8; }
uint64_t ptracer::arg6() { return regs.r9; }
struct user_regs_struct ptracer::getRegs() {
  return regs;
}

void ptracer::setRegs(struct user_regs_struct newValues) {
  regs = newValues;
  // Please note how the memory address is passed in data argument here.
  // Which I guess sort of makes sense? We are passing data to it?
  doPtrace(PTRACE_SETREGS, traceePid, nullptr, &regs);
  return;
}

traceePtr<void> ptracer::getRip() { return traceePtr<void>((void *)regs.rip); }
traceePtr<void> ptracer::getRsp() { return traceePtr<void>((void *)regs.rsp); }

traceePtr<void> ptracer::getRax() { return traceePtr<void>((void *)regs.rax); }

uint64_t ptracer::getEventMessage(pid_t traceePid) {
  long event;
  doPtrace(PTRACE_GETEVENTMSG, traceePid, nullptr, &event);

  return event;
}

int ptracer::getReturnValue() { return (int)regs.rax; }

uint64_t ptracer::getSystemCallNumber() { return regs.orig_rax; }

void ptracer::setReturnRegister(uint64_t retVal) {
  regs.rax = retVal;
  // Please note how the memory address is passed in data argument here.
  // Which I guess sort of makes sense? We are passing data to it?
  doPtrace(PTRACE_SETREGS, traceePid, nullptr, &regs);
}

void ptracer::updateState(pid_t newPid) {
  traceePid = newPid;
  doPtrace(PTRACE_GETREGS, traceePid, NULL, &regs);

  return;
}

pid_t ptracer::getPid() { return traceePid; }

void ptracer::setOptions(pid_t pid) {
  doPtrace(PTRACE_SETOPTIONS, pid, NULL, (void*)
	   (PTRACE_O_EXITKILL | // If Tracer exits. Send SIGKIll signal to all tracees.
	    PTRACE_O_TRACECLONE | // enroll child of tracee when clone is called.
	    // We don't really need to catch execves, but we get a spurious signal 5
	    // from ptrace if we don't.
	    PTRACE_O_TRACEEXEC |
	    PTRACE_O_TRACEFORK |
	    PTRACE_O_TRACEVFORK |
	    // Stop tracee right as it is about to exit. This is needed as we cannot
	    // assume WIFEXITED will work, see man ptrace 2.
	    PTRACE_O_TRACEEXIT |
	    PTRACE_O_TRACESYSGOOD |
	    PTRACE_O_TRACESECCOMP |
      PTRACE_O_TRACEEXEC
	    ));
  return;
}

string ptracer::readTraceeCString(
    traceePtr<char> readAddress, pid_t traceePid) {
  string r;
  bool done = false;

  // Read long-sized chunks of memory at at time.
  while (!done) {
    int64_t result =
        doPtrace(PTRACE_PEEKDATA, traceePid, readAddress.ptr, nullptr);
    ptracePeeks++;
    const char *p = (const char *)&result;
    const size_t bytesRead = strnlen(p, wordSize);
    if (wordSize != bytesRead) {
      done = true;
    }

    for (unsigned i = 0; i < bytesRead; i++) {
      r += p[i];
    }

    // Notice this doesn't change readAddress outside this function -> pass by
    // value.
    readAddress.ptr += bytesRead;
  }

  return r;
}

long ptracer::doPtrace(
    enum __ptrace_request request, pid_t pid, void *addr, void *data) {
  /*
    Return Value
    On success, PTRACE_PEEK* requests return the requested data, while other
    requests return zero. On error, all requests return -1, and errno is set
    appropriately. Since the value returned by a successful PTRACE_PEEK* request
    may be -1, the caller must clear errno before the call, and then check it
    afterward to determine whether or not an error occurred.
    -- ptrace manpage
  */

  errno = 0;
  const long val = ptrace(request, pid, addr, data);

  if (PTRACE_PEEKTEXT == request || PTRACE_PEEKDATA == request ||
      PTRACE_PEEKUSER == request) {
    if (0 != errno) {
      runtimeError(
          "Ptrace_peek* failed with error: " + string{strerror(errno)});
    }
  } else if (-1 == val) {
    runtimeError(
        "Ptrace failed with error: " + string{strerror(errno)} + " on thread " +
        to_string(pid) + " with request " + to_string(request) + "\n");
  }
  return val;
}

void ptracer::changeSystemCall(uint64_t val) {
  regs.orig_rax = val;
  regs.rax = val;
  doPtrace(PTRACE_SETREGS, traceePid, nullptr, &regs);
  return;
}

void ptracer::writeArg1(uint64_t val) {
  regs.rdi = val;
  doPtrace(PTRACE_SETREGS, traceePid, nullptr, &regs);
}

void ptracer::writeArg2(uint64_t val) {
  regs.rsi = val;
  doPtrace(PTRACE_SETREGS, traceePid, nullptr, &regs);
}
void ptracer::writeArg3(uint64_t val) {
  regs.rdx = val;
  doPtrace(PTRACE_SETREGS, traceePid, nullptr, &regs);
}

void ptracer::writeArg4(uint64_t val) {
  regs.r10 = val;
  doPtrace(PTRACE_SETREGS, traceePid, nullptr, &regs);
}

void ptracer::writeArg5(uint64_t val) {
  regs.r8 = val;
  doPtrace(PTRACE_SETREGS, traceePid, nullptr, &regs);
}

void ptracer::writeArg6(uint64_t val) {
  regs.r9 = val;
  doPtrace(PTRACE_SETREGS, traceePid, nullptr, &regs);
}

void ptracer::writeIp(uint64_t val) {
  regs.rip = val;
  doPtrace(PTRACE_SETREGS, traceePid, nullptr, &regs);
}

void ptracer::writeRax(uint64_t val) {
  regs.rax = val;
  doPtrace(PTRACE_SETREGS, traceePid, nullptr, &regs);
}

void ptracer::writeRbx(uint64_t val) {
  regs.rbx = val;
  doPtrace(PTRACE_SETREGS, traceePid, nullptr, &regs);
}

void ptracer::writeRdx(uint64_t val) {
  regs.rdx = val;
  doPtrace(PTRACE_SETREGS, traceePid, nullptr, &regs);
}

void ptracer::writeRcx(uint64_t val) {
  regs.rcx = val;
  doPtrace(PTRACE_SETREGS, traceePid, nullptr, &regs);
}
