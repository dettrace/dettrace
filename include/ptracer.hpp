#ifndef PTRACER_H
#define PTRACER_H

#include <stdint.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/reg.h> /* For constants ORIG_EAX, etc */
#include <sys/stat.h>
#include <sys/syscall.h> /* For SYS_write, etc */
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/user.h>
#include <sys/vfs.h>
#include <sys/wait.h>
#include <unistd.h>

#include <algorithm>
#include <cstddef>
#include <experimental/optional>
#include <iostream>
#include <map>
#include <memory>
#include <set>
#include <tuple>

#include "traceePtr.hpp"
#include "util.hpp"

using namespace std;

const size_t wordSize = 8; /**< Size of word, 8 bytes for x86_64. */

/**
 * ptrace event enum.
 * Types of events we expect returned from getNextEvent(), I wish we had ADTs.
 */
enum class ptraceEvent {
  syscall, /**< Post system call execution event. */
  nonEventExit, /** Process/thread has exited. */
  eventExit, /**< Process/thread has exited. */
  signal, /**< Received signal. */
  exec, /**< Execve event. */
  clone, /**< Clone event. */
  fork, /**< fork event. */
  vfork, /** fork event. */
  terminatedBySignal, /**< Tracee terminated by signal. */
  seccomp,
};

/**
 * State of SysCall enum.
 * Ptrace does not keep track for us if this is a pre or a post event. Instead
 * we must track this ourselves.
 */
enum class syscallState {
  pre, /**< pre-hook state*/
  post /**< post-hook state*/
};

/**
 * ptracer.
 * Class wrapping the functionality of the system call ptrace.
 */
class ptracer {
public:
  /**
   * counter to keep track read vm events;
   */
  uint32_t readVmCalls = 0;

  /**
   * counter to keep track write vm events;
   */
  uint32_t writeVmCalls = 0;

  /**
   * counter for peeks, peeks only called through: readTraceeCString.
   */
  uint32_t ptracePeeks = 0;

  /**
   * Map of real inodes to virtual inodes.
   */
  map<ino_t, ino_t> real2VirtualMap;

  /**
   * Constructor.
   * Create a ptracer. The child must have called PTRACE_TRACEME and then
   *stopped itself like so: raise(SIGSTOP); execvp(traceeCommand[0],
   *traceeCommand);
   *
   * Else this will block forever. Set up options for our tracer.
   * @param pid process pid
   */
  ptracer(pid_t pid);

  /**
   * Retrieves value for arg1: rdi register.
   * @return rdi register value
   */
  uint64_t arg1();

  /**
   * Retrieves value for arg2: rsi register.
   * @return rsi register value
   */
  uint64_t arg2();

  /**
   * Retrieves value for arg3: rdx register.
   * @return rdx register value
   */
  uint64_t arg3();

  /**
   * Retrieves value for arg4: r10 register.
   * RCX, along with R11, is used by the syscall instruction, being immediately
   * destroyed by it. Thus these registers are not only not saved after syscall,
   * but they can't even be used for parameter passing. Thus R10 was chosen to
   * replace unusable RCX to pass fourth parameter. per:
   * https://stackoverflow.com/questions/21322100/linux-x64-why-does-r10-come-before-r8-and-r9-in-syscalls
   *
   * @return r10 register value
   */
  uint64_t arg4();

  /**
   * Retrieves value for arg5: r8 register.
   * @return r8 register value
   */
  uint64_t arg5();

  /**
   * Retrieves value for arg6: r9 register.
   * @return r9 register value
   */
  uint64_t arg6();

  /**
   * Retrieves register struct.
   * @return x86 register struct
   */
  struct user_regs_struct getRegs();

  /**
   * Set regs to the values given by passed struct.
   * @param newValues struct of new register values
   */
  void setRegs(struct user_regs_struct newValues);
  /**
   * Retrieves value for Rip register.
   * @return Rip register value
   */
  traceePtr<void> getRip();

  /**
   * Retrieves value for Rsp register.
   * @return Rsp register value
   */
  traceePtr<void> getRsp();

  /**
   * Retrieves value for Rax register.
   * @return Rax register value
   */
  traceePtr<void> getRax();

  /**
   * Change system call.
   * Writing to rax register, be careful!
   * @param val value to write to eax for new system call
   */
  void changeSystemCall(uint64_t val);

  /**
   * Write  value to Arg1: rdi register.
   * @param val new rdi register value
   */
  void writeArg1(uint64_t val);

  /**
   * Write  value to Arg2: rsi register.
   * @param val new rsi register value
   */
  void writeArg2(uint64_t val);

  /**
   * Write  value to Arg3: rdx register.
   * @param val new rdx register value
   */
  void writeArg3(uint64_t val);

  /**
   * Write  value to Arg4: r10 register.
   * @param val new r10 register value
   */
  void writeArg4(uint64_t val);

  /**
   * Write  value to Arg5: r8 register.
   * @param val new r8 register value
   */
  void writeArg5(uint64_t val);

  /**
   * Write  value to Arg6: r9 register.
   * @param val new r9 register value
   */
  void writeArg6(uint64_t val);

  /**
   * Write  value to ip register.
   * @param val new ip register value
   */
  void writeIp(uint64_t val);

  /**
   * Write  value to rax register.
   * @param val new rax register value
   */
  void writeRax(uint64_t val);

  /**
   * Write value to rbx register.
   * @param val new rbx register value
   */
  void writeRbx(uint64_t val);

  /**
   * Write  value to rdx register.
   * @param val new rdx register value
   */
  void writeRdx(uint64_t val);

  /**
   * Write  value to rcx register.
   * @param val new rcx register value
   */
  void writeRcx(uint64_t val);
  /**
   * All system call return an argument through their rax register.
   * Set state here.
   * @param retVal return value
   */
  void setReturnRegister(uint64_t retVal);

  /**
   * Get results of system calls, we cast register value into int to avoid
   * issues with sign.
   * @return Return value
   */
  int getReturnValue();

  /**
   * Get system call number.
   * During pre system call event.
   * @return System call number
   */
  uint64_t getSystemCallNumber();

  /**
   * Wrapper around PTRACE_GETEVENTMSG for our current tracee.
   * @return Event message
   */
  static uint64_t getEventMessage(pid_t traceePid);

  /**
   * Compare status returned from waitpid to ptrace event.
   * @param status
   * @param event
   * @return
   */
  inline static bool isPtraceEvent(int status, enum __ptrace_eventcodes event) {
    return (status >> 8) == (SIGTRAP | (event << 8));
  }

  /**
   * Update registers to the state of the passed pid. This is now the new pid.
   * @param newPid new pid number
   */
  void updateState(pid_t newPid);

  /**
   * Return the pid for the current process we have stopped in an event.
   * @return pid
   */
  pid_t getPid();

  /**
   * Set the correct tracing options for a child we plan to trace. This should
   * be called per child and only once! This must be called when child is
   * stopped waiting on ptrace.
   * @param pid process id
   */
  static void setOptions(pid_t pid);

  /*
   * Ptrace wrapper with error checking, use this instead of raw ptrace.
   * @param request
   * @param pid
   * @param addr
   * @param data
   * @return On success, PTRACE_PEEK* requests return the requested data, while
   * other requests return zero. On error, all requests return -1, and errno is
   * set appropriately. Since the value returned by a successful PTRACE_PEEK*
   * request may be -1, the caller must clear errno before the call, and then
   * check it afterward to determine whether or not an error occurred.
   */
  static long doPtrace(
      enum __ptrace_request request, pid_t pid, void *addr, void *data);

  /**
   * Read a type T from the tracee at source address. Be careful when reading
   * record types which may further contain other pointers! You will have to
   * fetch the other pointers yourself.
   * @param sourceAddress memory address of the type T in tracee memory to read.
   * @param traceePid Pid of the tracee
   * @return the data of type T at the memory address in tracee address space
   */
  template <typename T>
  T readFromTracee(traceePtr<T> sourceAddress, pid_t traceePid) {
    readVmCalls++;
    T myData;
    doWithCheck(
        readVmTraceeRaw(sourceAddress, &myData, sizeof(T), traceePid),
        "readFromTracee: Unable to read bytes at address.");
    return myData;
  }

  /**
   * Read the C-string from the tracee's memory.
   * Notice we keep reading until we hit a null.
   * Undefined behavior will happen if the location is not actually a C-string.
   * @param readAddress address of CString to be read from (in tracee address
   * space)
   * @param traceePid the pid of the tracee
   * @return cpp string version of readAddress.
   */
  string readTraceeCString(traceePtr<char> readAddress, pid_t traceePid);

  /**
   * Write a value to tracee.
   * @param writeAddress memory address in trace memory to write to.
   * @param valueToCopy value of type T to be written in tracee memory
   * @param traceePid the pid of the tracee
   */
  template <typename T>
  void writeToTracee(
      traceePtr<T> writeAddress, T valueToCopy, pid_t traceePid) {
    writeVmCalls++;
    writeVmTraceeRaw(
        &valueToCopy, traceePtr<T>(writeAddress), sizeof(T), traceePid);

    return;
  }

private:
  pid_t traceePid; /**< The pid of the tracee.  */

  struct user_regs_struct regs; /**< Registers struct defined in sys.   */
};

#endif
