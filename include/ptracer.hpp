#ifndef PTRACER_H
#define PTRACER_H

#include <stdint.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/user.h>
#include <sys/vfs.h>
#include <sys/ptrace.h>
#include <sys/reg.h>     /* For constants ORIG_EAX, etc */
#include <string.h>
#include <sys/wait.h>
#include <sys/syscall.h>    /* For SYS_write, etc */
#include <sys/uio.h>

#include <algorithm>
#include <iostream>
#include <tuple>
#include <iostream>
#include <set>
#include <map>
#include <experimental/optional>
#include <memory>
#include <cstddef>

#include "util.hpp"
#include "traceePtr.hpp"

using namespace std;

// Words are 8 bytes for x86_64.
const size_t wordSize = 8;

/**
 * Types of events we expect returned from getNextEvent(), I wish we had ADTs.
 */
enum class ptraceEvent {
  syscall,     /// Post system call execution event.
  nonEventExit,        /// Process/thread has exited.
  eventExit,        /// Process/thread has exited.
  signal,      /// Received signal.
  exec,        /// Execve event.
  clone,       /// Clone event.
  fork,        /// fork event.
  vfork,        /// fork event.
  terminatedBySignal, // Tracee terminated by signal.
  seccomp,
};

/**
 * Ptrace does not keep track for us if this is a pre or a post event. Instead we must
 * track this ourselves.
 */
enum class syscallState { pre, post };


/**
 * Class wrapping the functionality of the system call ptrace.
 */
class ptracer{
public:
  map<ino_t,ino_t> real2VirtualMap;

  /**
   * Create a ptracer. The child must have called PTRACE_TRACEME and then stopped itself like
   * so:
   *     raise(SIGSTOP);
   *	 execvp(traceeCommand[0], traceeCommand);
   *
   * Else this will block forever. Set up options for our tracer.
   */
  ptracer(pid_t pid);

  // Get the argument from our system call.
  uint64_t arg1();
  uint64_t arg2();
  uint64_t arg3();
  uint64_t arg4();
  uint64_t arg5();
  uint64_t arg6();
  struct user_regs_struct getRegs();

  // Set regs to the values given by passed struct.
  void setRegs(struct user_regs_struct newValues);
  uint64_t getRip();
  uint64_t getRsp();

  /**
   * Change system call by writing to eax register, be careful!
   */
  void changeSystemCall(uint64_t val);

  void writeArg1(uint64_t val);
  void writeArg2(uint64_t val);
  void writeArg3(uint64_t val);
  void writeArg4(uint64_t val);
  void writeArg5(uint64_t val);
  void writeIp(uint64_t val);
  void writeRax(uint64_t val);
 /**
   * All system call return an argument through their eax register. Set state here.
   */
  void setReturnRegister(uint64_t retVal);

  /**
   * Get results of system calls. During post system call event.
   */
  uint64_t getReturnValue();

  /**
   * Get system call number. During pre system call event.
   */
  uint64_t getSystemCallNumber();

  /**
   * Wrapper around PTRACE_GETEVENTMSG for our current tracee.
   */
  uint64_t getEventMessage();

  /**
   * Compare status returned from waitpid to ptrace event.
   */
  static bool isPtraceEvent(int status, enum __ptrace_eventcodes event);

  /**
   * Update registers to the state of the passed pid. This is now the new pid.
   */
  void updateState(pid_t newPid);

  /**
   * Return the pid for the current process we have stopped in an event.
   */
  pid_t getPid();

  /**
   * Set the correct tracing options for a child we plan to trace. This should be called
   * per child and only once! This must be called when child is stopped waiting on ptrace.
   */
  static void setOptions(pid_t pid);

  /*
   * Ptrace wrapper with error checking, use this instead of raw ptrace.
   */
  static long doPtrace(enum __ptrace_request request, pid_t pid, void *addr, void *data);

  /**
   * Read a type T from the tracee at source address. Be careful when reading
   * record types which may further contain other pointers! You will have to
   * fetch the other pointers yourself.
   */
  template<typename T>
  static T readFromTracee(traceePtr<T> sourceAddress, pid_t traceePid){
    T myData;
    readVmTracee(sourceAddress, &myData, sizeof(T), traceePid);
    return myData;
  }


  /**
   * Read the C-string from the tracee's memory. Notice we keep reading until we hit a null.
   * Undefined behavior will happen if the location is not actually a C-string.
   * @retval str: A Cpp string version of readAddress.
   */
  static string readTraceeCString(traceePtr<char> source, pid_t traceePid);

  /**
   * Write a value
   */
  template<typename T>
  static void writeToTracee(traceePtr<T> writeAddress, T valueToCopy, pid_t traceePid){
    writeVmTracee(&valueToCopy, traceePtr<T>(writeAddress), sizeof(T), traceePid);

    return;
  }


private:
  pid_t traceePid;
  struct user_regs_struct regs;
};

#endif
