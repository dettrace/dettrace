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

using namespace std;

/**
 * Size of word.
 * Words are 8 bytes for x86_64.
 */
const size_t wordSize = 8;

/**
 * ptrace event enum.
 * Types of events we expect returned from getNextEvent(), I wish we had ADTs.
 */
enum class ptraceEvent {
  syscall,     /**< Post system call execution event. */
  nonEventExit,        /** Process/thread has exited. */
  eventExit,        /**< Process/thread has exited. */
  signal,      /**< Received signal. */
  exec,        /**< Execve event. */
  clone,       /**< Clone event. */
  fork,        /**< fork event. */
  vfork,        /** fork event. */
  terminatedBySignal, /**< Tracee terminated by signal. */
  seccomp,
};

/**
 * State of SysCall enum.
 * Ptrace does not keep track for us if this is a pre or a post event. Instead we must
 * track this ourselves.
 */
enum class syscallState {
  pre,  /**< pre-hook state*/
  post /**< post-hook state*/
};


/**
 * ptracer.
 * Class wrapping the functionality of the system call ptrace.
 */
class ptracer{
public:
  map<ino_t,ino_t> real2VirtualMap;

  /**
   * Constructor.
   * Create a ptracer. The child must have called PTRACE_TRACEME and then stopped itself like
   * so:
   *     raise(SIGSTOP);
   *	 execvp(traceeCommand[0], traceeCommand);
   *
   * Else this will block forever. Set up options for our tracer.
   * @param pid process pid
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
   * Change system call.
   * Writing to eax register, be careful!
   * @param val value to write to eax for new system call
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
   * All system call return an argument through their eax register.
   * Set state here.
   * @param retVal return value
   */
  void setReturnRegister(uint64_t retVal);

  /**
   * Get results of system calls.
   * During post system call event.
   * @return Return value
   */
  uint64_t getReturnValue();

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
  uint64_t getEventMessage();

  /**
   * Compare status returned from waitpid to ptrace event.
   * @param status
   * @param event
   * @return
   */
  static bool isPtraceEvent(int status, enum __ptrace_eventcodes event);

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
   * Set the correct tracing options for a child we plan to trace. This should be called
   * per child and only once! This must be called when child is stopped waiting on ptrace.
   * @param pid process id
   */
  static void setOptions(pid_t pid);

  /*
   * Ptrace wrapper with error checking, use this instead of raw ptrace.
   * @param request
   * @param pid
   * @param addr
   * @param data
   * @return On success, PTRACE_PEEK* requests return the requested data, while other
   * requests return zero. On error, all requests return -1, and errno is set
   * appropriately. Since the value returned by a successful PTRACE_PEEK* request may
   * be -1, the caller must clear errno before the call, and then check it afterward
   * to determine whether or not an error occurred.
   */
  static long doPtrace(enum __ptrace_request request, pid_t pid, void *addr, void *data);

  /**
   * Read a type T from the tracee at source address. Be careful when reading
   * record types which may further contain other pointers! You will have to
   * fetch the other pointers yourself.
   */
  template<typename T>
  static T readFromTracee(T* sourceAddress, pid_t traceePid){
    T myData;
    readVmTracee(sourceAddress, &myData, sizeof(T), traceePid);
    return myData;
  }


  /**
   * Read the C-string from the tracee's memory.
   * Notice we keep reading until we hit a null.
   * Undefined behavior will happen if the location is not actually a C-string.
   * @param readAddress address to be read from
   * REVIEW these mismatched between cpp and hpp (was source in hpp, readAddress in cpp)
   * @param traceePid the pid of the tracee
   * @return cpp string version of readAddress.
   */
  static string readTraceeCString(const char* readAddress, pid_t traceePid);

  /**
   * Write a value to tracee.
   * @param writeAddress
   * @param valueToCopy
   * @param traceePid the pid of the tracee
   */
  template<typename T>
  static void writeToTracee(T* writeAddress, T valueToCopy, pid_t traceePid){
    writeVmTracee(&valueToCopy, writeAddress, sizeof(T), traceePid);

    return;
  }


private:
  /**
  * The pid of the tracee.
  */
  pid_t traceePid;

  /**
   * Registers struct
   * defined in sys
   */
  struct user_regs_struct regs;
};

#endif
