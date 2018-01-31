#ifndef PTRACER_H
#define PTRACER_H

#include <sys/types.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/vfs.h>
#include <sys/ptrace.h>
#include <sys/reg.h>     /* For constants ORIG_EAX, etc */
#include <string.h>
#include <sys/wait.h>
#include <sys/syscall.h>    /* For SYS_write, etc */

#include <algorithm>
#include <iostream>
#include <tuple>
#include <iostream>
#include <set>
#include <experimental/optional>
#include <memory>
#include <cstddef>

using namespace std;

// Words are 8 bytes for x86_64.
const size_t wordSize = 8;

/**
 * Types of events we expect returned from getNextEvent(), I wish we had ADTs.
 */
enum class ptraceEvent {
  syscall,     /// Post system call execution event.
  exit,        /// Process/thread has exited.
  signal,      /// Received signal.
  exec,        /// Execve event.
  clone,       /// Clone event.
  fork,        /// fork event.
  vfork,        /// fork event.
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
  /**
   * Registers for tracee before/after system call. Must be updated manually
   * using TODO.
   */
  struct user_regs_struct regs;

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

  void writeArg1(uint64_t val);
  void writeArg3(uint64_t val);

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
  static T readFromTracee(T* sourceAddress, pid_t traceePid){
    // Value to return.
    T peekedVal;
    // 8 byte value to increment as we move up.
    uint64_t* source = (uint64_t*) sourceAddress;
    uint64_t* dest = (uint64_t*) &peekedVal;
    uint32_t bytesTransferred = 0;

    // This will potentially read > bytesToCopy bytes from tracee, but writes only
    // bytesToCopy bytes to dst.
    //TODO OSNL: Could this lead to a segfault?

    // Continue reading until we have >= size of T read.
    while (bytesTransferred < sizeof(T)) {

      long result = ptracer::doPtrace(PTRACE_PEEKDATA, traceePid, source, nullptr);

      // Move over either a word, or the bytes left to complete the struct, whichever
      // is smaller.
      memcpy(dest, &result, min(sizeof(T) - bytesTransferred, wordSize));
      bytesTransferred += wordSize;

      // Pointer arithmetic, move pointers up 8 bytes in memory.
      dest++;
      source++;
    }

    return peekedVal;
  }


  /**
   * Read the C-string from the tracee's memory. Notice we keep reading until we hit a null.
   * Undefined behavior will happen if the location is not actually a C-string.
   * @retval str: A Cpp string version of readAddress.
   */
  static string readTraceeCString(char* source, pid_t traceePid);
  
  /**
   * Write a value
   */
  template<typename T>
  static void writeToTracee(T* writeAddress, T valueToCopy, pid_t traceePid){
    uint32_t bytesTransferred = 0;
    // Pointers to increment as we write data. We use these variables as we need to guarantee,
    // that we move up 8 bytes in memory with each increment.
    uint64_t* writeAddressP = (uint64_t*) writeAddress;
    uint64_t* valueToCopyP = (uint64_t*) & valueToCopy;

    // Continue writing until we have transfered >= size of datatype bytes.
    while (bytesTransferred < sizeof(T)){
      // Number of bytes left to transfer is greater than or equal to a word.
      if(sizeof(T) - bytesTransferred >= wordSize){
	// Ptrace doesn't want a pointer to memory holding the value, it wants thea
	// value passed as a void pointer! Yuck...
	ptracer::doPtrace(PTRACE_POKEDATA, traceePid, writeAddressP, (void*)*valueToCopyP);
	bytesTransferred += wordSize;
      }
      // handle final transfer of < wordSize bytes.
      else {
	uint32_t bytesLeft = sizeof(T) - bytesTransferred;
	// read existing memory from tracee
	long origTraceeMem =
	  ptracer::doPtrace(PTRACE_PEEKDATA, traceePid, writeAddressP, nullptr);
	// overwrite the bytes we need to change
	memcpy(& origTraceeMem, valueToCopyP, bytesLeft);
	// copy merged result back to tracee
	ptracer::doPtrace(PTRACE_POKEDATA, traceePid, writeAddressP, (void*) origTraceeMem);
	bytesTransferred += bytesLeft;
      }

      writeAddressP++;
      valueToCopyP++;
    }

    return;
  }


private:
  pid_t traceePid;

};

#endif
