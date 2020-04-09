#ifndef UTIL_H
#define UTIL_H

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <limits.h>
#include <sys/uio.h>
#include <iostream>

#include <unordered_map>

#include <linux/futex.h>

#include "traceePtr.hpp"

using namespace std;

/**
 * Helper function for getting a value from a container
 */
template <
    template <class, class, class...> class Container,
    typename K,
    typename V,
    typename... Args>
V get_with_default(
    const Container<K, V, Args...>& container, K const& key, const V& defval) {
  typename Container<K, V, Args...>::const_iterator it = container.find(key);
  if (it == container.end()) {
    return defval;
  }

  return it->second;
}

/**
 * Throws erro with dettrace tag for easy grepping. Use instead of explicit
 * throw runtime_error
 */
void runtimeError(string error);

extern unordered_map<int, string> futexCommands;
extern unordered_map<int, string> futexAdditionalFlags;

/**
 * Parses a string of numbers while safely handing all errors by reporting
 * error to stderr and exit(1). Warning: does not check for underflows!
 * @param numToParse: a pointer to the string to be parsed.
 * @return parsedNum
 */
int parseNum(const char* const numToParse);

/**
 * Used as a wrapper for clib function calls which return int as indicator of
 * success. If the clib function returns -1, an error message containing
 * contents of errno and the supplied parameter errorMessage is written to
 * cerr, and exit(1).
 * Example:
 *  doWithCheck(mount(cwd, pathToBuild.c_str(), nullptr, MS_BIND, nullptr),
 *             "Unable to bind mount cwd");
 *
 * @param returnValue the int return value of a clib function
 * @param errorMessage a string to be appended to the description of errno if
 *                     an the clib function returned -1 (failed)
 * @return the return value of the clib function.
 */
int doWithCheck(int returnValue, const char* errorMessage);
void sysError(const char* context);

// =======================================================================================
/**
 * Read bytes from tracee memory using process_vm_readv while moving errors up
 * the call chain. The type T does not affect the behavior of the function,
 * however it provides clarity as to what the caller is wishing to read/write.
 * @param traceeMemory starting address in tracee memory (remote)
 * @param localMemory starting address in local memory (local)
 * @param numberOfBytes number of bytes to be read
 * @param traceePid tracee process' pid, whose address space is being read
 */
template <typename T>
ssize_t readVmTraceeRaw(
    traceePtr<T> traceeMemory,
    T* localMemory,
    size_t numberOfBytes,
    pid_t traceePid) {
  iovec remoteIoVec = {traceeMemory.ptr, numberOfBytes};
  iovec localIoVec = {localMemory, numberOfBytes};
  const unsigned long flags = 0;

  return process_vm_readv(traceePid, &localIoVec, 1, &remoteIoVec, 1, flags);
}
// =======================================================================================
/**
 * Write bytes to tracee memory using process_vm_writev while safely
 * handling errors. The type T does not affect the behavior of the
 * function, however it provides clarity as to what the caller
 * is wishing to read/write.
 * @param localMemory starting address in local memory (remote)
 * @param traceeMemory starting address in tracee memory (local)
 * @param numbeOfBytes number of bytes to be write
 * @param traceepid tracee process' pid, whose address space is being written to
 */
template <typename T>
void writeVmTraceeRaw(
    T* localMemory,
    traceePtr<T> traceeMemory,
    size_t numberOfBytes,
    pid_t traceePid) {
  iovec remoteIoVec = {traceeMemory.ptr, numberOfBytes};
  iovec localIoVec = {localMemory, numberOfBytes};
  const unsigned long flags = 0;

  doWithCheck(
      process_vm_writev(traceePid, &localIoVec, 1, &remoteIoVec, 1, flags),
      "writeVmTraceeRaw: Error calling process_vm_writev");

  return;
}

void throw_runtime_error_if_fail(
    bool cond,
    int os_error,
    const char* file,
    int line,
    const char* func,
    const char* desc);

#define VERIFY(cond)                                       \
  do {                                                     \
    throw_runtime_error_if_fail(                           \
        cond, errno, __FILE__, __LINE__, __func__, #cond); \
  } while (0)

#endif
