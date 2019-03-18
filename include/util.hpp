#ifndef UTIL_H
#define UTIL_H

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <iostream>
#include <limits.h>
#include <sys/uio.h>

#include<unordered_map>

#include <linux/futex.h>

#include "traceePtr.hpp"

using namespace std;

/**
 * Throws erro with dettrace tag for easy grepping. Use instead of explicit
 * throw runtime_error
 */
void runtimeError(string error);

extern unordered_map<int, string> futexNames; /**< map of futex words (32-bits) to string representations */

/**
 * Get env variable copy to free space and return as a heap-allocated pointer.
 * @param var: env variable to fetch from system (e.g. "HOME").
 * @param dieIfNotSet: if True, system will crash in case var was not found.
 * @return value of env variable as string if found. NULL if variable is
 *                    not found and dieifNotSet == false.
 */
char* getEnvVar(char* var, bool dieIfNotSet);

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
int doWithCheck(int returnValue, string errorMessage);

// =======================================================================================
/**
 * Read bytes from tracee memory using process_vm_readv while moving errors up the call
 * chain. The type T does not affect the behavior of the
 * function, however it provides clarity as to what the caller
 * is wishing to read/write.
 * @param traceeMemory starting address in tracee memory (remote)
 * @param localMemory starting address in local memory (local)
 * @param numberOfBytes number of bytes to be read
 * @param traceePid tracee process' pid, whose address space is being read
 */
template <typename T>
ssize_t readVmTraceeRaw(traceePtr<T> traceeMemory, T* localMemory, size_t numberOfBytes,
                  pid_t traceePid) {
  iovec remoteIoVec = {traceeMemory.ptr, numberOfBytes};
  iovec localIoVec = {localMemory, numberOfBytes };
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
void writeVmTraceeRaw(T* localMemory, traceePtr<T> traceeMemory, size_t numberOfBytes,
                   pid_t traceePid) {
  iovec remoteIoVec = {traceeMemory.ptr, numberOfBytes};
  iovec localIoVec = {localMemory, numberOfBytes };
  const unsigned long flags = 0;

  doWithCheck(process_vm_writev(traceePid, &localIoVec, 1, &remoteIoVec, 1, flags),
              "writeVmTraceeRaw: Error calling process_vm_writev");

  return;
}
#endif
