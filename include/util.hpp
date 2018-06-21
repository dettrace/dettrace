#ifndef UTIL_H
#define UTIL_H

/**
 * Utility functions.
 */
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <iostream>
#include <limits.h>
#include <sys/uio.h>

#include<unordered_map>

#include <linux/futex.h>

#include "TraceePtr.hpp"

using namespace std;

extern unordered_map<int, string> futexNames;

/*======================================================================================*/
/**
 * Get env variable copy to free space and return as a heap-allocated pointer.
 * @param var: env variable to fetch from system.
 * @param dieIfNotSet: if variable is not found, should system crash?
 * @return returnVar: value of variable as string or if not found and dieifNotSet == false.
 *                    otherwise return NUll.
 */
char* getEnvVar(char* var, bool dieIfNotSet);
/*======================================================================================*/
/**
 * Given a string attemp to parse using strtol. Handles all errors by crashing and sending
 * an appropriate error. Warning: does not check for underflows!
 @param: numToParse.
 @return: parsedNum ;)
 */
int parseNum(const char* const numToParse);
// =======================================================================================
/**
 * Call clib function that returns an integer and sets errno with automatic checking
 * and exiting on -1. Returns returnValue on success.
 *
 * Example:
 * doWithCheck(mount(cwd, pathToBuild.c_str(), nullptr, MS_BIND, nullptr),
 *             "Unable to bind mount cwd");
 */
int doWithCheck(int returnValue, string errorMessage);
// =======================================================================================
// Read bytes from user.
// Ptrace read is way too slow as it works at word granularity. Time to use
// process_vm_read!
template <typename T>
void readVmTracee(TraceePtr<T> traceeMemory, void* localMemory, size_t numberOfBytes,
                  pid_t traceePid) {
  iovec remoteIoVec = {traceeMemory.ptr, numberOfBytes};
  iovec localIoVec = {localMemory, numberOfBytes };
  const unsigned long flags = 0;

  doWithCheck(process_vm_readv(traceePid, &localIoVec, 1, &remoteIoVec, 1, flags),
              "process_vm_writev");

  return;

}
// =======================================================================================
template <typename T>
void writeVmTracee(void* localMemory, TraceePtr<T> traceeMemory, size_t numberOfBytes,
                   pid_t traceePid) {
  iovec remoteIoVec = {traceeMemory.ptr, numberOfBytes};
  iovec localIoVec = {localMemory, numberOfBytes };
  const unsigned long flags = 0;

  doWithCheck(process_vm_writev(traceePid, &localIoVec, 1, &remoteIoVec, 1, flags),
              "process_vm_writev");

  return;
}
// =======================================================================================
#endif
