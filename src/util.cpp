#include <err.h>
#include <linux/limits.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <iostream>

#include "util.hpp"

using namespace std;

unordered_map<int, string> futexCommands = {
    {FUTEX_WAIT, "FUTEX_WAIT"},
    {FUTEX_WAKE, "FUTEX_WAKE"},
    {FUTEX_FD, " FUTEX_FD"},
    {FUTEX_REQUEUE, " FUTEX_REQUEUE"},
    {FUTEX_CMP_REQUEUE, " FUTEX_CMP_REQUEUE"},
    {FUTEX_WAKE_OP, " FUTEX_WAKE_OP"},
    {FUTEX_LOCK_PI, " FUTEX_LOCK_PI"},
    {FUTEX_UNLOCK_PI, " FUTEX_UNLOCK_PI"},
    {FUTEX_TRYLOCK_PI, " FUTEX_TRYLOCK_PI"},
    {FUTEX_WAIT_BITSET, " FUTEX_WAIT_BITSET"},
    {FUTEX_WAKE_BITSET, " FUTEX_WAKE_BITSET"},
    {FUTEX_WAIT_REQUEUE_PI, " FUTEX_WAIT_REQUEUE_PI"},
    {FUTEX_CMP_REQUEUE_PI, " FUTEX_CMP_REQUEUE_PI"}};

unordered_map<int, string> futexAdditionalFlags = {
    // This is 128 which includes FUTEX_WAIT (value of 0).
    // So we omit it as it's equal to FUTEX_WAIT_PRIVATE.
    // { FUTEX_PRIVATE_FLAG, " FUTEX_PRIVATE_FLAG"},
    {FUTEX_CLOCK_REALTIME, " FUTEX_CLOCK_REALTIME"},
    {FUTEX_CMD_MASK, " FUTEX_CMD_MASK"},
    {FUTEX_WAIT_PRIVATE, " FUTEX_WAIT_PRIVATE"},
    {FUTEX_WAKE_PRIVATE, " FUTEX_WAKE_PRIVATE"},
    {FUTEX_REQUEUE_PRIVATE, " FUTEX_REQUEUE_PRIVATE"},
    {FUTEX_CMP_REQUEUE_PRIVATE, " FUTEX_CMP_REQUEUE_PRIVATE"},
    {FUTEX_WAKE_OP_PRIVATE, " FUTEX_WAKE_OP_PRIVATE"},
    {FUTEX_LOCK_PI_PRIVATE, " FUTEX_LOCK_PI_PRIVATE"},
    {FUTEX_UNLOCK_PI_PRIVATE, " FUTEX_UNLOCK_PI_PRIVATE"},
    {FUTEX_TRYLOCK_PI_PRIVATE, " FUTEX_TRYLOCK_PI_PRIVATE"},
    {FUTEX_WAIT_BITSET_PRIVATE, " FUTEX_WAIT_BITSET_PRIVATE"},
    {FUTEX_WAKE_BITSET_PRIVATE, " FUTEX_WAKE_BITSET_PRIVATE"},
    {FUTEX_WAIT_REQUEUE_PI_PRIVATE, " FUTEX_WAIT_REQUEUE_PI_PRIVATE"},
    {FUTEX_CMP_REQUEUE_PI_PRIVATE, " FUTEX_CMP_REQUEUE_PI_PRIVATE"}};

/*======================================================================================*/
void runtimeError(string error) {
  throw runtime_error("dettrace runtime exception: " + error);
}

/*======================================================================================*/
int parseNum(const char* const numToParse) {
  // Required to check error condition of strtol.
  char* endptr;

  int num = strtol(numToParse, &endptr, 10);
  if (endptr == numToParse) {
    fprintf(
        stderr,
        "util::parseNum: Cannot convert string \"%s\" into an integer.\n",
        numToParse);
    exit(1);
  } else if (*endptr == '\0') { /* Success, reached the end of the string. */
  } else { // Only some part of the string was converted.
    fprintf(
        stderr,
        "util::parseNum: Cannot convert string \"%s\" into an integer.\n",
        numToParse);
    exit(1);
  }

  return num;
}
/*======================================================================================*/
int doWithCheck(int returnValue, const char* errorMessage) {
  if (returnValue == -1) {
    sysError(errorMessage);
  }

  return returnValue;
}

void sysError(const char* context) {
  std::string message = strerror(errno);
  message += ":\n  ";
  message += context;
  runtimeError(message);
}

/*======================================================================================*/
