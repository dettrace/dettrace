#include "fingerprinter.hpp"

extern "C" {

__attribute__((weak)) long fingerprinter_prehook(
    struct SyscallState* s,
    int pid,
    int tid,
    int syscallno,
    unsigned long arg0,
    unsigned long arg1,
    unsigned long arg2,
    unsigned long arg3,
    unsigned long arg4,
    unsigned long arg5) {
  return -ENOSYS;
}

__attribute__((weak)) long fingerprinter_posthook(
    struct SyscallState* s,
    int pid,
    int tid,
    int syscallno,
    unsigned long retval,
    unsigned long arg0,
    unsigned long arg1,
    unsigned long arg2,
    unsigned long arg3,
    unsigned long arg4,
    unsigned long arg5) {
  return 0;
}
}
