#ifndef FINGERPRINTER_H
#define FINGERPRINTER_H

#include "globalState.hpp"
#include "state.hpp"
#include "scheduler.hpp"

struct SyscallState {
  bool noop;
};

struct ProcessState {};

extern "C" long fingerprinter_prehook(
  struct SyscallState* s,
  int pid,
  int tid,
  int syscallno,
  unsigned long arg0,
  unsigned long arg1,
  unsigned long arg2,
  unsigned long arg3,
  unsigned long arg4,
  unsigned long arg5
);

extern "C" long fingerprinter_posthook(
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
  unsigned long arg5
);

class fingerprinter {
public:
  static bool callPreHook(int syscallNumber, globalState& gs, state& s, ptracer& t, scheduler& sched);
  static void callPostHook(int syscallNumber, globalState& gs, state& s, ptracer& t, scheduler& sched);
};

#endif
