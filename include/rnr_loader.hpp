#ifndef _MY_RNR_LOADER_H
#define _MY_RNR_LOADER_H

#include "globalState.hpp"
#include "scheduler.hpp"
#include "state.hpp"

struct SyscallState {
  bool noop;
};

struct ProcessState {};

extern "C" {
struct rnr_loader {
  long (*rnr_sysenter)(
      struct SyscallState* s,
      int pid,
      int tid,
      int syscallno,
      unsigned long arg0,
      unsigned long arg1,
      unsigned long arg2,
      unsigned long arg3,
      unsigned long arg4,
      unsigned long arg5);
  long (*rnr_sysexit)(
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
      unsigned long arg5);
};
}

class rnr {
public:
  static void loadRnr(const string& dso);
  static bool callPreHook(
      int syscallNumber,
      globalState& gs,
      state& s,
      ptracer& t,
      scheduler& sched);
  static void callPostHook(
      int syscallNumber,
      globalState& gs,
      state& s,
      ptracer& t,
      scheduler& sched);
};

#endif
