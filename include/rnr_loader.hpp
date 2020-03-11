#ifndef _MY_RNR_LOADER_H
#define _MY_RNR_LOADER_H

#include "dettrace.hpp"
#include "globalState.hpp"
#include "scheduler.hpp"
#include "state.hpp"

class rnr {
public:
  static bool callPreHook(
      void* user_data,
      SysEnter sysenter,
      int syscallNumber,
      globalState& gs,
      state& s,
      ptracer& t,
      scheduler& sched);
  static void callPostHook(
      void* user_data,
      SysExit sysexit,
      int syscallNumber,
      globalState& gs,
      state& s,
      ptracer& t,
      scheduler& sched);
};

#endif
