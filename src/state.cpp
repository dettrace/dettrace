#include "state.hpp"

state::state(pid_t traceePid, int debugLevel)
  : clock(744847200), // avoid clock skew, see issue #24 for more details.
                      // same value as of libdet.c
    traceePid(traceePid),
    signalToDeliver(0),
    mmapMemory(2048),
    debugLevel(debugLevel)
{
  return;
}

int state::getLogicalTime(){
  return clock;
}

void state::incrementTime(){
  clock++;
}
