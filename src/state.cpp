#include "state.hpp"

state::state(logger& log, ValueMapper<ino_t, ino_t>& inodeMap,
             ValueMapper<ino_t, time_t>& mtimeMap, pid_t traceePid, int debugLevel)
  : clock(0),
    traceePid(traceePid),
    inodeMap{ inodeMap },
    mtimeMap{ mtimeMap },
    log(log),
    debugLevel(debugLevel){
  return;
}

int state::getLogicalTime(){
  return clock;
}

void state::incrementTime(){
  clock++;
}
