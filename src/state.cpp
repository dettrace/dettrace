#include "state.hpp"

state::state(logger& log, ValueMapper<ino_t>& inodeMap , pid_t traceePid, int debugLevel)
  : clock(0),
    traceePid(traceePid),
    inodeMap{ inodeMap },
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
