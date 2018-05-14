#include "state.hpp"

state::state(pid_t traceePid, int debugLevel)
  : clock(0),
    traceePid(traceePid),
    debugLevel(debugLevel){
  return;
}

int state::getLogicalTime(){
  return clock;
}

void state::incrementTime(){
  clock++;
}
