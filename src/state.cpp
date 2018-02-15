#include "state.hpp"

state::state(logger& log, pid_t traceePid)
  : clock(0),
    traceePid(traceePid),
    inodeMap(log, "inodeMap"),
    log(log){
  return;
}
