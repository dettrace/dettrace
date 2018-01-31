#include "state.hpp"

state::state(logger& log, pid_t traceePid, valueMapper& pidMap, pid_t ppid)
  : clock(0),
    traceePid(traceePid),
    ppid(ppid),
    pidMap(pidMap),
    inodeMap(log, "inodeMap"),
    log(log){
  return;
}
