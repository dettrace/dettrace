#include "state.hpp"

state::state(logger& log, pid_t traceePid, valueMapper& pidMap, pid_t ppid)
  : clock(0),
    traceePid(traceePid),
    pidMap(pidMap),
    inodeMap(log, "inodeMap"),
    log(log),
    ppid(ppid){

  return;
}
