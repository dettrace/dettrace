#include "systemCall.hpp"

systemCall::systemCall(long syscallNumber, string syscallName) :
  syscallNumber(syscallNumber),
  syscallName(syscallName){
  return;
  }


bool systemCall::handleDetPre(globalState& gs, state& s, ptracer& t, scheduler& sched){
  return true;
}

void systemCall::handleDetPost(globalState& gs, state& s, ptracer& t, scheduler& sched){
  return;
}
