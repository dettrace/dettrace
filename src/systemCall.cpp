#include "systemCall.hpp"

systemCall::systemCall(long syscallNumber, string syscallName) :
  syscallNumber(syscallNumber),
  syscallName(syscallName){
  return;
  }


bool systemCall::handleDetPre(state& s, ptracer& t){
  return true;
}

void systemCall::handleDetPost(state& s, ptracer& t){
  return;
}
