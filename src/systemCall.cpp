#include "systemCall.hpp"

systemCall::systemCall(long syscallNumber, string syscallName) :
  syscallNumber(syscallNumber),
  syscallName(syscallName){
  return;
  }


bool systemCall::handleDetPre(state& s, ptracer& t){
  throw runtime_error("systemCall::handleDetPre: Unimplemented system call: " +
		      syscallName);
}

void systemCall::handleDetPost(state& s, ptracer& t){
  throw runtime_error("systemCall::handleDetPost: Unimplemented system call: " +
		      syscallName);
  return;
}
