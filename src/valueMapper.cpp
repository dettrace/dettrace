#include <sys/syscall.h>
#include "logger.hpp"
#include "valueMapper.hpp"

using namespace std;

int valueMapper::addEntryValue(int realValue){
  myLogger.writeToLog(Importance::info, "%s: Added mapping %d -> %d\n",  mappingName.c_str(),
                      realValue, freshValue);

  int vValue = freshValue;
  realToVirtualValue[realValue] = vValue;
  virtualToRealValue[vValue] = realValue;
  freshValue++;
  return vValue;
  }

int valueMapper::getRealValue(int virtualValue){
  // Check if element exists?
  if(virtualToRealValue.find(virtualValue) != virtualToRealValue.end()){
    pid_t realValue = virtualToRealValue[virtualValue];
    myLogger.writeToLog(Importance::info, "%s: getRealValue(%d) = %d\n", mappingName.c_str(),
                        virtualValue, realValue);
    return realValue;
  }else{
    return -1;
  }
}

int valueMapper::getVirtualValue(int realValue){

  if(realToVirtualValue.find(realValue) != realToVirtualValue.end()){
    int returnValue = realToVirtualValue[realValue];
    myLogger.writeToLog(Importance::info, "%s: getVirtualValue(%d) = %d\n", mappingName.c_str(),
                        realValue, returnValue);
    return returnValue;
  }else{
    throw runtime_error(mappingName + ": getVirtualValue(" +
			to_string(realValue) + ") does not exist\n");
  }
}

valueMapper::valueMapper(logger& log, std::string name) :
  // Init class values.
  myLogger(log),
  mappingName(name){

  freshValue = 1;
}

bool valueMapper::realKeyExists(int realValue){
  bool keyExists = realToVirtualValue.find(realValue) != realToVirtualValue.end();
  return keyExists;
}

bool valueMapper::virtualKeyExists(int virtualValue){
  bool keyExists = virtualToRealValue.find(virtualValue) != virtualToRealValue.end();
  return keyExists;
}
