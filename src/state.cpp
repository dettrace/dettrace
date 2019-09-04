#include "state.hpp"

state::state(pid_t traceePid, int debugLevel) :
    fdStatus(new unordered_map<int, descriptorType>),
    traceePid(traceePid),
    signalToDeliver(0),
    mmapMemory(2048),
    debugLevel(debugLevel)
{
  return;
}

state::state(pid_t traceePid, int debugLevel,
             shared_ptr<unordered_map<int, descriptorType>> parentFdStatus):
    fdStatus(parentFdStatus),
    traceePid(traceePid),
    signalToDeliver(0),
    mmapMemory(2048),
    debugLevel(debugLevel)
{
  return;
}

state::state(pid_t traceePid, int debugLevel,
             unordered_map<int, descriptorType> fdStatus):
    fdStatus(new unordered_map<int, descriptorType>{fdStatus}),
    traceePid(traceePid),
    signalToDeliver(0),
    mmapMemory(2048),
    debugLevel(debugLevel)
{
  return;
}

void state::setFdStatus(int fd, descriptorType dt){
  fdStatus.get()->insert(pair<int, descriptorType>(fd, dt));
}

descriptorType state::getFdStatus(int fd){
  return fdStatus.get()->at(fd);
}

int state::countFdStatus(int fd){
  return fdStatus.get()->count(fd);
}
