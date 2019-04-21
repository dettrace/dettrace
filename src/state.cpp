#include "state.hpp"

state::state(pid_t traceePid, int debugLevel)
  : clock(744847200), // avoid clock skew, see issue #24 for more details.
                      // same value as of libdet.c
    fdStatus(new unordered_map<int, descriptorType>),
    traceePid(traceePid),
    signalToDeliver(0),
    mmapMemory(2048),
    debugLevel(debugLevel)
{

  return;
}

state::state(pid_t traceePid, int debugLevel,
             shared_ptr<unordered_map<int, descriptorType>> parentFdStatus)
  : clock(744847200), // avoid clock skew, see issue #24 for more details.
                      // same value as of libdet.c
    fdStatus(parentFdStatus),
    traceePid(traceePid),
    signalToDeliver(0),
    mmapMemory(2048),
    debugLevel(debugLevel)
{
  return;
}

state::state(pid_t traceePid, int debugLevel,
             unordered_map<int, descriptorType> fdStatus)
  : clock(744847200), // avoid clock skew, see issue #24 for more details.
                      // same value as of libdet.c
    fdStatus(new unordered_map<int, descriptorType>{fdStatus}),
    traceePid(traceePid),
    signalToDeliver(0),
    mmapMemory(2048),
    debugLevel(debugLevel)
{
  return;
}

int state::getLogicalTime(){
  return clock;
}

void state::incrementTime(){
  clock++;
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
