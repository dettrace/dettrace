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
  pipe_read_fds = std::make_shared<unordered_map<int, int>>();
  pipe_write_fds = std::make_shared<unordered_map<int, int>>();
  epollin_ev = std::make_shared<unordered_set<unsigned long>>();
  epollout_ev = std::make_shared<unordered_set<unsigned long>>();
  epollpri_ev = std::make_shared<unordered_set<unsigned long>>();

  currentSignalHandlers = std::make_shared<unordered_map<int, enum sighandler_type>>();
  timerCreateTimers = std::make_shared<unordered_map<timerID_t, timerInfo>>();

  futex_waiters = std::make_shared<unordered_map<unsigned long, deque<long>>>();
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

state state::forked(pid_t childPid) const {
  state childState(childPid, this->debugLevel);
  childState.clock = this->clock;
  childState.CPUIDTrapSet = this->CPUIDTrapSet;
  childState.currentSignalHandlers = make_shared<unordered_map<int, enum sighandler_type>>(*(this->currentSignalHandlers));
  childState.dirEntries = this->dirEntries;
  childState.epollin_ev = make_shared<unordered_set<unsigned long>>(*(this->epollin_ev));
  childState.epollout_ev = make_shared<unordered_set<unsigned long>>(*(this->epollin_ev));
  childState.epollpri_ev = make_shared<unordered_set<unsigned long>>(*(this->epollin_ev));

  childState.exfsNotNull = this->exfsNotNull;
  childState.rdfsNotNull = this->rdfsNotNull;
  childState.wrfsNotNull = this->wrfsNotNull;

  childState.fdStatus = make_shared<unordered_map<int, descriptorType>>(*(this->fdStatus));
  childState.fileExisted = this->fileExisted;
  childState.firstTrySystemcall = false;
  childState.inodeToDelete = this->inodeToDelete;
  childState.isExitGroup = false;
  childState.mmapMemory = this->mmapMemory;
  childState.noopSystemCall = false;
  childState.onPreExitEvent = false;
  childState.origExfs = this->origExfs;
  childState.origRdfs = this->origRdfs;
  childState.origWrfs = this->origWrfs;
  childState.originalArg1 = 0;
  childState.originalArg2 = 0;
  childState.originalArg3 = 0;
  childState.originalArg4 = 0;
  childState.originalArg5 = 0;
  childState.originalArg6 = 0;
  childState.rdfsNotNull = false;
  childState.regSaver = this->regSaver;
  childState.requestedSignalHandler = this->requestedSignalHandler;
  childState.requestedSignalToHandle = this->requestedSignalToHandle;
  childState.signalInjected = false;
  childState.timerCreateTimers = make_shared<unordered_map<timerID_t, timerInfo>>(*(this->timerCreateTimers));
  childState.totalBytes = this->totalBytes;
  childState.traceePid = childPid;
  childState.userDefinedTimeout = false;
  childState.wait4Blocking = false;

  childState.pipe_read_fds = make_shared<unordered_map<int, int>>(*(this->pipe_read_fds));
  childState.pipe_write_fds = make_shared<unordered_map<int, int>>(*(this->pipe_write_fds));

  unordered_map<unsigned long, deque<long>> waiters;
  for (auto it = this->futex_waiters.get()->begin(); it != this->futex_waiters.get()->end(); ++it) {
    deque<long> pids;
    for (auto it1 = it->second.begin(); it1 != it->second.end(); ++it1) {
      pids.clear();
      if (*it1 > 0) {
	pids.push_back(*it1);
      }
    }
    waiters.insert({it->first, pids});
  }
  childState.futex_waiters = make_shared<unordered_map<unsigned long, deque<long>>>(waiters);

  return childState;
}

state state::cloned(pid_t childPid) const {
  state childState(childPid, this->debugLevel);
  childState.clock = this->clock;
  childState.CPUIDTrapSet = this->CPUIDTrapSet;
  childState.currentSignalHandlers = this->currentSignalHandlers;
  childState.dirEntries = this->dirEntries;
  childState.epollin_ev = this->epollin_ev;
  childState.epollout_ev = this->epollin_ev;
  childState.epollpri_ev = this->epollin_ev;

  childState.exfsNotNull = this->exfsNotNull;
  childState.rdfsNotNull = this->rdfsNotNull;
  childState.wrfsNotNull = this->wrfsNotNull;

  childState.fdStatus = this->fdStatus;

  childState.fileExisted = this->fileExisted;
  childState.firstTrySystemcall = false;
  childState.inodeToDelete = this->inodeToDelete;
  childState.isExitGroup = false;
  childState.mmapMemory = this->mmapMemory;
  childState.noopSystemCall = false;
  childState.onPreExitEvent = false;
  childState.origExfs = this->origExfs;
  childState.origRdfs = this->origRdfs;
  childState.origWrfs = this->origWrfs;
  childState.originalArg1 = 0;
  childState.originalArg2 = 0;
  childState.originalArg3 = 0;
  childState.originalArg4 = 0;
  childState.originalArg5 = 0;
  childState.originalArg6 = 0;
  childState.rdfsNotNull = false;
  childState.regSaver = this->regSaver;
  childState.requestedSignalHandler = this->requestedSignalHandler;
  childState.requestedSignalToHandle = this->requestedSignalToHandle;
  childState.signalInjected = false;
  childState.timerCreateTimers = this->timerCreateTimers;
  childState.totalBytes = this->totalBytes;
  childState.traceePid = childPid;
  childState.userDefinedTimeout = false;
  childState.wait4Blocking = false;

  childState.pipe_read_fds = this->pipe_read_fds;
  childState.pipe_write_fds = this->pipe_write_fds;

  childState.futex_waiters = this->futex_waiters;

  return childState;
}
