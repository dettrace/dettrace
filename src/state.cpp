#include "state.hpp"

state::state(
    pid_t traceePid,
    int debugLevel,
    unsigned long epoch,
    unsigned long clock_step)
    : clock(epoch * state::MICRO_SECS_PER_SEC),
      epoch(epoch),
      clock_step(clock_step),
      fdStatus(new unordered_map<int, descriptorType>),
      traceePid(traceePid),
      signalToDeliver(0),
      mmapMemory(2048),
      debugLevel(debugLevel) {
  currentSignalHandlers =
      std::make_shared<unordered_map<int, enum sighandler_type>>();
  timerCreateTimers = std::make_shared<unordered_map<timerID_t, timerInfo>>();
  remote_sockfds = std::make_shared<unordered_set<int>>();
  timerfds = std::make_shared<unordered_map<int, struct itimerspec>>();
  signalfds = std::make_shared<unordered_set<int>>();

  poll_retry_count = 0;
  poll_retry_maximum = LONG_MAX;

  return;
}

void state::setFdStatus(int fd, descriptorType dt) {
  (*fdStatus.get())[fd] = dt;
}

descriptorType state::getFdStatus(int fd) { return fdStatus.get()->at(fd); }

int state::countFdStatus(int fd) { return fdStatus.get()->count(fd); }

state state::forked(pid_t childPid) const {
  state childState(childPid, this->debugLevel, this->epoch, this->clock_step);
  childState.CPUIDTrapSet = this->CPUIDTrapSet;
  childState.currentSignalHandlers =
      make_shared<unordered_map<int, enum sighandler_type>>(
          *(this->currentSignalHandlers));
  childState.dirEntries = this->dirEntries;

  childState.exfsNotNull = this->exfsNotNull;
  childState.rdfsNotNull = this->rdfsNotNull;
  childState.wrfsNotNull = this->wrfsNotNull;

  childState.fdStatus =
      make_shared<unordered_map<int, descriptorType>>(*(this->fdStatus));
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
  childState.timerCreateTimers =
      make_shared<unordered_map<timerID_t, timerInfo>>(
          *(this->timerCreateTimers));
  childState.totalBytes = this->totalBytes;
  childState.traceePid = childPid;
  childState.userDefinedTimeout = false;
  childState.wait4Blocking = false;

  childState.poll_retry_count = 0;
  childState.poll_retry_maximum = LONG_MAX;

  childState.remote_sockfds =
      make_shared<unordered_set<int>>(*(this->remote_sockfds));
  childState.timerfds =
      make_shared<unordered_map<int, struct itimerspec>>(*(this->timerfds));
  childState.signalfds = make_shared<unordered_set<int>>(*(this->signalfds));
  childState.clock = this->epoch * state::MICRO_SECS_PER_SEC;
  return childState;
}

state state::cloned(pid_t childPid) const {
  state childState(childPid, this->debugLevel, this->epoch, this->clock_step);
  childState.CPUIDTrapSet = this->CPUIDTrapSet;
  childState.currentSignalHandlers = this->currentSignalHandlers;
  childState.dirEntries = this->dirEntries;

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

  childState.poll_retry_count = 0;
  childState.poll_retry_maximum = LONG_MAX;

  childState.remote_sockfds = this->remote_sockfds;
  childState.timerfds = this->timerfds;
  childState.signalfds = this->signalfds;
  childState.clock = this->epoch * state::MICRO_SECS_PER_SEC;
  return childState;
}
