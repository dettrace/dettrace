#include <sys/ptrace.h>
#include <sys/reg.h>     /* For constants ORIG_EAX, etc */
#include <sys/syscall.h>    /* For SYS_write, etc */
#include <sys/types.h>
#include <sys/user.h>
#include <sys/vfs.h>
#include <sys/wait.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <getopt.h>


#include <stdint.h>
#include <cstdlib>
#include <stdio.h>
#include <cstdio> // for perror
#include <cstring> // for strlen
#include <sys/stat.h>
#include <fcntl.h>
#include <stdarg.h>

#include <iostream>
#include <tuple>
#include <thread>

#include "logger.hpp"
#include "valueMapper.hpp"
#include "systemCallList.hpp"
#include "systemCall.hpp"
#include "dettraceSystemCall.hpp"
#include "util.hpp"
#include "state.hpp"
#include "ptracer.hpp"

/**
 * Useful link for understanding ptrace as it works with execve.
 * https://stackoverflow.com/questions/7514837/why-does
 * https://stackoverflow.com/questions/47006441/ptrace-catching-many-traps-for-execve/47039345#47039345
 */

using namespace std;
// =======================================================================================

pair<int, int> parseProgramArguments(int argc, char* argv[]);
void runTracee(int optIndex, int argc, char** argv);
void runTracer(int debugLevel, pid_t childPid);
ptraceEvent getNextEvent(pid_t currentPid, pid_t& traceesPid, int& status);
unique_ptr<systemCall> getSystemCall(int syscallNumber, string syscallName);
// =======================================================================================
/**
 * Given a program through the command line, spawn a child thread, call PTRACEME and exec
 * the given program. The parent will use ptrace to intercept and determinize the through
 * system call interception.
 */
int main(int argc, char** argv){
  pid_t pid = fork();

  int optIndex, debugLevel;
  tie(optIndex, debugLevel) = parseProgramArguments(argc, argv);
  // Child.
  if(pid == 0){
    runTracee(optIndex, argc, argv);
  }else{
    runTracer(debugLevel, pid);
  }
  return 0;
}
// =======================================================================================
/**
 * Child will become the process the user wishes to through call to execve.
 */
void runTracee(int optIndex, int argc, char** argv){
  ptrace(PTRACE_TRACEME, 0, NULL, NULL);

  // +1 for exectuable's name, +1 for NULL at the end.
  int newArgc = argc - optIndex + 1 + 1;
  char* traceeCommand[newArgc];

  memcpy(traceeCommand, & argv[optIndex], newArgc * sizeof(char*));
  traceeCommand[newArgc - 1] = NULL;

  // Stop ourselves until the tracer is ready. This ensures the tracer has time to get set
  //up.
  raise(SIGSTOP);
  int val = execvp(traceeCommand[0], traceeCommand);
  if(val == -1){
    throw runtime_error("Unable to exec your program. Reason\n" +
			string { strerror(errno) });
  }

  return;
}
// =======================================================================================
/**
 * Parent is the tracer. Trace child by intercepting all system call and signals child
 * produces.
 * TODO: One tracer may trace multiple child threads. We will probably have a single central
 * tracer tracing multiple threads or processes, they can be differentiated based on the pid
 * or tid (thread id).
 */
void runTracer(int debugLevel, pid_t startingPid){
  // Logger to write all messages to.
  logger log {stderr, debugLevel};

  // TODO: Add a global state?

  // State represents all state we wish to maintain between subsequent system calls, e.g.
  // vpid mappings, logical time, etc.
  // Since we may have multiple processes and threads, we hold a state per pid. TODO:
  // do different threads have the same pid but different tid? I think so, tid might
  // be better.
  map<pid_t, state> states;
  // Set state for first process.
  states.emplace(startingPid, state {log, startingPid});

  // Explicitly add the mapping between vPid <-> rPid (realPid).
  // TODO: Fix!
  // states[startingPid].pidMap.addEntryValue(startingPid);

  // Needed to tell ptrace to continue process from last event.
  pid_t lastPid = startingPid;

  // Initialized in pre-system call event, remains valid all the way until post-system
  // call event. This saves us having to refetch the system call on the post-systemcall
  // stop.
  unique_ptr<systemCall> systemcall;

  // Wait for first process to be ready! First process is special and we must set
  // the options ourselves. Thereafter, ptracer::setOptions will handle this for new
  // process'.
  ptracer tracer { startingPid };
  ptracer::setOptions(startingPid);

  // Loop to iterate over all events (signals, system calls, etc) that ptrace catches
  // we skip the ones we don't care about.
  while(states.size() != 0){
    pid_t traceesPid;
    int status;

    ptraceEvent ret = getNextEvent(lastPid, traceesPid, status);
    lastPid = traceesPid;

    // We have never seen this pid before. Add it to our table of states.
    if(states.count(traceesPid) == 0){
      log.writeToLog(Importance::info, "Added process [%d] to states map.", traceesPid);
      states.emplace(traceesPid, state {log, traceesPid} );
      // First time seeing this process set ptrace options.
      ptracer::setOptions(traceesPid);
    }

    state& currState = states.at(traceesPid);

    // This process is done.
    if(ret == ptraceEvent::exit){
      // Pop entry from map.
      states.erase(traceesPid);
      continue;
    }

    if(ret == ptraceEvent::syscall){
      // Update register information. TODO: Right now we update this information on every
      // exit and entrance, as an optimization we might not want to...
      // This is necessary for all "pre system calls" to get the correct sys call number.
      tracer.updateState(traceesPid);

      // pre-exit to system call.
      if(currState.syscallStopState == syscallState::pre){
	log.writeToLog(Importance::info, "Ptrace syscall-pre!\n");
	currState.syscallStopState = syscallState::post;

	int syscallNumber = tracer.getSystemCallNumber();
	string syscallName = systemCallMappings[syscallNumber];

	// No idea what this system call is! error out.
	if(syscallNumber > 0 && syscallNumber > SYSTEM_CALL_COUNT){
	  throw runtime_error("Unkown system call number: " +  to_string(syscallNumber));
	}

	log.writeToLog(Importance::info,"Intercepted system call #%d: %s\n",
		       syscallNumber, syscallName.c_str());

	systemcall = getSystemCall(syscallNumber, syscallName);

	// Tick clock once per syscall pre-post pair. Notice we don't tick on every event
	// as signals are asynchronous events.
	currState.clock++;
	log.setPadding();

	currState.doSystemcall = systemcall->handleDetPre(currState, tracer);
	continue;
      }
      // Post system call exit.
      else{
	log.writeToLog(Importance::info, "Ptrace syscall-post!\n");
	currState.syscallStopState = syscallState::pre;

	// System call was done in the last iteration.
	log.writeToLog(Importance::info,"Syscall returned with value: %d\n",
		       tracer.getReturnValue());

	systemcall->handleDetPost(currState, tracer);
	log.unsetPadding();

	continue;
      }
    }

    // We have encountered a call to fork, vfork, clone. Spawn a new thread that
    // will trace that new process.
    if(ret == ptraceEvent::fork){
      log.writeToLog(Importance::inter, "Caught fork event!\n");
      pid_t newProcess = (pid_t) tracer.getEventMessage();
      log.writeToLog(Importance::info, "Starting new tracer thread for tracee: %d\n",
		     newProcess);
      // Call this function recursively in another thread. Pretty neat :o
      // thread t(ptraceParent, debugLevel, newProcess);
      // TODO: Eventually we might multiplex the processes. For now, let child
      // run to completion.
      log.writeToLog(Importance::info, "Parent tracer waiting for thread to finish...\n");
      // t.join();
      log.writeToLog(Importance::info, "Tracer thread done!\n");
    }

    if(ret == ptraceEvent::clone){
      // Nothing to do for now...
      log.writeToLog(Importance::inter, "Caught clone event!\n");
      continue;
    }

    if(ret == ptraceEvent::exec){
      // Nothing to do for now... New process is already automatically ptraced by
      // our tracer.
      log.writeToLog(Importance::inter, "Caught execve!\n");
      continue;
    }

    if(ret == ptraceEvent::signal){
      // Nothing for now. Kelly's code will go here.
      log.writeToLog(Importance::inter, "Tracer: Received signal: %d\n", WSTOPSIG(status));
      continue;
    }

    throw runtime_error("Uknown return value for ptracer::getNextEvent()\n");
  }

  return;
}
// =======================================================================================
/**
 * Catch next event from any process that we are tracing. Return the event type as well
 * as the pid for the process that created this event, also set the status.
 * @param currentPid: the pid of the previously intercepted process. If this is the first
 * time calling, it is the original process to trace.
 * @param traceesPid[out]: pid of the process we just intercepted.
 * @param status[out]: status retured by waitpid.
 */
ptraceEvent getNextEvent(pid_t currentPid, pid_t& traceesPid, int& status){
  // Tell the process that we just intercepted an event for to continue, with us tracking
  // it's system calls. If this is the first time this function is called, it will be the
  // starting process. Which we expect to be in a waiting state.
  ptracer::doPtrace(PTRACE_SYSCALL, currentPid, 0, 0);

  // Intercept any system call.
  traceesPid = waitpid(-1, &status, 0);

  // Check if tracee has exited.
  if (WIFEXITED(status)){
    return ptraceEvent::exit;
  }

  // Condition for PTRACE_O_TRACEEXEC
  if( ptracer::isPtraceEvent(status, PTRACE_EVENT_EXEC) ){
    return ptraceEvent::exec;
  }

  // Condition for PTRACE_O_TRACECLONE
  if( ptracer::isPtraceEvent(status, PTRACE_EVENT_CLONE) ){
    return ptraceEvent::clone;
  }

  // Even though fork() is clone under the hood, any time that clone is used with
  // SIGCHLD, ptrace calls that event a fork *sigh*.
  // Also requires PTRACE_O_FORK fly.
  if( ptracer::isPtraceEvent(status, PTRACE_EVENT_FORK) ){
    return ptraceEvent::fork;
  }

  // This is a stop caused by a system call exit-pre/exit-post.
  // Check if WIFSTOPPED return true,
  // if yes, compare signal number to SIGTRAP | 0x80 (see ptrace(2)).
  if(WIFSTOPPED(status) && (WSTOPSIG(status) == (SIGTRAP | 0x80)) ){
    return ptraceEvent::syscall;
  }

  // TODO? ADD WIFSTOPPED check.
  return ptraceEvent::signal;
}
// =======================================================================================
/**
 * index is the first index in the argv array containing a non option.
 * @return (index, debugLevel)
 */
pair<int, int> parseProgramArguments(int argc, char* argv[]){
  string usageMsg = "./detTrace [--debug <debugLevel> | --help] ./exe [exeCmdArgs]";
  int debugLevel = 0;
  string exePlusArgs;

  // Command line options for our program.
  static struct option programOptions[] = {
    {"debug", required_argument, 0, 'd'},
    {"help",  no_argument,       0, 'h'},
    {0,       0,                 0, 0}    // Last must be filled with 0's.
  };

  while(true){
    int optionIdx = 0;
    // "+" means only parse until we hit the first non option character.
    // Otherwise something like "bin/detbox ls -ahl" would not work as getopt would
    // try to parse "-ahl".
    int returnVal = getopt_long(argc, argv, "+h", programOptions, &optionIdx);
    // We're done!
    if(returnVal == -1){ break; }

    switch(returnVal){
      // Debug flag.
    case 'd':
      debugLevel = parseNum(optarg);
      if(debugLevel < 0 || debugLevel > 5){
        throw runtime_error("Debug level must be between [0,5].");
      }
      break;
      // Help message.
    case 'h':
      fprintf(stderr, "%s\n", usageMsg.c_str());
      exit(1);
    case '?':
      throw runtime_error("Invalid option passed to detTrace!");
    }

  }
  // User did not pass exe arguments:
  if(argv[optind] == NULL){
    fprintf(stderr, "Missing arguments to dettrace!\n");
    fprintf(stderr, "%s\n", usageMsg.c_str());
    exit(1);
  }

  return make_pair(optind, debugLevel);
}
// =======================================================================================
/**
 * Return the system call we currently caught from the tracer.
 * Notice we are forced to use a pointer to get virtual dispatch.
 */
unique_ptr<systemCall> getSystemCall(int syscallNumber, string syscallName){
  switch(syscallNumber){
  case SYS_access:
    return make_unique<accessSystemCall>(syscallNumber, syscallName);
  case SYS_arch_prctl:
    return make_unique<arch_prctlSystemCall>(syscallNumber, syscallName);
  case SYS_brk:
    return make_unique<brkSystemCall>(syscallNumber, syscallName);
  case SYS_clone:
    return make_unique<cloneSystemCall>(syscallNumber, syscallName);
  case SYS_close:
    return make_unique<closeSystemCall>(syscallNumber, syscallName);
  case SYS_dup2:
    return make_unique<dup2SystemCall>(syscallNumber, syscallName);
  case SYS_execve:
    return make_unique<execveSystemCall>(syscallNumber, syscallName);
  case SYS_exit_group:
    return make_unique<exit_groupSystemCall>(syscallNumber, syscallName);
  case SYS_fstat:
    return make_unique<fstatSystemCall>(syscallNumber, syscallName);
  case SYS_fstatfs:
    return make_unique<fstatfsSystemCall>(syscallNumber, syscallName);
  case SYS_getdents:
    return make_unique<getdentsSystemCall>(syscallNumber, syscallName);
  case SYS_getpid:
    return make_unique<getpidSystemCall>(syscallNumber, syscallName);
  case SYS_ioctl:
    return make_unique<ioctlSystemCall>(syscallNumber, syscallName);
  case SYS_munmap:
    return make_unique<munmapSystemCall>(syscallNumber, syscallName);
  case SYS_mmap:
    return make_unique<mmapSystemCall>(syscallNumber, syscallName);
  case SYS_mprotect:
    return make_unique<mprotectSystemCall>(syscallNumber, syscallName);
  case SYS_open:
    return make_unique<openSystemCall>(syscallNumber, syscallName);
  case SYS_openat:
    return make_unique<openatSystemCall>(syscallNumber, syscallName);
  case SYS_prlimit64:
    return make_unique<prlimit64SystemCall>(syscallNumber, syscallName);
  case SYS_read:
    return make_unique<readSystemCall>(syscallNumber, syscallName);
  case SYS_rt_sigprocmask:
    return make_unique<rt_sigprocmaskSystemCall>(syscallNumber, syscallName);
  case SYS_rt_sigaction:
    return make_unique<rt_sigactionSystemCall>(syscallNumber, syscallName);
  case SYS_set_robust_list:
    return make_unique<set_robust_listSystemCall>(syscallNumber, syscallName);
  case SYS_set_tid_address:
    return make_unique<set_tid_addressSystemCall>(syscallNumber, syscallName);
  case SYS_sigaltstack:
    return make_unique<sigaltstackSystemCall>(syscallNumber, syscallName);
  case SYS_statfs:
    return make_unique<statfsSystemCall>(syscallNumber, syscallName);
  case SYS_time:
    return make_unique<timeSystemCall>(syscallNumber, syscallName);
  case SYS_utimensat:
    return make_unique<utimensatSystemCall>(syscallNumber, syscallName);
  case SYS_write:
    return make_unique<writeSystemCall>(syscallNumber, syscallName);
  }

  // Generic system call. Throws error.
  return make_unique<systemCall>(syscallNumber, syscallName);
}
