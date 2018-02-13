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
#include <sched.h>

#include "logger.hpp"
#include "valueMapper.hpp"
#include "systemCallList.hpp"
#include "systemCall.hpp"
#include "dettraceSystemCall.hpp"
#include "util.hpp"
#include "state.hpp"
#include "ptracer.hpp"
#include "execution.hpp"

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
  int optIndex, debugLevel;
  tie(optIndex, debugLevel) = parseProgramArguments(argc, argv);

  // Set up pid namespace.
  // int ret = unshare(CLONE_NEWUSER);
  // if(ret == -1){
    // printf("Unable to unshare new user: %s\n", strerror(errno));
    // return 1;
  // }

  // ret = unshare(CLONE_NEWPID);
  // if(ret == -1){
    // printf("Unable to unshare new pid: %s\n", strerror(errno));
    // return 1;
  // }

  pid_t pid = fork();
  if(pid == -1){
    printf("Fork failed. Reason: %s\n", strerror(errno));
    return 1;
  }

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
 * produces. This process will take care of running children deterministically and
 * sequentially.
 *
 */
void runTracer(int debugLevel, pid_t startingPid){
  execution exe {debugLevel, startingPid};
  exe.runProgram();

  return;
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

