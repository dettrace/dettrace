#include <sys/personality.h>
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
#include <libgen.h>
#include <sys/mount.h>

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
int doWithCheck(int returnValue, string errorMessage);
pair<int, int> parseProgramArguments(int argc, char* argv[]);
void runTracee(int optIndex, int argc, char** argv);
void runTracer(int debugLevel, pid_t childPid);
ptraceEvent getNextEvent(pid_t currentPid, pid_t& traceesPid, int& status);
unique_ptr<systemCall> getSystemCall(int syscallNumber, string syscallName);
void mountDir(string source, string target);
void setUpContainer(string pathToExe);
// =======================================================================================
/**
 * Given a program through the command line, spawn a child thread, call PTRACEME and exec
 * the given program. The parent will use ptrace to intercept and determinize the through
 * system call interception.
 */
int main(int argc, char** argv){
  int optIndex, debugLevel;
  tie(optIndex, debugLevel) = parseProgramArguments(argc, argv);

  // Set up new user namespace. This is needed as we will have root access withing
  // our own user namespace. Other namepspace commands require CAP_SYS_ADMIN to work.
  // Namespaces must must be done before fork. As changes don't apply until after
  // fork, to all child processes.
  doWithCheck(unshare(CLONE_NEWUSER| // Our own user namespace.
		      CLONE_NEWPID | // Our own pid namespace.
		      CLONE_NEWNS),  // Our own mount namespace
	      "Unable to create namespaces");

  pid_t pid = doWithCheck(fork(), "Failed to fork child");

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
  // Find absolute path to our build directory relative to the dettrace binary.
  char argv0[strlen(argv[0])];
  strcpy(argv0, argv[0]); // Use a copy since dirname may mutate contents.
  string pathToExe{ dirname(argv0) };

  setUpContainer(pathToExe);

  // Perform execve based on user command.
  ptrace(PTRACE_TRACEME, 0, NULL, NULL);

  // +1 for exectuable's name, +1 for NULL at the end.
  int newArgc = argc - optIndex + 1 + 1;
  char* traceeCommand[newArgc];

  memcpy(traceeCommand, & argv[optIndex], newArgc * sizeof(char*));
  traceeCommand[newArgc - 1] = NULL;

  // Create minimal environment.
  // Note: gcc needs to be somewhere along PATH or it gets very confused, see
  // https://github.com/upenn-acg/detTrace/issues/23
  string ldpreload {"LD_PRELOAD=/dettrace/lib/libdet.so"};
  char *const envs[] = {(char* const)ldpreload.c_str(),
                        (char* const)"PATH=/usr/bin/:/bin",
                        NULL};

  // Stop ourselves until the tracer is ready. This ensures the tracer has time to get set
  //up.
  raise(SIGSTOP);
  // execvpe() duplicates the actions of the shell in searching  for  an executable file
  // if the specified filename does not contain a slash (/) character.

  int val = execvpe(traceeCommand[0], traceeCommand, envs);
  if(val == -1){
    cerr << "Unable to exec your program. Reason:\n  " << string { strerror(errno) } << endl;
    cerr << "Ending tracer with SIGABTR signal." << endl;

    // Parent is waiting for us to exec so it can trace traceeCommand, this isn't going
    // to happen. End parent with signal.
    pid_t ppid = getppid();
    syscall(SYS_tgkill, ppid, ppid, SIGABRT);
  }


  return;
}
// =======================================================================================
/**
 *
 * Jail our container under /root/. Notice this relies on a certain directory structure
 * for our jail:
 *
 * DetTrace ) ls root/
 * bin/  build/  dettrace/  lib/  lib64/  proc/
 *
 */
void setUpContainer(string pathToExe){
  // (Assumed to be in /bin/dettrace where / is our project root.
  string buildDir { pathToExe + "/../root/build/" };

  // 1. First we mount cwd in our /root/build/ directory.
  char* cwdPtr = get_current_dir_name();
  mountDir(string { cwdPtr }, buildDir);
  free(cwdPtr);

  // 2. Move over to our build directory! This will make code cleaner as all logic is
  // relative this dir.
  doWithCheck(chdir(buildDir.c_str()), "Unable to chdir");

  // Bind mount our directories.
  mountDir("/bin/", "../bin/");
  mountDir("/usr/", "../usr/");
  mountDir("/lib/", "../lib/");
  mountDir("/lib64/", "../lib64/");
  // Mount our dettrace/bin and dettrace/lib folders.
  mountDir("../../bin/", "../dettrace/bin");
  mountDir("../../lib/", "../dettrace/lib");

  // Proc is special, we mount a new proc dir.
  doWithCheck(mount("/proc", "../proc/", "proc", MS_MGC_VAL, nullptr),
	      "Mounting proc failed");

  // Chroot our process!
  doWithCheck(chroot("../"), "Failed to chroot");

  // Disable ASLR for our child
  doWithCheck(personality(PER_LINUX | ADDR_NO_RANDOMIZE), "Unable to disable ASLR");
}
// =======================================================================================
/**
 * Parent is the tracer. Trace child by intercepting all system call and signals child
 * produces. This process will take care of running children deterministically and
 * sequentially.
 *
 */
void runTracer(int debugLevel, pid_t startingPid){
  // Init tracer and execution context.
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
/**
 * Call clib function that returns an integer and sets errno with automatic checking
 * and exiting on -1. Returns returnValue on success.
 *
 * Example:
 * doWithCheck(mount(cwd, pathToBuild.c_str(), nullptr, MS_BIND, nullptr),
 *             "Unable to bind mount cwd");
 */
int doWithCheck(int returnValue, string errorMessage){
  string reason = strerror(errno);
  if(returnValue == -1){
    cerr << errorMessage + ":\n  " + reason << endl;
    exit(1);
  }

  return returnValue;
}
// =======================================================================================
/**
 * Wrapper around mount with strings.
 */
void mountDir(string source, string target){
  doWithCheck(mount(source.c_str(), target.c_str(), nullptr, MS_BIND, nullptr),
	      "Unable to bind mount: " + source + " to " + target);
}

// =======================================================================================

