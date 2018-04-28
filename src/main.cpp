#include <sys/personality.h>
#include <sys/ptrace.h>
#include <sys/reg.h>     /* For constants ORIG_EAX, etc */
#include <sys/syscall.h>    /* For SYS_write, etc */
#include <sys/types.h>
#include <sys/user.h>
#include <sys/vfs.h>
#include <sys/wait.h>
#include <string.h>
#include <getopt.h>

#include <sched.h>
#include <unistd.h>
#include <sys/wait.h>
#include <signal.h>
#include <fcntl.h>
#include <limits.h>
#include <errno.h>
#include <stdint.h>
#include <cstdlib>
#include <stdio.h>
#include <sys/stat.h>
#include <stdarg.h>
#include <libgen.h>
#include <sys/mount.h>

#include <iostream>
#include <tuple>

#include "logger.hpp"
#include "systemCallList.hpp"
#include "systemCall.hpp"
#include "dettraceSystemCall.hpp"
#include "util.hpp"
#include "state.hpp"
#include "ptracer.hpp"
#include "execution.hpp"
#include "ptracer.hpp"
#include "seccomp.hpp"

#include <seccomp.h>

/**
 * Useful link for understanding ptrace as it works with execve.
 * https://stackoverflow.com/questions/7514837/why-does
 * https://stackoverflow.com/questions/47006441/ptrace-catching-many-traps-for-execve/47039345#47039345
 */

using namespace std;
// =======================================================================================
tuple<int, int, string, bool> parseProgramArguments(int argc, char* argv[]);
int runTracee(void* args);
void runTracer(int debugLevel, pid_t childPid);
ptraceEvent getNextEvent(pid_t currentPid, pid_t& traceesPid, int& status);
unique_ptr<systemCall> getSystemCall(int syscallNumber, string syscallName);
void mountDir(string source, string target);
void setUpContainer(string pathToExe, string pathToChoort, bool userDefinedChroot);
void mkdirIfNotExist(string dir);

// See user_namespaces(7)
static void update_map(char *mapping, char *map_file);
static void proc_setgroups_write(pid_t child_pid, const char *str);
// =======================================================================================
struct childArgs{
  int optIndex;
  int argc;
  char** argv;
  int debugLevel;
  string path;
  bool useContainer;
};
// =======================================================================================
/**
 * Given a program through the command line, spawn a child thread, call PTRACEME and exec
 * the given program. The parent will use ptrace to intercept and determinize the through
 * system call interception.
 */
int main(int argc, char** argv){
  int optIndex, debugLevel;
  string path; bool useContainer;
  tie(optIndex, debugLevel, path, useContainer) = parseProgramArguments(argc, argv);

  // Check for debug enviornment variable.
  char* debugEnvvar = secure_getenv("dettraceDebug");
  if(debugEnvvar != nullptr){
    string str { debugEnvvar };
    try{
      debugLevel = stoi(str);
    }catch (...){
      throw runtime_error("Invalid integer: " + str);
    }


    if(debugLevel < 0 || debugLevel > 5){
      throw runtime_error("Debug level must be between [0,5].");
    }
  }

  // Set up new user namespace. This is needed as we will have root access withing
  // our own user namespace. Other namepspace commands require CAP_SYS_ADMIN to work.
  // Namespaces must must be done before fork. As changes don't apply until after
  // fork, to all child processes.
  const int STACK_SIZE (1024 * 1024);
  static char child_stack[STACK_SIZE];    /* Space for child's stack */

  struct childArgs args;
  args.optIndex = optIndex;
  args.argc = argc;
  args.argv = argv;
  args.debugLevel = debugLevel;
  args.path = path;
  args.useContainer = useContainer;

  pid_t pid = doWithCheck(clone(runTracee, child_stack + STACK_SIZE,
				SIGCHLD |      // Alert parent of child signals?
				CLONE_NEWUSER| // Our own user namespace.
				CLONE_NEWPID | // Our own pid namespace.
				CLONE_NEWNS,  // Our own mount namespace
				(void*) &args),
			  "clone");

  // Parent falls through.
  runTracer(debugLevel, pid);

  return 0;
}
// =======================================================================================
/**
 * Child will become the process the user wishes through call to execvpe.
 */
int runTracee(void* voidArgs){
  childArgs args = *((childArgs*)voidArgs);
  int optIndex = args.optIndex;
  int argc = args.argc;
  char** argv = args.argv;
  int debugLevel = args.debugLevel;
  string path = args.path;
  bool useContainer = args.useContainer;

  // Find absolute path to our build directory relative to the dettrace binary.
  char argv0[strlen(argv[0])];
  strcpy(argv0, argv[0]); // Use a copy since dirname may mutate contents.
  string pathToExe{ dirname(argv0) };

  if(useContainer){
    if(path != ""){
      setUpContainer(pathToExe, path, true);
    }else{
      const string defaultRoot = "/../root/";
      setUpContainer(pathToExe, pathToExe + defaultRoot, false);
    }
  }

  // Perform execve based on user command.
  ptracer::doPtrace(PTRACE_TRACEME, 0, NULL, NULL);

  // +1 for exectuable's name, +1 for NULL at the end.
  int newArgc = argc - optIndex + 1 + 1;
  char* traceeCommand[newArgc];

  memcpy(traceeCommand, & argv[optIndex], newArgc * sizeof(char*));
  traceeCommand[newArgc - 1] = NULL;

  // Create minimal environment.
  // Note: gcc needs to be somewhere along PATH or it gets very confused, see
  // https://github.com/upenn-acg/detTrace/issues/23

  string ldpreload {"LD_PRELOAD=/dettrace/lib/libdet.so"};
  if(! useContainer){
    ldpreload = "LD_PRELOAD=" + pathToExe + "/../lib/libdet.so";
  }
  char *const envs[] = {(char* const)ldpreload.c_str(),
                        (char* const)"PATH=/usr/bin/:/bin",
                        NULL};

  // Set up seccomp + bpf filters using libseccomp.
  // Default action to take when no rule applies to system call. We send a PTRACE_SECCOMP
  // event message to the tracer with a unique data: INT16_MAX
  seccomp myFilter { debugLevel };

  // Stop ourselves until the tracer is ready. This ensures the tracer has time to get set
  //up.
  raise(SIGSTOP);

  myFilter.loadFilterToKernel();

  // execvpe() duplicates the actions of the shell in searching  for  an executable file
  // if the specified filename does not contain a slash (/) character.
  int val = execvpe(traceeCommand[0], traceeCommand, envs);
  if(val == -1){
    if(errno == ENOENT){
      cerr << "Unable to exec your program. No such exectuable found\n" << endl;
      cerr << "This program may not exist inside the choort." << endl;
      cerr << "Only programs in bin/ or in this directory tree are mounted." << endl;
    }
    cerr << "Unable to exec your program. Reason:\n  " << string { strerror(errno) } << endl;
    cerr << "Ending tracer with SIGABTR signal." << endl;

    // Parent is waiting for us to exec so it can trace traceeCommand, this isn't going
    // to happen. End parent with signal.
    pid_t ppid = getppid();
    syscall(SYS_tgkill, ppid, ppid, SIGABRT);
  }

  return 0;
}
// =======================================================================================
/**
 *
 * Jail our container under chootPath.
 *
 */
void setUpContainer(string pathToExe, string pathToChoort , bool userDefinedChroot){
  string buildDir = pathToChoort + "/build/";

  mkdirIfNotExist(buildDir);
  mkdirIfNotExist(pathToChoort + "/dettrace/"); // /dettrace directory
  mkdirIfNotExist(pathToChoort + "/dettrace/lib/"); // /dettrace/lib directory
  mkdirIfNotExist(pathToChoort + "/dettrace/bin/"); // /dettrace/bin directory

  // 1. First we mount cwd in our /build/ directory.
  char* cwdPtr = get_current_dir_name();
  mountDir(string { cwdPtr }, buildDir);
  free(cwdPtr);

  // Mount our dettrace/bin and dettrace/lib folders. The destination is relative
  // as we have already moved into our /bui
  mountDir(pathToExe + "/../bin/", pathToChoort + "/dettrace/bin/");
  mountDir(pathToExe + "/../lib/", pathToChoort + "/dettrace/lib/");

  // 2. Move over to our build directory! This will make code cleaner as all logic is
  // relative this dir.
  doWithCheck(chdir(buildDir.c_str()), "Unable to chdir");

  // Bind mount our directories.
  if(!userDefinedChroot){
    mountDir("/bin/", "../bin/");
    mountDir("/usr/", "../usr/");
    mountDir("/lib/", "../lib/");
    mountDir("/lib64/", "../lib64/");
    // Mount dev/null
    mountDir("/dev/null", "../dev/null");
    // Ld cache
    mountDir("/etc/ld.so.cache", "../etc/ld.so.cache");
  }

  // Proc is special, we mount a new proc dir.
  char* none = "none"; // Hack so valgrind doesn't complain.
  doWithCheck(mount("/proc", "../proc/", "proc", MS_MGC_VAL, none),
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
  // This is modified code from user_namespaces(7)

  /* Update the UID and GID maps in the child */
  char map_path[PATH_MAX];
  const int MAP_BUF_SIZE = 100;
  char map_buf[MAP_BUF_SIZE];
  char* uid_map;
  char* gid_map;
  snprintf(map_path, PATH_MAX, "/proc/%ld/uid_map", (long) startingPid);

  snprintf(map_buf, MAP_BUF_SIZE, "0 %ld 1", (long) getuid());
  uid_map = map_buf;

  update_map(uid_map, map_path);

  // Set GID Map
  string deny = "deny";
  proc_setgroups_write(startingPid, deny.c_str());

  snprintf(map_path, PATH_MAX, "/proc/%ld/gid_map", (long) startingPid);
  snprintf(map_buf, MAP_BUF_SIZE, "0 %ld 1", (long) getgid());
  gid_map = map_buf;

  update_map(gid_map, map_path);

  // Init tracer and execution context.
  execution exe {debugLevel, startingPid};
  exe.runProgram();

  return;
}
// =======================================================================================
/**
 * index is the first index in the argv array containing a non option.
 * @param string: Either a user specified chroot path or none.
 * @return (index, debugLevel)
 */
tuple<int, int, string, bool> parseProgramArguments(int argc, char* argv[]){
  string usageMsg =
    "./detTrace [--debug <debugLevel> | --help | --chroot <pathToRoot> | --nocontainer] ./exe [exeCmdArgs]";
  int debugLevel = 0;
  string exePlusArgs;
  string pathToChroot = "";
  bool useContainer = true;

  // Command line options for our program.
  static struct option programOptions[] = {
    {"debug" , required_argument,  0, 'd'},
    {"help"  , no_argument,        0, 'h'},
    {"chroot", required_argument,  0, 'c'},
    {"nocontainer", no_argument, 0, 'n'},
    {0,        0,                  0, 0}    // Last must be filled with 0's.
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
    case 'c':
      pathToChroot = string { optarg };
      // Debug flag.
      break;
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
      // no-container flag, used for testing
    case 'n':
      useContainer = false;
      break;
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

  return make_tuple(optind, debugLevel, pathToChroot, useContainer);
}
// =======================================================================================
/**
 * Wrapper around mount with strings.
 */
void mountDir(string source, string target){
  const char* none = "none"; // Hack so valgrind doesn't complain.
  doWithCheck(mount(source.c_str(), target.c_str(), none, MS_BIND, none),
	      "Unable to bind mount: " + source + " to " + target);
}
// =======================================================================================
static void update_map(char *mapping, char *map_file){
  int fd = open(map_file, O_RDWR);
  if (fd == -1) {
    fprintf(stderr, "ERROR: open %s: %s\n", map_file,
	    strerror(errno));
    exit(EXIT_FAILURE);
  }
  ssize_t map_len = strlen(mapping);
  if (write(fd, mapping, map_len) != map_len) {
    fprintf(stderr, "ERROR: write %s: %s\n", map_file,
	    strerror(errno));
    exit(EXIT_FAILURE);
  }

  close(fd);
}
// =======================================================================================
/* Linux 3.19 made a change in the handling of setgroups(2) and the
   'gid_map' file to address a security issue. The issue allowed
   *unprivileged* users to employ user namespaces in order to drop
   The upshot of the 3.19 changes is that in order to update the
   'gid_maps' file, use of the setgroups() system call in this
   user namespace must first be disabled by writing "deny" to one of
   the /proc/PID/setgroups files for this namespace.  That is the
   purpose of the following function. */
static void proc_setgroups_write(pid_t child_pid, const char *str){
  char setgroups_path[PATH_MAX];
  int fd;

  snprintf(setgroups_path, PATH_MAX, "/proc/%ld/setgroups",
	   (long) child_pid);

  fd = open(setgroups_path, O_RDWR);
  if (fd == -1) {

    /* We may be on a system that doesn't support
       /proc/PID/setgroups. In that case, the file won't exist,
       and the system won't impose the restrictions that Linux 3.19
       added. That's fine: we don't need to do anything in order
       to permit 'gid_map' to be updated.
       However, if the error from open() was something other than
       the ENOENT error that is expected for that case,  let the
       user know. */

    if (errno != ENOENT)
      fprintf(stderr, "ERROR: open %s: %s\n", setgroups_path,
	      strerror(errno));
    return;
  }

  if (write(fd, str, strlen(str)) == -1)
    fprintf(stderr, "ERROR: write %s: %s\n", setgroups_path,
	    strerror(errno));

  close(fd);
}
// =======================================================================================
void mkdirIfNotExist(string dir){
  int result = mkdir(dir.c_str(), ACCESSPERMS);
  if(result == -1){
    // That's okay :)
    if(errno == EEXIST){
      return;
    }else{
      string reason { strerror(errno) };
      throw runtime_error("Unable to make directory: " + dir + "\nReason: " + reason);
    }
  }
  return;
}

// =======================================================================================
