#include <sys/personality.h>
#include <sys/ptrace.h>
#include <sys/reg.h>     /* For constants ORIG_EAX, etc */
#include <sys/syscall.h>    /* For SYS_write, etc */
#include <sys/types.h>
#include <sys/user.h>
#include <sys/vfs.h>
#include <sys/wait.h>
#include <sys/utsname.h>
#include <string.h>
#include <getopt.h>
#include <dirent.h>
#include <sys/prctl.h>

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
#include <sys/prctl.h>
#include <archive.h>

#include <iostream>
#include <tuple>
#include <vector>
#include <cassert>

#include "logger.hpp"
#include "systemCallList.hpp"
#include "dettraceSystemCall.hpp"
#include "util.hpp"
#include "state.hpp"
#include "ptracer.hpp"
#include "execution.hpp"
#include "ptracer.hpp"
#include "seccomp.hpp"

#include <seccomp.h>

#define MAKE_KERNEL_VERSION(x, y, z) ((x) << 16 | (y) << 8 | (z) )

/**
 * Useful link for understanding ptrace as it works with execve.
 * https://stackoverflow.com/questions/7514837/why-does
 * https://stackoverflow.com/questions/47006441/ptrace-catching-many-traps-for-execve/47039345#47039345
 */

using namespace std;

struct programArgs{
  int optIndex;
  int argc;
  char** argv;
  int debugLevel;
  string pathToChroot;
  bool useContainer;
  string workingDir;
  // User is using --chroot flag.
  bool userChroot;
  string pathToExe;
  bool useColor;
  string logFile;
  bool printStatistics;
  bool convertUids;
};
// =======================================================================================
programArgs parseProgramArguments(int argc, char* argv[]);
int runTracee(programArgs args);
int spawnTracerTracee(void* args);
ptraceEvent getNextEvent(pid_t currentPid, pid_t& traceesPid, int& status);

static bool fileExists(string directory);
static void mountDir(string source, string target);
static void setUpContainer(string pathToExe, string pathToChroot, string workingDir, bool userDefinedChroot);
static void mkdirIfNotExist(string dir);
static void createFileIfNotExist(string path);

// See user_namespaces(7)
static void update_map(char* mapping, char* map_file);
static void proc_setgroups_write(pid_t pid, const char* str);

// Default starting value used by our programArgs.
static bool isDefault(string arg);
// =======================================================================================

// Check if using kernel < 4.8.0. Ptrace + seccomp semantics changed in this version.
bool usingOldKernel(){
  struct utsname utsname = {};
  long x, y, z;
  char* r = NULL, *rp = NULL;

  doWithCheck(uname(&utsname), "uname");

  r = utsname.release;
  x = strtoul(r, &rp, 10);
  if (rp == r){
    throw runtime_error("dettrace runtime exception: Problem parsing uname results.\n");
  }
  r = 1 + rp;
  y = strtoul(r, &rp, 10);
  if (rp == r){
    throw runtime_error("dettrace runtime exception: Problem parsing uname results.\n");
  }
  r = 1 + rp;
  z = strtoul(r, &rp, 10);

  return (MAKE_KERNEL_VERSION(x, y, z) < MAKE_KERNEL_VERSION(4, 8, 0) ?
          true : false);
}

const string usageMsg =
  "  Dettrace\n"
  "\n"
  "  A container for dynamic determinism enforcement. Arbitrary programs ran inside\n"
  "  will run deterministically."
  "\n"
  "  ./detTrace [optionalArguments] ./exe [exeCmdArgs]\n"
  "  ./detTrace --help\n"
  "\n"
  "  Optional Arguments:\n"
  "  --debug <debugLevel>\n"
  "    Prints log information based on verbosity, useful to debug dettrace errors.\n"
  "  --working-dir\n"
  "     Specify the working directory that dettrace should use to build, by default\n"
  "     it is the current working directory."
  "  --chroot <pathToRoot>\n"
  "    Specify root to use for chroot (such as one created by debootstrap).\n"
  "  --no-container\n"
  "    Do not use any sort of containerization (May not be deterministic!).\n"
  "  --no-color\n"
  "    Do not use colored output for log. Useful when piping log to a file.\n"
  "  --log\n"
  "    Path to write log to. Defaults to stderr. If writing to a file, the filename\n"
  "    has a unique suffix appended.\n"
  "  --convert-uids Some packages attempt to use UIDs not mapped in our namespace. Catch\n"
  "    this behavior for lchown, chown, fchown, fchowat, and dynamically change the UIDS to\n"
  "    0 (root).\n"
  "  --print-statistics\n"
  "    Print metadata about process that just ran including: number of system call events\n"
  "    read/write retries, rdtsc, rdtscp, cpuid.\n";

/**
 * Given a program through the command line, spawn a child thread, call PTRACEME and exec
 * the given program. The parent will use ptrace to intercept and determinize the through
 * system call interception.
 */
int main(int argc, char** argv){
  programArgs args = parseProgramArguments(argc, argv);

  // Check for debug enviornment variable.
  char* debugEnvvar = secure_getenv("dettraceDebug");
  if(debugEnvvar != nullptr){
    string str { debugEnvvar };
    try{
      args.debugLevel = stoi(str);
    }catch (...){
      throw runtime_error("dettrace runtime exception: Invalid integer: " + str);
    }

    if(args.debugLevel < 0 || args.debugLevel > 5){
      throw runtime_error("dettrace runtime exception: Debug level must be between [0,5].");
    }
  }

  // Set up new user namespace. This is needed as we will have root access withing
  // our own user namespace. Other namepspace commands require CAP_SYS_ADMIN to work.
  // Namespaces must must be done before fork. As changes don't apply until after
  // fork, to all child processes.

  int cloneFlags =
    CLONE_NEWUSER | // Our own user namespace.
    CLONE_NEWPID | // Our own pid namespace.
    CLONE_NEWNS;  // Our own mount namespace

  // our own user namespace. Other namepspace commands require CAP_SYS_ADMIN to work.
  // Namespaces must must be done before fork. As changes don't apply until after
  // fork, to all child processes.
  const int STACK_SIZE (1024 * 1024);
  static char child_stack[STACK_SIZE];    /* Space for child's stack */

  doWithCheck(prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0),
              "Pre-clone prctl error: setting no new privs");

  // Requires SIGCHILD otherwise parent won't be notified of parent exit.
  // We use clone instead of unshare so that the current process does not live in
  // the new user namespace, this is a requirement for writing multiple UIDs into
  // the uid mappings.
  pid_t pid = clone(spawnTracerTracee, child_stack + STACK_SIZE, cloneFlags | SIGCHLD,
                    (void*) &args);
  if(pid == -1){
    string reason = strerror(errno);
    cerr << "clone failed:\n  " + reason << endl;
    return 1;
  }

  // This is modified code from user_namespaces(7)
  // see https://lwn.net/Articles/532593/
  /* Update the UID and GID maps for children in their namespace, notice we do not
     live in that namespace. We use clone instead of unshare to avoid moving us into
     to the namespace. This allows us, in the future, to extend the mappins to other
     uids when running as root (not currently implemented, but notice this cannot be
     done when using unshare.)*/
  char map_path[PATH_MAX];
  const int MAP_BUF_SIZE = 100;
  char map_buf[MAP_BUF_SIZE];
  char* uid_map;
  char* gid_map;

  // Must be done before we unshare namespaces!!!
  uid_t uid = getuid();
  gid_t gid = getgid();

  // Set up container to hostOS UID and GID mappings
  snprintf(map_path, PATH_MAX, "/proc/%d/uid_map", pid);
  snprintf(map_buf, MAP_BUF_SIZE, "0 %ld 1", (long)uid);
  uid_map = map_buf;
  update_map(uid_map, map_path);

  // Set GID Map
  string deny = "deny";
  proc_setgroups_write(pid, deny.c_str());
  snprintf(map_path, PATH_MAX, "/proc/%d/gid_map", pid);
  snprintf(map_buf, MAP_BUF_SIZE, "0 %ld 1", (long)gid);
  gid_map = map_buf;
  update_map(gid_map, map_path);

  int status;
  doWithCheck(waitpid(-1, &status, 0), "cannot wait for child");
}
// =======================================================================================
/**
 * Child will become the process the user wishes through call to execvpe.
 * @arg tempdir: either empty string or tempdir to use, for cpio chroot.
 */
int runTracee(programArgs args){
  int optIndex = args.optIndex;
  int argc = args.argc;
  char** argv = args.argv;
  int debugLevel = args.debugLevel;
  string pathToChroot = args.pathToChroot;
  bool useContainer = args.useContainer;
  string workingDir = args.workingDir;
  string pathToExe = args.pathToExe;

  if(useContainer){
    setUpContainer(pathToExe, pathToChroot, workingDir, args.userChroot);
  }

  doWithCheck(prctl(PR_SET_TSC, PR_TSC_SIGSEGV, 0, 0, 0), "Pre-clone prctl error");
  doWithCheck(prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0), "Pre-clone prctl error: setting no new privs");

  // Perform execve based on user command.
  ptracer::doPtrace(PTRACE_TRACEME, 0, NULL, NULL);

  // +1 for executable's name, +1 for NULL at the end.
  int newArgc = argc - optIndex + 1 + 1;
  char* traceeCommand[newArgc];

  memcpy(traceeCommand, & argv[optIndex], newArgc * sizeof(char*));
  traceeCommand[newArgc - 1] = NULL;

  // Create minimal environment.
  // Note: gcc needs to be somewhere along PATH or it gets very confused, see
  // https://github.com/upenn-acg/detTrace/issues/23

  string ldpreload {"LD_PRELOAD=/dettrace/lib/libdet.so"};
  if(! useContainer){
    // Always use full path when refering to files.
    auto path = pathToExe + "/../lib/libdet.so";
    char* fullpath = realpath(path.c_str(), NULL);
    ldpreload = "LD_PRELOAD=" + string { fullpath };

    free(fullpath);
  }

  char *const envs[] = {(char* const)ldpreload.c_str(),
                        (char* const)"PATH=/usr/bin/:/bin",
                        NULL};

  // Set up seccomp + bpf filters using libseccomp.
  // Default action to take when no rule applies to system call. We send a PTRACE_SECCOMP
  // event message to the tracer with a unique data: INT16_MAX
  seccomp myFilter { debugLevel, args.convertUids };

  // Stop ourselves until the tracer is ready. This ensures the tracer has time to get set
  //up.
  raise(SIGSTOP);

  myFilter.loadFilterToKernel();

  // execvpe() duplicates the actions of the shell in searching  for  an executable file
  // if the specified filename does not contain a slash (/) character.
  int val = execvpe(traceeCommand[0], traceeCommand, envs);
  if(val == -1){
    if(errno == ENOENT){
      cerr << "Unable to exec your program ("
           << traceeCommand[0]
           << "). No such executable found\n" << endl;
      cerr << "This program may not exist inside the chroot." << endl;
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

static int
copy_data(struct archive *ar, struct archive *aw)
{
  int r;
  const void *buff;
  size_t size;
#if ARCHIVE_VERSION_NUMBER >= 3000000
  int64_t offset;
#else
  off_t offset;
#endif

  for (;;) {
    r = archive_read_data_block(ar, &buff, &size, &offset);
    if (r == ARCHIVE_EOF)
      return (ARCHIVE_OK);
    if (r != ARCHIVE_OK)
      return (r);
    r = archive_write_data_block(aw, buff, size, offset);
    if (r != ARCHIVE_OK) {
      printf("archive_write_data_block(): %s",
	   archive_error_string(aw));
      return (r);
    }
  }
}

static void
extract(const char *filename, int do_extract, int flags)
{
  struct archive *a;
  struct archive *ext;
  struct archive_entry *entry;
  int r;

  a = archive_read_new();
  ext = archive_write_disk_new();
  archive_write_disk_set_options(ext, flags);
  /*
   * Note: archive_write_disk_set_standard_lookup() is useful
   * here, but it requires library routines that can add 500k or
   * more to a static executable.
   */
  archive_read_support_format_cpio(a);
  /*
   * On my system, enabling other archive formats adds 20k-30k
   * each.  Enabling gzip decompression adds about 20k.
   * Enabling bzip2 is more expensive because the libbz2 library
   * isn't very well factored.
   */
  if (filename != NULL && strcmp(filename, "-") == 0)
    filename = NULL;
  if ((r = archive_read_open_filename(a, filename, 10240))) {
    fprintf(stderr, "archive_read_open_filename(): %s %d",
	    archive_error_string(a), r);
    exit(1);
  }
  for (;;) {
    r = archive_read_next_header(a, &entry);
    if (r == ARCHIVE_EOF)
      break;
    if (r != ARCHIVE_OK) {
      fprintf(stderr, "archive_read_next_header(): %s %d",
	      archive_error_string(a), 1);
      exit(1);
    }
    if (do_extract) {
      r = archive_write_header(ext, entry);
      if (r != ARCHIVE_OK)
	printf("archive_write_header(): %s",
	       archive_error_string(ext));
      else {
	copy_data(a, ext);
	r = archive_write_finish_entry(ext);
	if (r != ARCHIVE_OK) {
	  fprintf(stderr, "archive_write_finish_entry(): %s %d",
	       archive_error_string(ext), 1);
	  exit(1);
	}
      }

    }
  }
  archive_read_close(a);
  archive_read_free(a);

  archive_write_close(ext);
  archive_write_free(ext);
}

// =======================================================================================
/**
 *
 * populate initramfs into @path
 *
 */
static void populateInitramfs(const char* initramfs, const char* path)
{
  string errmsg = "Failed to change direcotry to ";
  char* oldcwd = get_current_dir_name();
  doWithCheck(chdir(path), errmsg + path);
  extract(initramfs, 1, 0);
  doWithCheck(chdir(oldcwd), errmsg + oldcwd);
  free(oldcwd);
}
// =======================================================================================
// pathToChroot must exist and be located inside the chroot if the user defined their own chroot!
static void checkPaths(string pathToChroot, string workingDir){
    if( !fileExists(workingDir)){
      throw runtime_error("dettrace runtime exception: workingDir: " + workingDir + " does not exits!");
    }

    // Check it is "inside" the userDefinedChroot:
    char* trueChrootC = realpath(pathToChroot.c_str(), nullptr);
    char* trueWorkingDirC = realpath(workingDir.c_str(), nullptr);

    if(trueChrootC == nullptr){
      runtimeError("Unable to realpath for pathToChroot: " + pathToChroot);
    }
    if(trueWorkingDirC == nullptr){
      runtimeError("Unable to realpath for WorkingDir: " + workingDir);
    }

    string trueChroot = string{ trueChrootC };
    string trueWorkingDir = string{ trueWorkingDirC };

    // Check if one string is a prefix of the other, the c++ way.
    // mismatch function: "The behavior is undefined if the second range is shorter than the first range."
    // I <3 C++
    if(trueWorkingDir.length() < trueChroot.length()){
      runtimeError("Working directory specified is not in the specified chroot!");
    }

    auto res = std::mismatch(trueChroot.begin(), trueChroot.end(), trueWorkingDir.begin());
    if (res.first != trueChroot.end()){
      runtimeError("Working directory specified is not in the specified chroot!");
    }

    free(trueChrootC);
    free(trueWorkingDirC);
}
/**
 * Jail our container under chootPath.
 * This directory must exist and be located inside the chroot if the user defined their own chroot!
 */
static void setUpContainer(string pathToExe, string pathToChroot, string workingDir, bool userDefinedChroot){
  if(userDefinedChroot && ! isDefault(workingDir)){
    checkPaths(pathToChroot, workingDir);
  }

  const vector<string> mountDirs =
    {  "/dettrace", "/dettrace/lib", "/dettrace/bin", "/bin", "/usr", "/lib", "/lib64",
       "/dev", "/etc", "/proc", "/build", "/tmp", "/root" };

  if (!userDefinedChroot) {
    char buf[256];
    snprintf(buf, 256, "%s", "/tmp/dtroot.XXXXXX");
    string tempdir = string { mkdtemp(buf) };

    string cpio;
    doWithCheck(mount("none", tempdir.c_str(), "tmpfs", 0, NULL), "mount initramfs");
    cpio = pathToExe + "/../initramfs.cpio";
    char* cpioReal = realpath(cpio.c_str(), NULL);
    if (!cpioReal) {
      fprintf(stderr, "unable to find initramfs: %s\n", cpio.c_str());
      exit(1);
    }
    populateInitramfs(cpioReal, tempdir.c_str());
    free(cpioReal);
    pathToChroot = tempdir;
  }

  string buildDir = pathToChroot + "/build/";
  for(auto dir : mountDirs){
      mkdirIfNotExist(pathToChroot + dir);
  }

  if(isDefault(workingDir)) {
    // We mount our current working directory in our /build/ directory.
    char* cwdPtr = get_current_dir_name();
    mountDir(string { cwdPtr }, buildDir);
    free(cwdPtr);
  }else{
    // User specified working directory besides cwd, use this instead!
    // This directory must exist and be located inside the chroot if the
    // user defined their own chroot!
    mountDir(workingDir, buildDir);
  }

  // Mount our dettrace/bin and dettrace/lib folders.
  mountDir(pathToExe + "/../bin/", pathToChroot + "/dettrace/bin/");
  mountDir(pathToExe + "/../lib/", pathToChroot + "/dettrace/lib/");

  // The user did not specify a chroot env, try to scrape a minimal filesystem from the
  // host OS'.
  if(! userDefinedChroot){
    mountDir("/bin/", pathToChroot + "/bin/");
    mountDir("/usr/", pathToChroot + "/usr/");
    mountDir("/lib/", pathToChroot + "/lib/");
    mountDir("/lib64/", pathToChroot + "/lib64/");
    mountDir("/etc/ld.so.cache", pathToChroot + "/etc/ld.so.cache");
  }

  // Sometimes the chroot won't have a /dev/null, bind mount the host's just in case.
  createFileIfNotExist(pathToChroot + "/dev/null");
  mountDir(pathToExe + "/../root/dev/null", pathToChroot + "/dev/null");
  // We always want to bind mount these directories to replace the host OS or chroot ones.
  createFileIfNotExist(pathToChroot + "/dev/random");
  mountDir(pathToExe + "/../root/dev/random", pathToChroot + "/dev/random");

  createFileIfNotExist(pathToChroot + "/dev/urandom");
  mountDir(pathToExe + "/../root/dev/urandom", pathToChroot + "/dev/urandom");

  // Proc is special, we mount a new proc dir.
  doWithCheck(mount("/proc", (pathToChroot + "/proc/").c_str(), "proc", MS_MGC_VAL, nullptr),
              "Mounting proc failed");

  doWithCheck(chroot(pathToChroot.c_str()), "Failed to chroot");
  // set working directory to buildDir
  doWithCheck(chdir("/build/"), "Failed to set working directory to " + buildDir);

  // doWithCheck(mount("/proc", "/proc/", "proc", MS_MGC_VAL, nullptr),
  //             "Mounting proc failed");

  // Disable ASLR for our child
  doWithCheck(personality(PER_LINUX | ADDR_NO_RANDOMIZE), "Unable to disable ASLR");
}
// =======================================================================================
/**
 * Spawn two processes, a parent and child, the parent will become the tracer, and child
 * will be tracee.
 */
int spawnTracerTracee(void* voidArgs){
  programArgs args = *((programArgs*) voidArgs);

  // Properly set up propegation rules for mounts created by dettrace, that is
  // make this a slave mount (and all mounts underneath this one) so that changes inside
  // this mount are not propegated to the parent mount.
  // This makes sure we don't pollute the host OS' mount space with entries made by us
  // here.
  doWithCheck(mount("none", "/", NULL, MS_SLAVE | MS_REC, 0), "mount slave");

  // TODO assert is bad (does not print buffered log output).
  // Switch to throw runtime exception.
  assert(getpid() == 1);

  pid_t pid = fork();
  if (pid < 0) {
    throw runtime_error("fork() failed.\n");
    exit(EXIT_FAILURE);
  } else if(pid > 0) {
    // We must mount proc so that the tracer sees the same PID and /proc/ directory
    // as the tracee. The tracee will do the same so it sees /proc/ under it's chroot.
    doWithCheck(mount("/proc", "/proc/", "proc", MS_MGC_VAL, nullptr),
              "tracer mounting proc failed");

    execution exe{
        args.debugLevel, pid, args.useColor, usingOldKernel(), args.logFile,
        args.printStatistics};
    exe.runProgram();
  } else if (pid == 0) {
    runTracee(args);
  }

  return 0;
}
// =======================================================================================
/**
 * index is the first index in the argv array containing a non option.
 * @param string: Either a user specified chroot path or none.
 * @return (optind, debugLevel, pathToChroot, useContainer, inSchroot, useColor)
 */
programArgs parseProgramArguments(int argc, char* argv[]){
  programArgs args;
  args.optIndex = 0;
  args.argc = argc;
  args.argv = argv;
  args.debugLevel = 0;
  args.pathToChroot = "NONE";
  args.useContainer = true;
  args.workingDir = "NONE";
  args.userChroot = false;
  args.pathToExe = "NONE";
  args.useColor = true;
  args.logFile = "NONE";
  args.printStatistics = false;
  args.convertUids = false;

  // Command line options for our program.
  static struct option programOptions[] = {
    {"debug" , required_argument,  0, 'd'},
    {"help"  , no_argument,        0, 'h'},
    {"chroot", required_argument,  0, 'c'},
    {"no-container", no_argument, 0, 'n'},
    {"no-color", no_argument, 0, 'r'},
    {"log", required_argument, 0, 'l'},
    {"print-statistics", no_argument, 0, 'p'},
    {"working-dir", required_argument, 0, 'w'},
    {"convert-uids", no_argument, 0, 'u'},
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
      args.pathToChroot = string { optarg };
      // Debug flag.
      break;
    case 'd':
      args.debugLevel = parseNum(optarg);
      if(args.debugLevel < 0 || args.debugLevel > 5){
        throw runtime_error("dettrace runtime exception: Debug level must be between [0,5].");
      }
      break;
      // Help message.
    case 'h':
      fprintf(stderr, "%s\n", usageMsg.c_str());
      exit(1);
      // no-container flag, used for testing
    case 'n':
      args.useContainer = false;
      break;
    case 'r':
      args.useColor = false;
      break;
    case 'l':
      args.logFile = string { optarg };
      break;
    case 'p':
      args.printStatistics = true;
      break;
    case 'u':
      args.convertUids = true;
      break;
    case 'w':
      args.workingDir = string { optarg };
      break;
    case '?':
      throw runtime_error("dettrace runtime exception: Invalid option passed to detTrace!");
    }
  }

  // User did not pass exe arguments:
  if(argv[optind] == NULL){
    fprintf(stderr, "Missing arguments to dettrace!\n");
    fprintf(stderr, "Use --help\n");
    exit(1);
  }

  args.optIndex = optind;

  // Find absolute path to our build directory relative to the dettrace binary.
  char argv0[strlen(argv[0])+1/*NULL*/];
  strcpy(argv0, argv[0]); // Use a copy since dirname may mutate contents.
  string pathToExe{ dirname(argv0) };
  args.pathToExe = pathToExe;

  if (isDefault(args.pathToChroot)) {
    args.userChroot = false;
    const string defaultRoot = "/../root/";
    args.pathToChroot = pathToExe + defaultRoot;
  } else {
    args.userChroot = true;
  }
  return args;
}
// =======================================================================================
/**
 * Use stat to check if file/directory exists to mount.
 * @return boolean if file exists
 */
static bool fileExists(string file) {
  struct stat sb;

  return (stat(file.c_str(), &sb) == 0);
}

/**
 * Wrapper around mount with strings.
 */
static void mountDir(string source, string target){

  /* Check if source path exists*/
  if (!fileExists(source)) {
    throw runtime_error("dettrace runtime exception: Trying to mount source " + source + ". File does not exist.\n");
  }

  /* Check if target path exists*/
  if (!fileExists(target))  {
    throw runtime_error("dettrace runtime exception: Trying to mount target " + target + ". File does not exist.\n");
  }

  // TODO: Marking it as private here shouldn't be necessary since we already unshared the entire namespace as private?
  // Notice that we want a bind mount, so MS_BIND is necessary. MS_REC is also necessary to
  // properly work when mounting dirs that are themselves bind mounts, otherwise you will get
  // an error EINVAL as per `man 2 mount`:
  // EINVAL In an unprivileged mount namespace (i.e., a mount namespace owned by  a  user
  //             namespace  that  was created by an unprivileged user), a bind mount operation
  //             (MS_BIND)  was  attempted  without  specifying  (MS_REC),  which  would  have
  //             revealed the filesystem tree underneath one of the submounts of the directory
  //             being bound.

  // Note this line causes spurious false positives when running under valgrind. It's okay
  // that these areguments are nullptr.
  doWithCheck(mount(source.c_str(), target.c_str(), nullptr,
                    MS_BIND | MS_PRIVATE | MS_REC, nullptr),
	      "Unable to bind mount: " + source + " to " + target);
}
// =======================================================================================
static void update_map(char *mapping, char *map_file){
  int fd = open(map_file, O_WRONLY);
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
static void proc_setgroups_write(pid_t pid, const char *str){
  char setgroups_path[PATH_MAX];
  int fd;

  snprintf(setgroups_path, PATH_MAX, "/proc/%d/setgroups", pid);

  fd = open(setgroups_path, O_WRONLY);
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
static void mkdirIfNotExist(string dir){
  int result = mkdir(dir.c_str(), ACCESSPERMS);
  if(result == -1){
    // That's okay :)
    if(errno == EEXIST){
      return;
    }else{
      string reason { strerror(errno) };
      throw runtime_error("dettrace runtime exception: Unable to make directory: " + dir + "\nReason: " + reason);
    }
  }
  return;
}
// =======================================================================================
// Create a blank file with sensible permissions.
static void createFileIfNotExist(string path){
  if(fileExists(path)){
    return;
  }

  doWithCheck(open(path.c_str(), O_RDWR | O_CREAT, S_IRUSR | S_IRGRP | S_IROTH),
              "Unable to create file: " + path);

  return;
}
// =======================================================================================
// Default starting value used by our programArgs.
static bool isDefault(string arg) {
  return arg == "NONE";
}
