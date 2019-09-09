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
#include <dirent.h>
#include <sys/prctl.h>
#include <pthread.h>
#include <sys/select.h>
#include <sys/sysmacros.h>

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
#include <time.h>

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
#include "vdso.hpp"

#include <seccomp.h>

#define CXXOPTS_NO_RTTI 1 // no rtti for cxxopts, this should be default.
#include <cxxopts.hpp>

/**
 * Useful link for understanding ptrace as it works with execve.
 * https://stackoverflow.com/questions/7514837/why-does
 * https://stackoverflow.com/questions/47006441/ptrace-catching-many-traps-for-execve/47039345#47039345
 */

using namespace std;

struct programArgs{
  std::vector<std::string> args;
  int debugLevel;
  string pathToChroot;
  string workingDir;
  string pathToExe;
  string logFile;

  bool useColor;
  bool printStatistics;
  // User is using --chroot flag.
  bool userChroot;
  // We sometimes want to run dettrace inside a chrooted enviornment. Annoyingly, Linux
  // does not let us create a user namespace if the current process is chrooted. This
  // is a feature. So we handle this special case, by allowing dettrace to treat the
  // current enviornment as a chroot.
  bool alreadyInChroot;
  bool convertUids;
  bool useContainer;
  bool allow_network;
  bool with_aslr;

  bool with_proc_overrides;
  bool with_devrand_overrides;

  bool with_host_envs;
  std::vector<std::pair<std::string, std::string>> envs;

  std::string tracee;
  std::vector<std::string> traceeArgs;

  unsigned timeoutSeconds;
  unsigned long epoch;
  unsigned long clone_ns_flags;

  programArgs(int argc, char* argv[]) {
    this->debugLevel = 0;
    this->pathToChroot = "";
    this->useContainer = false;
    this->workingDir = "";
    this->userChroot = false;
    this->pathToExe = "";
    this->useColor = true;
    this->logFile = "";
    this->printStatistics = false;
    this->convertUids = false;
    this->alreadyInChroot = false;
    this->timeoutSeconds = 0;
    this->epoch = execution::default_epoch;
    this->allow_network = false;
    this->with_aslr = false;
    this->with_host_envs = false;
    this->clone_ns_flags = 0;
    this->with_proc_overrides = true;
    this->with_devrand_overrides = true;
  }
};
// =======================================================================================
programArgs parseProgramArguments(int argc, char* argv[]);
int runTracee(std::unique_ptr<programArgs> args);
int spawnTracerTracee(void* args);
ptraceEvent getNextEvent(pid_t currentPid, pid_t& traceesPid, int& status);

static string devrandFifoPath, devUrandFifoPath;

static bool realDevNull(string path);
static bool fileExists(string directory);
static void deleteFile(string path);
static void mountDir(string source, string target);
static void setUpContainer(string pathToExe, string pathToChroot, string workingDir, bool userDefinedChroot, bool alreadyInChroot);
static void mkdirIfNotExist(string dir);
static void createFileIfNotExist(string path);

// See user_namespaces(7)
static void update_map(char* mapping, char* map_file);
static void proc_setgroups_write(pid_t pid, const char* str);

// Default starting value used by our programArgs.
static bool isDefault(string& arg);
// =======================================================================================
static execution *globalExeObject = nullptr;
void sigalrmHandler(int _) {
  assert(nullptr != globalExeObject);
  globalExeObject->killAllProcesses();
  // TODO: print out message about timeout expiring
  runtimeError("dettrace timeout expired\n");
}
// =======================================================================================

struct CloneArgs {
  std::unique_ptr<programArgs> args;
  std::map<std::string, std::tuple<unsigned long, unsigned long, unsigned long>> vdsoSyms;
  CloneArgs(struct programArgs& args) {
    this->args = std::make_unique<programArgs>(args);
  }
};

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
      runtimeError("Invalid integer: " + str);
    }

    if(args.debugLevel < 0 || args.debugLevel > 5){
      runtimeError("Debug level must be between [0,5].");
    }
  }

  // Set up new user namespace. This is needed as we will have root access withing
  // our own user namespace. Other namepspace commands require CAP_SYS_ADMIN to work.
  // Namespaces must must be done before fork. As changes don't apply until after
  // fork, to all child processes.

  int cloneFlags = args.clone_ns_flags;

  if (args.alreadyInChroot) {
    cloneFlags &= ~CLONE_NEWUSER;
  }

  // our own user namespace. Other namepspace commands require CAP_SYS_ADMIN to work.
  // Namespaces must must be done before fork. As changes don't apply until after
  // fork, to all child processes.
  const int STACK_SIZE (1024 * 1024);
  static char child_stack[STACK_SIZE];    /* Space for child's stack */

  doWithCheck(prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0),
              "Pre-clone prctl error: setting no new privs");

  // get vDSO symbols before clone/fork
  // only offets are used so it doesn't really matter
  // we read it from tracer or tracee.
  CloneArgs cloneArgs(args);
  auto syms = vdsoGetSymbols(getpid());
  if (4 > syms.size()) {
    runtimeError("VDSO symbol map has only "+to_string(syms.size())+", expect at least 4!");
  }
  cloneArgs.vdsoSyms = syms;

  // Requires SIGCHILD otherwise parent won't be notified of parent exit.
  // We use clone instead of unshare so that the current process does not live in
  // the new user namespace, this is a requirement for writing multiple UIDs into
  // the uid mappings.
  pid_t pid = clone(spawnTracerTracee, child_stack + STACK_SIZE, cloneFlags | SIGCHLD,
                    (void*) &cloneArgs);
  if(pid == -1){
    string reason = strerror(errno);
    cerr << "clone failed:\n  " + reason << endl;
    return 1;
  }
  // This is modified code from user_namespaces(7)
  // see https://lwn.net/Articles/532593/
  /* Update the UID and GID maps for children in their namespace, notice we do not
     live in that namespace. We use clone instead of unshare to avoid moving us into
     to the namespace. This allows us, in the future, to extend the mappings to other
     uids when running as root (not currently implemented, but notice this cannot be
     done when using unshare.)*/
  if ((args.clone_ns_flags & CLONE_NEWPID) == CLONE_NEWPID) {
    char map_path[PATH_MAX];
    const int MAP_BUF_SIZE = 100;
    char map_buf[MAP_BUF_SIZE];
    char* uid_map;
    char* gid_map;

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
  }

  int status;

  // Propegate Child's exit status to use as our own exit status.
  doWithCheck(waitpid(-1, &status, 0), "cannot wait for child");
  if (WIFEXITED(status)) {
    return WEXITSTATUS(status);
  } else {
    return 1;
  }
}

// get canonicalized exe path
static string getExePath(pid_t pid = 0) {
#define PROC_PID_EXE_LEN 32
#define REAL_PATH_LEN 4095
  char proc_pid_exe[PROC_PID_EXE_LEN];
  char path[1+REAL_PATH_LEN] = {0,};
  ssize_t nb;
  if (pid == 0) {
    snprintf(proc_pid_exe, PROC_PID_EXE_LEN, "/proc/self/exe");
  } else {
    snprintf(proc_pid_exe, PROC_PID_EXE_LEN, "/proc/%u/exe", pid);
  }

  if ((nb = readlink(proc_pid_exe, path, REAL_PATH_LEN)) < 0) {
    return "";
  }
  // readlink doesn't put null byte
  path[nb] = '\0';

  while(nb >= 0 && path[nb] != '/')
    --nb;
  path[nb] = '\0';
  return path;
#undef REAL_PATH_LEN
#undef PROC_PID_EXE_LEN
}

// prepare envvars for tracee
static std::pair<char**, size_t>populate_env_vars
     (std::vector<std::pair<std::string, std::string>>& envvars) {
  // Create minimal environment.
  // Note: gcc needs to be somewhere along PATH or it gets very confused, see
  // https://github.com/upenn-acg/detTrace/issues/23
  unsigned long env_vars_bytes = 0;
  unsigned long env_vars_nr = 0;
  for (auto it = envvars.cbegin(); it != envvars.cend(); ++it) {
    env_vars_bytes += it->first.size() + it->second.size() + 3;
    ++env_vars_nr;
  }

  char* env_var_store = (char*)calloc(1 + env_vars_bytes, 1);
  if (!env_var_store) {
    string errmsg = "unable to alloc env string for size: " + to_string(env_vars_bytes) + "\n";
    runtimeError(errmsg);
  }

  char** envs = (char**)calloc(1 + env_vars_nr, sizeof(char*));
  if (!envs) {
    string errmsg = "unable to alloc envvar for size: " + to_string(sizeof(char*) * env_vars_nr) + "\n";
    runtimeError(errmsg);
  }

  int i = 0;
  int k = 0;
  int n = (int)env_vars_bytes;
  for (auto it = envvars.cbegin(); it != envvars.cend(); ++it) {
    char* env = &env_var_store[k];
    k += snprintf(&env_var_store[k], n - k, "%s=%s", it->first.c_str(), it->second.c_str());
    env_var_store[k++] = '\0';
    envs[i++] = env;
  }
  envs[i++] = NULL;

  return std::make_pair(envs, (size_t)i);
}

// =======================================================================================
/**
 * Child will become the process the user wishes through call to execvpe.
 * @arg tempdir: either empty string or tempdir to use, for cpio chroot.
 */
int runTracee(std::unique_ptr<programArgs> args){
  auto argv = args->args;
  int debugLevel = args->debugLevel;
  string pathToChroot = args->pathToChroot;
  bool useContainer = args->useContainer;
  string workingDir = args->workingDir;
  string pathToExe = args->pathToExe;

  if(useContainer){
    setUpContainer(pathToExe, pathToChroot, workingDir, args->userChroot, args->alreadyInChroot);
  } else {
    if (!args->with_aslr) {
      // Disable ASLR for our child
      doWithCheck(personality(PER_LINUX | ADDR_NO_RANDOMIZE), "Unable to disable ASLR");
    }
    if (args->clone_ns_flags & CLONE_NEWNS) {
      if (args->with_devrand_overrides) {
	mountDir(devrandFifoPath, "/dev/random");
	mountDir(devUrandFifoPath, "/dev/urandom");
      }
      if (args->with_proc_overrides) {
	// jld: determinize various parts of /proc which our benchmarks read from
	mountDir(pathToExe+"/../root/proc/meminfo", "/proc/meminfo");
	mountDir(pathToExe+"/../root/proc/std::at", "/proc/stat");
	mountDir(pathToExe+"/../root/proc/filesystems", "/proc/filesystems");
      }
      char* home = secure_getenv("HOME");
      if (home) {
	mountDir(home, "/root");
      }
    }
  }

  // trap on rdtsc/rdtscp insns
  doWithCheck(prctl(PR_SET_TSC, PR_TSC_SIGSEGV, 0, 0, 0), "Pre-clone prctl error");
  doWithCheck(prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0), "Pre-clone prctl error: setting no new privs");

  // Perform execve based on user command.
  ptracer::doPtrace(PTRACE_TRACEME, 0, NULL, NULL);

  // +1 for executable's name, +1 for NULL at the end.
  int newArgc = args->args.size() + 1;
  char* traceeCommand[newArgc];

  for (int i = 0; i < newArgc - 1; i++) {
    traceeCommand[i] = (strdup)(argv[i].c_str());
  }
  traceeCommand[newArgc - 1] = NULL;

  char** envs = NULL;
  size_t nenvs = 0;

  std::tie(envs, nenvs) = populate_env_vars(args->envs);

  // Set up seccomp + bpf filters using libseccomp.
  // Default action to take when no rule applies to system call. We send a PTRACE_SECCOMP
  // event message to the tracer with a unique data: INT16_MAX
  seccomp myFilter { debugLevel, args->convertUids };

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
extract(const void* buffer, size_t size, int do_extract, int flags)
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
  if ((r = archive_read_open_memory(a, buffer, size))) {
    fprintf(stderr, "archive_read_open_fd(): %s %d",
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

extern unsigned long __initramfs_start;
extern unsigned long __initramfs_end;
extern unsigned long __initramfs_size;

// =======================================================================================
/**
 *
 * populate initramfs into @path
 *
 */
static void populateInitramfs(const char* path)
{
  string errmsg = "Failed to change direcotry to ";
  char* oldcwd = get_current_dir_name();
  doWithCheck(chdir(path), errmsg + path);
  extract((const void*)&__initramfs_start, __initramfs_size, 1, 0);
  doWithCheck(chdir(oldcwd), errmsg + oldcwd);
  free(oldcwd);
}
// =======================================================================================
// pathToChroot must exist and be located inside the chroot if the user defined their own chroot!
static void checkPaths(string pathToChroot, string workingDir){
    if( !fileExists(workingDir)){
      runtimeError("workingDir: " + workingDir + " does not exits!");
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
 * DEVRAND STEP 3: thread that writes pseudorandom output to a /dev/[u]random fifo
 */
static void* devRandThread(void* fifoPath_) {

  char* fifoPath = (char*) fifoPath_;

  // allow this thread to be unilaterally killed when tracer exits
  int oldCancelType;
  doWithCheck(pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, &oldCancelType), "pthread_setcanceltype");

  //fprintf(stderr, "[devRandThread] using fifo  %s\n", fifoPath);

  PRNG prng(0x1234);

  uint32_t totalBytesWritten = 0;
  uint16_t random = 0;
  bool getNewRandom = true;

  // NB: if the fifo is ever closed by all readers/writers, then contents
  // buffered within it get dropped. This leads to nondeterministic results, so
  // we always keep the fifo open here. We open the fifo for writing AND reading
  // as that eliminates EPIPE ("other end of pipe closed") errors when the
  // tracee has closed the fifo and we call write(). Instead, our write() call
  // will block once the fifo fills up. Once a tracee starts reading, the buffer
  // will drain and our write() will get unblocked. However, no bytes should get
  // lost during this process, ensuring the tracee(s) always see(s) a
  // deterministic sequence of reads.
  int fd = open(fifoPath, O_RDWR);
  doWithCheck(fd, "open");

  while (true) {
    if (getNewRandom) {
      random = prng.get();
    }
    int bytesWritten = write(fd, &random, 2);
    if (2 != bytesWritten) {
      perror("[devRandThread] error writing to fifo");
      // need to try writing these bytes again so that the fifo generates deterministic output
      getNewRandom = false;

    } else {
      fsync(fd);
      getNewRandom = true;
      totalBytesWritten += 2;
      //printf("[devRandThread] wrote %u bytes so far...\n", totalBytesWritten);
    }
  }

  close(fd);
  return NULL;
}

/**
 * Jail our container under chootPath.
 * This directory must exist and be located inside the chroot if the user defined their own chroot!
 */
static void setUpContainer(string pathToExe, string pathToChroot, string workingDir, bool userDefinedChroot, bool alreadyInChroot){
  if(userDefinedChroot && ! isDefault(workingDir)){
    checkPaths(pathToChroot, workingDir);
  }

  const vector<string> mountDirs =
    {  "/dettrace", "/dettrace/bin", "/bin", "/usr", "/lib", "/lib64",
       "/dev", "/etc", "/proc", "/build", "/tmp", "/root" };

  if (!userDefinedChroot) {
    char buf[256];
    snprintf(buf, 256, "%s", "/tmp/dtroot.XXXXXX");
    string tempdir = string { mkdtemp(buf) };

    string cpio;
    doWithCheck(mount("none", tempdir.c_str(), "tmpfs", 0, NULL), "mount initramfs");
    populateInitramfs(tempdir.c_str());
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

  // The user did not specify a chroot env, try to scrape a minimal filesystem from the
  // host OS'.
  if(! userDefinedChroot){
    mountDir("/bin/", pathToChroot + "/bin/");
    mountDir("/usr/", pathToChroot + "/usr/");
    mountDir("/lib/", pathToChroot + "/lib/");
    mountDir("/lib64/", pathToChroot + "/lib64/");
    mountDir("/etc/ld.so.cache", pathToChroot + "/etc/ld.so.cache");
  }

  // make sure chroot has a real /dev/null
  string chrootDevNullPath = pathToChroot + "/dev/null";
  if (fileExists(chrootDevNullPath) && realDevNull(chrootDevNullPath)) {
    // we're done!
  } else {
    if (fileExists(chrootDevNullPath)) {
      deleteFile(chrootDevNullPath);
    }
    if (alreadyInChroot) {
      // we're running under reprotest as sudo, so we can use real mknod
      // hat tip to: https://unix.stackexchange.com/questions/27279/how-to-create-dev-null
      dev_t dev = makedev(1,3);
      mode_t mode = S_IFCHR | S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH;
      doWithCheck(mknod(chrootDevNullPath.c_str(), mode, dev), "mknod");
    } else {
      // fail if /dev/null isn't real
      if (!realDevNull("/dev/null")) {
        runtimeError("/dev/null is not a real /dev/null device\n");
      }
      // bind mount our /dev/null into the container
      createFileIfNotExist(chrootDevNullPath);
      mountDir("/dev/null", chrootDevNullPath);
    }
  }

  // DEVRAND STEP 4: bind mount our /dev/[u]random fifos into the chroot
  createFileIfNotExist(pathToChroot + "/dev/random");
  mountDir(devrandFifoPath, pathToChroot + "/dev/random");

  createFileIfNotExist(pathToChroot + "/dev/urandom");
  mountDir(devUrandFifoPath, pathToChroot + "/dev/urandom");

  // Proc is special, we mount a new proc dir.
  doWithCheck(mount("/proc", (pathToChroot + "/proc/").c_str(), "proc", MS_MGC_VAL, nullptr),
              "Mounting proc failed");
  // jld: determinize various parts of /proc which our benchmarks read from
  mountDir(pathToExe+"/../root/proc/meminfo", pathToChroot+"/proc/meminfo");
  mountDir(pathToExe+"/../root/proc/stat", pathToChroot+"/proc/stat");
  mountDir(pathToExe+"/../root/proc/filesystems", pathToChroot+"/proc/filesystems");

  doWithCheck(chroot(pathToChroot.c_str()), "Failed to chroot");
  // set working directory to buildDir
  doWithCheck(chdir("/build/"), "Failed to set working directory to " + buildDir);

  // Disable ASLR for our child
  doWithCheck(personality(PER_LINUX | ADDR_NO_RANDOMIZE), "Unable to disable ASLR");
}
// =======================================================================================
/**
 * Spawn two processes, a parent and child, the parent will become the tracer, and child
 * will be tracee.
 */
int spawnTracerTracee(void* voidArgs){
  CloneArgs* cloneArgs = static_cast<CloneArgs*>(voidArgs);
  auto args = std::move(cloneArgs->args);
  auto vdsoSyms = cloneArgs->vdsoSyms;

  // Properly set up propegation rules for mounts created by dettrace, that is
  // make this a slave mount (and all mounts underneath this one) so that changes inside
  // this mount are not propegated to the parent mount.
  // This makes sure we don't pollute the host OS' mount space with entries made by us
  // here.
  if ((args->clone_ns_flags & CLONE_NEWNS) == CLONE_NEWNS) {
    doWithCheck(mount("none", "/", NULL, MS_SLAVE | MS_REC, 0), "mount slave");
  }

  // TODO assert is bad (does not print buffered log output).
  // Switch to throw runtime exception.
  if ( (args->clone_ns_flags & CLONE_NEWPID) == CLONE_NEWPID) {
    pid_t first_pid;
    if ((first_pid = getpid()) != 1) {
      string errmsg("PID of first process expected to be 1, got: ");
      errmsg += to_string(first_pid);
      errmsg += "\n";
      runtimeError(errmsg);
    }
  }

  // DEVRAND STEP 1: create unique /dev/[u]random fifos before we fork, so
  // that their names are available to tracee
  char tmpnamBuffer[L_tmpnam];
  char* tmpnamResult = tmpnam(tmpnamBuffer);
  assert(NULL != tmpnamResult);
  devrandFifoPath = string{ tmpnamBuffer } + "-random.fifo";
  //fprintf(stderr, "%s\n", devrandFifoPath.c_str());
  devUrandFifoPath = string{ tmpnamBuffer } + "-urandom.fifo";
  doWithCheck(mkfifo(devrandFifoPath.c_str(), 0666), "mkfifo");
  doWithCheck(mkfifo(devUrandFifoPath.c_str(), 0666), "mkfifo");

  pid_t pid = fork();
  if (pid < 0) {
    runtimeError("fork() failed.\n");
    exit(EXIT_FAILURE);
  } else if(pid > 0) {
    // We must mount proc so that the tracer sees the same PID and /proc/ directory
    // as the tracee. The tracee will do the same so it sees /proc/ under it's chroot.
    if ((args->clone_ns_flags & CLONE_NEWNS) == CLONE_NEWNS &&
	(args->clone_ns_flags & CLONE_NEWPID) == CLONE_NEWPID) {
      doWithCheck(mount("none", "/proc/", "proc", MS_MGC_VAL, nullptr),
                  "tracer mounting proc failed");
    }

    // DEVRAND STEP 2: spawn a thread to write to each fifo
    pthread_t devRandomPthread, devUrandomPthread;
    // NB: we copy *FifoPath to the heap as our stack storage goes away: these allocations DO get leaked
    // If we wanted to not leak them, devRandThread could copy to its stack and free the heap copy
    doWithCheck( pthread_create(&devRandomPthread, NULL, devRandThread, (void*)strdup(devrandFifoPath.c_str())),
                 "pthread_create /dev/random pthread" );
    doWithCheck( pthread_create(&devUrandomPthread, NULL, devRandThread, (void*)strdup(devUrandFifoPath.c_str())),
                 "pthread_create /dev/urandom pthread" );

    execution exe{
        args->debugLevel, pid, args->useColor,
        args->logFile, args->printStatistics,
        devRandomPthread, devUrandomPthread,
        cloneArgs->vdsoSyms,
        args->allow_network,
        args->epoch};

    globalExeObject = &exe;
    struct sigaction sa;
    sa.sa_handler = sigalrmHandler;
    doWithCheck(sigemptyset(&sa.sa_mask), "sigemptyset");
    sa.sa_flags = 0;
    doWithCheck(sigaction(SIGALRM, &sa, NULL), "sigaction(SIGALRM)");
    alarm(args->timeoutSeconds);

    exe.runProgram();
  } else if (pid == 0) {
    runTracee(std::move(args));
  }

  return 0;
}

// unwrap_or (default) OptionValue
class OptionValue1: public cxxopts::OptionValue {
public:
  explicit OptionValue1(cxxopts::OptionValue value) {
    m_value = std::move(value);
  }
  template <typename T>
  const T&
  unwrap_or(const T& default_value) const {
    if (m_value.count()) {
      return m_value.as<T>();
    } else {
      return default_value;
    }
  }
private:
  cxxopts::OptionValue m_value;
};

// =======================================================================================
/**
 * index is the first index in the argv array containing a non option.
 * @param string: Either a user specified chroot path or none.
 * @return (optind, debugLevel, pathToChroot, useContainer, inSchroot, useColor)
 */
programArgs parseProgramArguments(int argc, char* argv[]){
  programArgs args(argc, argv);

  cxxopts::Options options("dettrace",  "A container for dynamic determinism enforcement. \n"
			   "Arbitrary programs run inside will run deterministically.");

  options
    .positional_help("program [programArgs..]");

  options.add_options()
    ( "help",
      "display this help diaglog")
    ( "debug",
      "set debugging level[0..5]. default is 0 (off).",
      cxxopts::value<int>()->default_value("0"))
    ( "log-file",
      "Path to write log to. If writing to a file, the filename"
      "has a unique suffix appended. default is stderr.",
      cxxopts::value<std::string>())
    ( "chroot",
      "Specify root to use for chroot (such as one created by debootstrap)",
      cxxopts::value<std::string>())
    ( "working-dir",
      "Specify the working directory that dettrace should use as a workspace for the "
      "deterministic process tree, by default it is the current working directory.",
      cxxopts::value<std::string>())
    ( "with-host-envs",
      "derive envvars from host,when disabled, the tracee starts with a miniaml env: "
      "PATH=/bin:/usr/bin. default is true.\n",
      cxxopts::value<bool>()->default_value("true"))
    ( "env",
      "KEY=VAL, set environment variables for tracee, only allowd when `--with-host-env=no`,"
      "this flag can be added multiple times to add multiple envvars.",
      cxxopts::value<std::vector<string>>())
    ( "with-proc-overrides",
      "override /proc/{stat,meminfo,filesystems} to predefiend values so that "
      "tracee depends on them becomes more deterministic. default is true.",
      cxxopts::value<bool>()->default_value("true"))
    ( "with-devrand-overrides",
      "override /dev/{random,urandom} to psudo deterministic seeds "
      "so that app get deterministic random values. default is true.",
      cxxopts::value<bool>()->default_value("true"))
    ( "with-aslr",
      "enable/disable Address Space Layout Randomization (ASLR). "
      "Note ASLR can affect determinism when enabled. default is false.",
      cxxopts::value<bool>())
    ( "with-userns",
      "allow dettrace use of Linux user namespace."
      " disable userns may cause non-determinism because of uid/gid, however"
      " it maybe reasonable to disable it under docker. default is true.",
      cxxopts::value<bool>())
    ( "with-pidns",
      "allow dettrace use of Linux PID namespace."
      " disable pidns may cause non-determinism because of PIDs, however"
      " it maybe reasonable to disable it under docker. default is true.",
      cxxopts::value<bool>())
    ( "with-mountns",
      "allow dettrace use of Linux mount namespace."
      " disable pidns may cause non-determinism because of /proc, /sys, however"
      " it maybe reasonable to disable it under docker.",
      cxxopts::value<bool>())
    ( "with-network",
      "Allow netowrking related syscalls like socket/send/recv"
      " which could be non-deterministic. default is false.",
      cxxopts::value<bool>()->default_value("false"))
    ( "epoch",
      "set system epoch (start) time \"now|yyyy-mm-dd,HH:MM:SS\" (utc). default is 1993-08-08,22:00:00.",
      cxxopts::value<std::string>()->default_value("1993-08-08,22:00:00"))
    ( "with-color",
      "Allow use of ANSI colors in log output. Useful when piping log to a file. default is true.",
      cxxopts::value<bool>())
    ( "print-statistics",
      "Print metadata about process that just ran including: number of system call events"
      " read/write retries, rdtsc, rdtscp, cpuid. default is false\n",
      cxxopts::value<bool>()->default_value("false"))
    ( "timeoutSeconds",
      "Tear down all tracee processes with SIGKILL after this many seconds. default is 0 - indefinite.",
      cxxopts::value<unsigned long>()->default_value("0"))
    ( "already-in-chroot",
      "The current environment is already the desired chroot. For some reason the"
      " current mount namespace is polluted with our bind mounts (even though we create"
      " our own namespace). Therefore make sure to unshare -m before running dettrace with"
      " this command, either when chrooting or when calling dettrace. default is false",
      cxxopts::value<bool>()->default_value("false"))
    ( "convert-uids",
      "Some programs attempt to use UIDs not mapped in our namespace. Catch"
      " this behavior for lchown, chown, fchown, fchowat, and dynamically change the UIDS to"
      " 0 (root). default is false.",
      cxxopts::value<bool>()->default_value("false"))
    ( "program",
      "program to run",
      cxxopts::value<std::string>())
    ( "programArgs",
      "program arguments",
      cxxopts::value<std::vector<std::string>>());

  try {
    options.parse_positional("program", "programArgs");
    auto result = options.parse(argc, argv);

    const std::string emptyString("");

    args.alreadyInChroot = (static_cast<OptionValue1>(result["already-in-chroot"])).unwrap_or(false);
    args.pathToChroot = (static_cast<OptionValue1>(result["chroot"])).unwrap_or(emptyString);
    args.debugLevel = (static_cast<OptionValue1>(result["debug"])).unwrap_or(0);
    args.useColor = (static_cast<OptionValue1>(result["with-color"])).unwrap_or(false);
    args.logFile = (static_cast<OptionValue1>(result["log-file"])).unwrap_or(emptyString);
    args.printStatistics = (static_cast<OptionValue1>(result["print-statistics"])).unwrap_or(false);
    args.convertUids = (static_cast<OptionValue1>(result["convert-uids"])).unwrap_or(false);
    args.workingDir = (static_cast<OptionValue1>(result["working-dir"])).unwrap_or(emptyString);
    args.timeoutSeconds = (static_cast<OptionValue1>(result["timeoutSeconds"])).unwrap_or(0);
    args.allow_network = (static_cast<OptionValue1>(result["with-network"])).unwrap_or(false);
    args.with_aslr = (static_cast<OptionValue1>(result["with-aslr"])).unwrap_or(false);
    args.with_proc_overrides = (static_cast<OptionValue1>(result["with-proc-overrides"])).unwrap_or(false);
    args.with_devrand_overrides = (static_cast<OptionValue1>(result["with-devrand-overrides"])).unwrap_or(false);
    args.with_host_envs = result["with-host-envs"].as<bool>();

    bool userns  = (static_cast<OptionValue1>(result["with-userns"])).unwrap_or(false);
    bool pidns   = (static_cast<OptionValue1>(result["with-pidns"])).unwrap_or(false);
    bool mountns = (static_cast<OptionValue1>(result["with-mountns"])).unwrap_or(false);
    if (userns) {
      args.clone_ns_flags |= CLONE_NEWUSER;
    }
    if (pidns) {
      args.clone_ns_flags |= CLONE_NEWPID;
    }
    if (mountns) {
      args.clone_ns_flags |= CLONE_NEWNS;
    }

    args.useContainer = false;
    // epoch
    {
      string ts = result["epoch"].as<std::string>();
      if (ts == "now") {
	args.epoch = time(NULL);
      } else {
	struct tm tm = {0,};
	if (!strptime(ts.c_str(), "%Y-%m-%d,%H:%M:%S", &tm)) {
	  string errmsg("invalid time for --epoch: ");
	  errmsg += ts;
	  runtimeError(errmsg);
	}
	tm.tm_isdst = -1; /* dst auto detect */
	args.epoch = timegm(&tm);
      }
    }

    if (!args.with_host_envs) {
      if (result["env"].count() > 0) {
	auto kvs = result["env"].as<std::vector<std::string>>();
	for (auto kv: kvs) {
	  auto j = kv.find('=');
	  auto k = kv.substr(0, j);
	  auto v = kv.substr(1+j);
	  args.envs.push_back({k, v});
	}
      }
    } else {
      extern char** environ;
      for (int i = 0; environ[i]; i++) {
	string kv(environ[i]);
	auto j = kv.find('=');
	auto k = kv.substr(0, j);
	auto v = kv.substr(1+j);
	args.envs.push_back({k, v});
      }
    }

    args.args.clear();
    if (!result["program"].count()) {
      std::cout << options.help() << std::endl;
      exit(1);
    }
    args.args.push_back(result["program"].as<std::string>());

    const std::vector<std::string> emptyArgs;
    auto traceeArgs = (static_cast<OptionValue1>(result["programArgs"])).unwrap_or(emptyArgs);
    std::copy(traceeArgs.begin(), traceeArgs.end(), std::back_inserter(args.args));

    args.pathToExe = getExePath();

    if (isDefault(args.pathToChroot)) {
      args.userChroot = false;
      const string defaultRoot = "/../root/";
      args.pathToChroot = args.pathToExe + defaultRoot;
    } else {
      args.userChroot = true;
    }

    bool usingWorkingDir = args.workingDir != "";
    if (args.alreadyInChroot && (args.userChroot || usingWorkingDir)) {
      fprintf(stderr, "Cannot use --already-in-chroot with --chroot or --working-dir.\n");
      exit(1);
    }

    if (usingWorkingDir && !args.userChroot) {
      fprintf(stderr, "Cannot use --working-dir without specifying a --chroot.\n");
      exit(1);
    }

    // Detect if we're inside a chroot by attempting to make a user namespace.
    if (args.alreadyInChroot) {
      if (unshare(CLONE_NEWUSER) != -1) {
	fprintf(stderr, "We detected you are not currently running inside a chroot env.\n");
	exit(1);
      }
      // Treat current enviornment as our chroot.
      args.userChroot = true;
      args.pathToChroot = "/";
    }
  } catch(cxxopts::option_not_exists_exception& e) {
    std::cerr << "command line parsing exception: " << e.what() << std::endl;
    std::cerr << options.help() << std::endl;
    exit(1);
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
 * @return true if the given path is a real /dev/null device, false otherwise
 */
static bool realDevNull(string path) {
  struct stat statDevNull;
  doWithCheck(stat(path.c_str(), &statDevNull), "stat /dev/null");
  /*
  string fileType = "";
  if (S_ISREG(statDevNull.st_mode)) { fileType = "S_ISREG"; }
  if (S_ISDIR(statDevNull.st_mode)) { fileType = "S_ISDIR"; }
  if (S_ISCHR(statDevNull.st_mode)) { fileType = "S_ISCHR"; }
  if (S_ISBLK(statDevNull.st_mode)) { fileType = "S_ISBLK"; }
  if (S_ISFIFO(statDevNull.st_mode)) { fileType = "S_ISFIFO"; }
  if (S_ISLNK(statDevNull.st_mode)) { fileType = "S_ISLNK"; }
  if (S_ISSOCK(statDevNull.st_mode)) { fileType = "S_ISSOCK"; }
  cout << path
       << " " << fileType
       << " major:" << major(statDevNull.st_dev)
       << " minor:" << minor(statDevNull.st_dev)
       << endl;
  */
  // NB: on platforms where we run DT tests, /dev/null sometimes shows up as
  // something besides a 1,3 CHR device. For example, it appears to show up
  // with the version number 0,64 on Azure DevOps. Not sure what the
  // significance of these numbers are, but they seem to act like proper
  // /dev/null files as far as our readDevNull test is concerned.
  return S_ISCHR(statDevNull.st_mode) &&
    ((1 == major(statDevNull.st_dev) && 3 == minor(statDevNull.st_dev)) ||
     (0 == major(statDevNull.st_dev)));
}

/**
 * Wrapper around mount with strings.
 */
static void mountDir(string source, string target){

  /* Check if source path exists*/
  if (!fileExists(source)) {
    fprintf(stderr, "WARNING: Trying to mount source %s. File does not exist.\n", source.c_str());
    return;
  }

  /* Check if target path exists*/
  if (!fileExists(target))  {
    runtimeError("Trying to mount target " + target + ". File does not exist.\n");
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
      runtimeError("Unable to make directory: " + dir + "\nReason: " + reason);
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

  int fd;
  doWithCheck((fd = open(path.c_str(), O_RDWR | O_CREAT, S_IRUSR | S_IRGRP | S_IROTH)),
              "Unable to create file: " + path);
  if (fd >= 0) close(fd);

  return;
}
/** Delete the file at the given path. If file does not exist, this does nothing. */
static void deleteFile(string path) {
  if (!fileExists(path)) {
    return;
  }
  doWithCheck(unlink(path.c_str()), "unlink");
}
// =======================================================================================
// Default starting value used by our programArgs.
static bool isDefault(string& arg) {
  return arg.empty();
}
