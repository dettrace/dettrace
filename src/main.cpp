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
#include "tempfile.hpp"
#include "fakefs.hpp"
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
  int argc;
  char** argv;

  std::vector<std::string> args;
  int debugLevel;
  string pathToChroot;
  string mountHome;
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
  bool with_etc_overrides;

  std::unordered_map<std::string, std::string> envs;

  std::string tracee;
  std::vector<std::string> traceeArgs;

  unsigned timeoutSeconds;
  unsigned long epoch;
  unsigned long clone_ns_flags;

  unsigned short prng_seed;
  bool in_docker;

  programArgs(int argc, char* argv[]) {
    this->argc = argc;
    this->argv = argv;
    this->debugLevel = 0;
    this->pathToChroot = "";
    this->useContainer = false;
    this->mountHome = "";
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
    this->clone_ns_flags = 0;
    this->with_proc_overrides = true;
    this->with_devrand_overrides = true;
    this->with_etc_overrides = true;
    this->prng_seed = 0;
    this->in_docker = false;
  }
};
// =======================================================================================
programArgs parseProgramArguments(int argc, char* argv[]);
int runTracee(programArgs* args);
int spawnTracerTracee(void* args);
ptraceEvent getNextEvent(pid_t currentPid, pid_t& traceesPid, int& status);

static string devrandFifoPath, devUrandFifoPath;

static bool fileExists(const string& directory);
static void mountDir(const string& source, const string& target);
static void createFileIfNotExist(const string& path);

// See user_namespaces(7)
static void update_map(char* mapping, char* map_file);
static void proc_setgroups_write(pid_t pid, const char* str);

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
  programArgs* args;
  std::unique_ptr<TempDir> tmpdir;
  std::map<std::string, std::tuple<unsigned long, unsigned long, unsigned long>> vdsoSyms;
  CloneArgs(programArgs* args) {
    this->args = args;
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
  if (args.alreadyInChroot) {
    args.clone_ns_flags &=~ CLONE_NEWUSER;
  }
  int cloneFlags = args.clone_ns_flags;

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
  CloneArgs cloneArgs(&args);
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
  if ((args.clone_ns_flags & CLONE_NEWUSER) == CLONE_NEWUSER) {
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
  doWithCheck(waitpid(pid, &status, 0), "cannot wait for child");
  if (WIFEXITED(status)) {
    return WEXITSTATUS(status);
  } else if (WIFSIGNALED(status)) {
    return WTERMSIG(status);
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
     (std::unordered_map<std::string, std::string>& envvars) {
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
int runTracee(programArgs* args){
  auto argv = args->args;
  int debugLevel = args->debugLevel;
  string pathToExe = args->pathToExe;

  {
    if (!args->with_aslr) {
      // Disable ASLR for our child
      doWithCheck(personality(PER_LINUX | ADDR_NO_RANDOMIZE), "Unable to disable ASLR");
    }
    if (!fileExists("/dev/null")) {
      // we're running under reprotest as sudo, so we can use real mknod
      // hat tip to: https://unix.stackexchange.com/questions/27279/how-to-create-dev-null
      dev_t dev = makedev(1,3);
      mode_t mode = S_IFCHR | S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH;
      doWithCheck(mknod("/dev/null", mode, dev), "mknod");
    }

    if (args->clone_ns_flags & CLONE_NEWNS) {
      if (args->with_devrand_overrides) {
        createFileIfNotExist("/dev/random");
        mountDir(devrandFifoPath, "/dev/random");
        createFileIfNotExist("/dev/urandom");
        mountDir(devUrandFifoPath, "/dev/urandom");
      }

      if (!args->mountHome.empty()) {
	mountDir(args->mountHome, "/root");
      }

      doWithCheck(mount("none", "/tmp", "tmpfs", 0, NULL), "mount /tmp as tmpfs failed");
      if (args->with_proc_overrides) {
	mountDir(pathToExe+"/../root/proc/meminfo", "/proc/meminfo");
	mountDir(pathToExe+"/../root/proc/stat", "/proc/stat");
	mountDir(pathToExe+"/../root/proc/filesystems", "/proc/filesystems");
      }
      if (args->with_etc_overrides) {
	mountDir(pathToExe+"/../root/etc/hosts", "/etc/hosts");
	mountDir(pathToExe+"/../root/etc/passwd", "/etc/passwd");
	mountDir(pathToExe+"/../root/etc/group", "/etc/group");
	mountDir(pathToExe+"/../root/etc/ld.so.cache", "/etc/ld.so.cache");
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

static pthread_cond_t  devRandThreadReady = PTHREAD_COND_INITIALIZER;
static pthread_mutex_t devRandThreadMutex = PTHREAD_MUTEX_INITIALIZER;

struct DevRandThreadParam {
  std::string fifoPath;
  unsigned int prngSeed;
};

/**
 * DEVRAND STEP 3: thread that writes pseudorandom output to a /dev/[u]random fifo
 */
static void* devRandThread(void* param_) {
  struct DevRandThreadParam* param = (struct DevRandThreadParam*)param_;
  const char* fifoPath = param->fifoPath.c_str();

  pthread_mutex_lock(&devRandThreadMutex);
  // allow this thread to be unilaterally killed when tracer exits
  int oldCancelType;
  doWithCheck(pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, &oldCancelType), "pthread_setcanceltype");

  // fprintf(stderr, "[devRandThread] using fifo  %s, seed: %x\n", fifoPath, param->prngSeed);

  PRNG prng(param->prngSeed);

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
  int fd = open(fifoPath, O_RDWR );
  doWithCheck(fd, string("open: ") + fifoPath);
  pthread_cond_signal(&devRandThreadReady);
  pthread_mutex_unlock(&devRandThreadMutex);
  
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

static inline void closeAllFds(void) {
  for (int fd = 3; fd < 256; fd++) {
    close(fd);
  }
}

static void doTracerCleanup(bool umountTmpfs, std::unique_ptr<TempDir> tmpdir) {
  closeAllFds();

  if (umountTmpfs) {
    umount("/tmp");
  }

  unlink(devrandFifoPath.c_str());
  unlink(devUrandFifoPath.c_str());

  auto path = tmpdir->path();
  unlink(path.c_str());
}

// =======================================================================================
/**
 * Spawn two processes, a parent and child, the parent will become the tracer, and child
 * will be tracee.
 */
int spawnTracerTracee(void* voidArgs){
  CloneArgs* cloneArgs = static_cast<CloneArgs*>(voidArgs);
  auto args = cloneArgs->args;
  auto vdsoSyms = cloneArgs->vdsoSyms;

  int pipefds[2];

  doWithCheck(pipe2(pipefds, O_CLOEXEC), "spawnTracerTracee pipe2 failed");

  // Properly set up propegation rules for mounts created by dettrace, that is
  // make this a slave mount (and all mounts underneath this one) so that changes inside
  // this mount are not propegated to the parent mount.
  // This makes sure we don't pollute the host OS' mount space with entries made by us
  // here.
  if((args->clone_ns_flags & CLONE_NEWNS) &&
       (args->clone_ns_flags & CLONE_NEWUSER)) {
    doWithCheck(mount("none", "/", NULL, MS_SLAVE | MS_REC, 0), "failed to mount / as slave");
  }

  cloneArgs->tmpdir = std::make_unique<TempDir>("dt-");

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
  {
    TempPath tmpnamBuffer(*cloneArgs->tmpdir);
    devrandFifoPath = tmpnamBuffer.path() + "-random.fifo";
    devUrandFifoPath = tmpnamBuffer.path() + "-urandom.fifo";
  }
  
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

    if ((args->clone_ns_flags & CLONE_NEWNS) == CLONE_NEWNS) {
      doWithCheck(mount("none", "/dev/pts", "devpts", 0, nullptr),
                  "tracer mounting devpts failed");
    }

    if (!fileExists(devrandFifoPath)) {
      runtimeError("cannot create psudo /dev/random fifo");
    }

    if (!fileExists(devUrandFifoPath)) {
      runtimeError("cannot create psudo /dev/urandom fifo");
    }

    // DEVRAND STEP 2: spawn a thread to write to each fifo
    pthread_t devRandomPthread, devUrandomPthread;

    struct DevRandThreadParam params[2] =
      {
       { devrandFifoPath, args->prng_seed },
       { devUrandFifoPath, args->prng_seed },
      };
    // NB: we copy *FifoPath to the heap as our stack storage goes away: these allocations DO get leaked
    // If we wanted to not leak them, devRandThread could copy to its stack and free the heap copy
    pthread_mutex_lock(&devRandThreadMutex);
    doWithCheck( pthread_create(&devRandomPthread, NULL, devRandThread, (void*)&params[0]),
		 "pthread_create /dev/random pthread" );
    pthread_cond_wait(&devRandThreadReady, &devRandThreadMutex);
    // we should unlock then lock the mutex again, but just leave the mutex locked
    // assuming: unlock -> lock = ID?
    doWithCheck( pthread_create(&devUrandomPthread, NULL, devRandThread, (void*)&params[1]),
		 "pthread_create /dev/urandom pthread" );
    pthread_cond_wait(&devRandThreadReady, &devRandThreadMutex);
    pthread_mutex_unlock(&devRandThreadMutex);
    pthread_mutex_destroy(&devRandThreadMutex);

    // allow tracee to unblock. it maybe dangerous if tracee runs too early, when devrandPthread and/or
    // devUrandPthread is not ready: the tracee could have exited before the pthreads are created, hence
    // the FifoPath might have be deleted by the tracee already.
    int ready = 1;
    doWithCheck(write(pipefds[1], (const void*)&ready, sizeof(int)), "spawnTracerTracee, pipe write");
 
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

    int exit_code = exe.runProgram();

    // do exra house keeping.
    doTracerCleanup(true, std::move(cloneArgs->tmpdir));
    return exit_code;
  } else if (pid == 0) {
    int ready = 0;
    doWithCheck(read(pipefds[0], &ready, sizeof(int)), "spawnTracerTracee, pipe read");
    assert(ready == 1);
    return runTracee(args);
  }
  return -1;
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

  cxxopts::Options options("dettrace",
	 "Provides a container for dynamic determinism enforcement.\n"
	 "Arbitrary programs run inside (guests) become deterministic \n"
	 "functions of their inputs. Configuration flags control which inputs \n"
	 "are allowed to affect the guest’s execution.\n");

  options
    .positional_help("[-- program [programArgs..]]");

  options.add_options()
    ( "help",
      "display this help dialogue");

  options.add_options(
     "1. Container Initial Conditions\n"
    " -------------------------------\n"
    " The host file system is visible to the guest, by default excluding\n"
    " /proc and /dev.  The guest computation is a function of host file\n"
    " contents, but not timestamps (or inodes).  Typically, an existing\n"
    " container or chroot system is used to control the visible files.\n"
    " \n"
    " Aside from files, the below flags control other aspects of the guest\n"
    " starting state.\n\n")

    ( "epoch",
      "Set system epoch (start) time.  Accepts now or yyyy-mm-dd,HH:MM:SS (utc)."
      "The epoch time also becomes the initial atime/mtime on all files visible in"
      "the container.  These timestamps change deterministically as execution proceeds."
      "default is 1993-08-08,22:00:00.",
      cxxopts::value<std::string>())
    ( "prng-seed",
      "Use this string to seed to the PRNG that is used to supply all"
      "randomness accessed by the guest.  This affects both /dev/[u]random and "
      "system calls that create randomness.  The rdrand instruction is disabled for"
      "the guest. default is 4660.",
      cxxopts::value<unsigned int>())
    ( "base-env",
      "empty|minimal|host (default is minimal)."
      "The base environment that is set (before adding additions via --env)."
      "In the `host` setting, we directly inherit the parent process\'s environment."
      "Setting `host` is equivalent to passing `--env V` for each variable in the"
      "current environment."
      "\n"
      "The `minimal` setting provides a minimal deterministic environment, setting"
      "only PATH, HOSTNAME, and HOME to the following "
      "\n"
      "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
      "HOSTNAME=nowhere"
      "HOME=/root"
      "\n"
      "Setting `minimal` is equivalent to passing the above variables via --env.",
      cxxopts::value<string>()->default_value("minimal"))
    ( "e,env",
      "Set an environment variable for the guest.  If the `=str` value "
      "is elided, then the variable is read from the user's environment."
      "this flag can be added multiple times to add multiple envvars.",
      cxxopts::value<std::vector<string>>())
    ( "mount-home",
      "Specify the working directory that dettrace should use as a workspace for the "
      "deterministic process tree, by default it is the current working directory.",
      cxxopts::value<std::string>())
    ( "in-docker",
      "A convenience feature for when launching dettrace in a fresh docker "
      "container, e.g. `docker run dettrace --in-docker cmd`.  This is a shorthand for "
      "  `--fs-host --host-userns --host-pidns --host-mountns --base-env=host`."
      "Docker creates fresh namespaces and controls the base file system, making it "
      "safe to disable these corresponding dettrace features.  However, it "
      "is important to not “docker exec” additional processes into the container, as"
      "it will pollute the deterministic namespaces.",
      cxxopts::value<bool>()->default_value("false"));

  options.add_options(
     "2. Opt-in non-deterministic inputs\n"
    " ----------------------------------\n"
    " All sources of nondeterminism are disabled by default. This ensures\n"
    " the application is maximally isolated from unintended deviation in\n"
    " internal state or outputs caused from environmental deviation.  Activating\n"
    " these flags opts in to individual nondeterministic inputs, allowing\n"
    " implicit, non-reproducible inputs to the guest.  By doing so, you take it\n"
    " upon yourself to guarantee that the guest application either does not use, or\n"
    " is invariant to, these sources of input.\n\n")

    ( "network",
      "By default, networking is disallowed inside the guest, as it is generally"
      "non-reproducible. This flag allows networking syscalls like"
      "socket/send/recv, which become additional implicit inputs to the guest"
      "computation.      ",
      cxxopts::value<bool>()->default_value("false"))
    ( "real-proc",
      "default is no."
      "When set, the program can access the full, nondeterministic /proc and /dev"
      "interfaces.  In the default, disabled setting, deterministic information is"
      "presented in these paths instead.  This overlay presents a canonical virtual"
      "hardware platform to the application.",
      cxxopts::value<bool>()->default_value("false"))
    ( "aslr",
      "Enable Address Space Layout Randomization. ASLR is disabled by default "
      "as it is intrinsically a source of nondeterminism.",
      cxxopts::value<bool>())
    ( "host-userns",
      "Allow access to the host’s user namespace.  By default, dettrace creates"
      "a fresh, deterministic user-namespace when launching the guest, that is,"
      "CLONE_NEWUSER is set when cloning the guest process."
      "It is safe to set --host-userns to `true` when the dettrace process is already"
      "executing in a fresh container, e.g. the root process in a Docker container.",
      cxxopts::value<bool>())
    ( "host-pidns",
      "Allow access to the host’s PID namespace.  By default, dettrace creates"
      "a fresh, deterministic PID namespace when launching the guest.  It is safe"
      "to set this to `true` when the dettrace process is executing inside a fresh"
      "container as the root process.",
      cxxopts::value<bool>())
    ( "host-mountns",
      "Allow dettrace to inherit the mount namespace from the host.  By default,"
      "when this is disabled, dettrace creates a fresh mount namespace.  "
      "Setting to `true` is potentially dangerous.  dettrace may pollute the host"
      "system’s mount namespace and not successfully clean up all of these mounts.",
      cxxopts::value<bool>());

  options.add_options(
     "3. Debugging and logging\n"
    " ------------------------\n")
    ( "debug",
      "set debugging level[0..5]. default is 0 (off).",
      cxxopts::value<int>()->default_value("0"))
    ( "log-file",
      "Path to write log to. If writing to a file, the filename"
      "has a unique suffix appended. default is stderr.",
      cxxopts::value<std::string>())
    ( "with-color",
      "Allow use of ANSI colors in log output. Useful when piping log to a file. default is true.",
      cxxopts::value<bool>())
    ( "print-statistics",
      "Print metadata about process that just ran including: number of system call events"
      " read/write retries, rdtsc, rdtscp, cpuid. default is false\n",
      cxxopts::value<bool>()->default_value("false"));

  // internal options
  options.add_options(
     "4. Internal/Advanced flags you are unlikely to use\n"
    " --------------------------------------------------\n")
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
    ( "timeoutSeconds",
      "Tear down all tracee processes with SIGKILL after this many seconds. default is 0 - indefinite.",
      cxxopts::value<unsigned long>()->default_value("0"))
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

    std::string defaultHome = secure_getenv("HOME");

    args.alreadyInChroot = (static_cast<OptionValue1>(result["already-in-chroot"])).unwrap_or(false);
    args.debugLevel = (static_cast<OptionValue1>(result["debug"])).unwrap_or(0);
    args.useColor = (static_cast<OptionValue1>(result["with-color"])).unwrap_or(false);
    args.logFile = (static_cast<OptionValue1>(result["log-file"])).unwrap_or(emptyString);
    args.printStatistics = (static_cast<OptionValue1>(result["print-statistics"])).unwrap_or(false);
    args.convertUids = (static_cast<OptionValue1>(result["convert-uids"])).unwrap_or(false);
    args.mountHome = (static_cast<OptionValue1>(result["mount-home"])).unwrap_or(defaultHome);
    args.timeoutSeconds = (static_cast<OptionValue1>(result["timeoutSeconds"])).unwrap_or(0);
    args.allow_network = (static_cast<OptionValue1>(result["network"])).unwrap_or(false);
    args.with_aslr = (static_cast<OptionValue1>(result["aslr"])).unwrap_or(false);
    auto use_real_proc = result["real-proc"].as<bool>();       // must have default!
    auto base_env = result["base-env"].as<std::string>();
    args.prng_seed = (static_cast<OptionValue1>(result["prng-seed"])).unwrap_or(0x1234);

    // userns|pidns|mountns default vaules are true
    bool host_userns  = (static_cast<OptionValue1>(result["host-userns"])).unwrap_or(false);
    bool host_pidns   = (static_cast<OptionValue1>(result["host-pidns"])).unwrap_or(false);
    bool host_mountns = (static_cast<OptionValue1>(result["host-mountns"])).unwrap_or(false);
    if (!host_userns) {
      args.clone_ns_flags |= CLONE_NEWUSER;
    }
    if (!host_pidns) {
      args.clone_ns_flags |= CLONE_NEWPID;
    }
    if (!host_mountns) {
      args.clone_ns_flags |= CLONE_NEWNS;
    }

    args.with_proc_overrides = !use_real_proc;
    args.with_devrand_overrides = !use_real_proc;
    args.with_etc_overrides = !use_real_proc;

    // epoch
    {
      if (result["epoch"].count()) {
	auto ts = result["epoch"].as<std::string>();
	if (ts == "now") {
	  args.epoch = time(NULL);
	} else {
	  struct tm tm;
	  if (!strptime(ts.c_str(), "%Y-%m-%d,%H:%M:%S", &tm)) {
	    string errmsg("invalid time for --epoch: ");
	    errmsg += ts;
	    runtimeError(errmsg);
	  }
	  tm.tm_isdst = -1; /* dst auto detect */
	  args.epoch = timegm(&tm);
	}
      }
    }

    if (result["in-docker"].as<bool>()) {
      args.in_docker = true;
      args.clone_ns_flags = 0;
    }

    if (base_env == "host") {
      extern char** environ;
      for (int i = 0; environ[i]; i++) {
	string kv(environ[i]);
	auto j = kv.find('=');
	auto k = kv.substr(0, j);
	auto v = kv.substr(1+j);
	args.envs.insert({k, v});
      }
    } else if (base_env == "minimal") {
      args.envs.insert({"PATH",     "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"});
      args.envs.insert({"HOSTNAME", "nowhare"});
      args.envs.insert({"HOME", "/root"});
    }

    if (args.clone_ns_flags & CLONE_NEWUSER || args.alreadyInChroot) {
      args.envs["HOME"] = "/root";
    }

    if (result["env"].count() > 0) {
      auto kvs = result["env"].as<std::vector<std::string>>();
      for (auto kv: kvs) {
	auto j = kv.find('=');
	auto k = kv.substr(0, j);
	auto v = kv.substr(1+j);
	args.envs.insert({k, v});
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

    if (args.pathToChroot == "") {
      args.userChroot = false;
      const string defaultRoot = "/../root/";
      args.pathToChroot = args.pathToExe + defaultRoot;
    } else {
      args.userChroot = true;
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
static bool fileExists(const string& file) {
  struct stat sb;

  return (stat(file.c_str(), &sb) == 0);
}

/**
 * Wrapper around mount with strings.
 */
static void mountDir(const string& source, const string& target){

  /* Check if source path exists*/
  if (!fileExists(source)) {
    runtimeError("Trying to mount " + source + " => " + target + ". Source file does not exist.\n");
  }

  /* Check if target path exists*/
  if (!fileExists(target))  {
    runtimeError("Trying to mount " + source + " => " + target + ". Target file does not exist.\n");    
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
// Create a blank file with sensible permissions.
static void createFileIfNotExist(const string& path){
  if(fileExists(path)){
    return;
  }

  int fd;
  doWithCheck((fd = open(path.c_str(), O_RDWR | O_CREAT, S_IRUSR | S_IRGRP | S_IROTH)),
              "Unable to create file: " + path);
  if (fd >= 0) close(fd);

  return;
} 
