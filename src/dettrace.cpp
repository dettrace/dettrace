#include <iostream>
#include <memory>
#include <string>
#include <vector>

#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <sys/mount.h>
#include <sys/personality.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/reg.h>
#include <sys/select.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/sysmacros.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/vfs.h>
#include <sys/wait.h>
#include <unistd.h>

#include "dettrace.hpp"
#include "devrand.hpp"
#include "execution.hpp"
#include "logicalclock.hpp"
#include "seccomp.hpp"
#include "tempfile.hpp"
#include "util.hpp"
#include "vdso.hpp"

struct CloneArgs {
  const TraceOptions* opts;
  VDSOSymbol* vdso;
  int nb_vdso;
};

static pid_t _dettrace(const TraceOptions* opts);
static int _dettrace_child(const CloneArgs* opts);
static int runTracee(
    const TraceOptions& opts,
    const char* devrandFifoPath,
    const char* devUrandFifoPath);

// See user_namespaces(7)
static void update_map(char* mapping, char* map_file);
static void proc_setgroups_write(pid_t pid, const char* str);

extern "C" pid_t dettrace(const TraceOptions* opts) {
  try {
    return _dettrace(opts);
  } catch (std::runtime_error e) {
    std::cerr << "Error: " << e.what() << "\n";
    return -1;
  } catch (...) {
    std::cerr << "Error: Unknown exception occurred\n";
    return -1;
  }

  return -1;
}

static execution* globalExeObject = nullptr;

void sigalrmHandler(int _) {
  VERIFY(nullptr != globalExeObject);
  globalExeObject->killAllProcesses();
  // TODO: print out message about timeout expiring
  runtimeError("dettrace timeout expired\n");
}

/**
 * Use stat to check if file/directory exists to mount.
 * @return boolean if file exists
 */
static bool fileExists(const char* file) {
  struct stat sb;
  return (stat(file, &sb) == 0);
}

/**
 * Wrapper around mount with strings.
 */
static void mountDir(const char* source, const char* target) {
  /* Check if source path exists*/
  if (!fileExists(source)) {
    runtimeError(
        "Trying to mount " + std::string{source} + " => " +
        std::string{target} + ". Source file does not exist.\n");
  }

  /* Check if target path exists*/
  if (!fileExists(target)) {
    runtimeError(
        "Trying to mount " + std::string{source} + " => " +
        std::string{target} + ". Target file does not exist.\n");
  }

  // TODO: Marking it as private here shouldn't be necessary since we already
  // unshared the entire namespace as private? Notice that we want a bind mount,
  // so MS_BIND is necessary. MS_REC is also necessary to properly work when
  // mounting dirs that are themselves bind mounts, otherwise you will get an
  // error EINVAL as per `man 2 mount`: EINVAL In an unprivileged mount
  // namespace (i.e., a mount namespace owned by  a  user
  //             namespace  that  was created by an unprivileged user), a bind
  //             mount operation (MS_BIND)  was  attempted  without  specifying
  //             (MS_REC),  which  would  have revealed the filesystem tree
  //             underneath one of the submounts of the directory being bound.

  // Note this line causes spurious false positives when running under valgrind.
  // It's okay that these areguments are nullptr.
  if (mount(source, target, nullptr, MS_BIND | MS_PRIVATE | MS_REC, nullptr) ==
      -1) {
    auto err = "Unable to bind mount: " + std::string{source} + " to " +
               std::string{target};
    sysError(err.c_str());
  }
}

/**
 * Creates a blank file with sensible permissions.
 */
static void createFileIfNotExist(const std::string& path) {
  if (fileExists(path.c_str())) {
    return;
  }

  int fd = open(path.c_str(), O_RDWR | O_CREAT, S_IRUSR | S_IRGRP | S_IROTH);
  if (fd == -1) {
    auto err = "Unable to create file: " + path;
    sysError(err.c_str());
  }
  if (fd >= 0) {
    close(fd);
  }

  return;
}

static pid_t _dettrace(const TraceOptions* opts) {
  if (!opts) {
    return -1;
  }

  // our own user namespace. Other namespace commands require CAP_SYS_ADMIN to
  // work. Namespaces must must be done before fork. As changes don't apply
  // until after fork, to all child processes.
  const int STACK_SIZE(1024 * 4096);
  static char child_stack[STACK_SIZE]; /* Space for child's stack */

  doWithCheck(
      prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0),
      "Pre-clone prctl error: setting no new privs");

  struct VDSOSymbol vdsoSyms[8];
  struct ProcMapEntry vdso;
  int numVdsoSyms = 0;

  memset(&vdso, 0, sizeof(vdso));

  if (proc_get_vdso_vvar(getpid(), &vdso, NULL) == 0 && vdso.procMapBase != 0) {
    numVdsoSyms = proc_get_vdso_symbols(&vdso, vdsoSyms, 8);
    if (numVdsoSyms < 4) {
      runtimeError(
          "VDSO symbol map has only " + to_string(numVdsoSyms) +
          ", expect at least 4!");
    }
  }

  auto clone_args = CloneArgs{
      opts,
      vdsoSyms,
      numVdsoSyms,
  };

  pid_t child = clone(
      (int (*)(void*))_dettrace_child, child_stack + STACK_SIZE,
      opts->clone_ns_flags | SIGCHLD, (void*)&clone_args);
  if (child == -1) {
    std::string reason = strerror(errno);
    std::cerr << "clone failed:\n  " + reason << std::endl;
    return -1;
  }

  // This is modified code from user_namespaces(7)
  // see https://lwn.net/Articles/532593/
  /* Update the UID and GID maps for children in their namespace, notice we do
     not live in that namespace. We use clone instead of unshare to avoid moving
     us into to the namespace. This allows us, in the future, to extend the
     mappings to other uids when running as root (not currently implemented, but
     notice this cannot be done when using unshare.)*/
  if ((opts->clone_ns_flags & CLONE_NEWUSER) == CLONE_NEWUSER) {
    char map_path[PATH_MAX];
    const int MAP_BUF_SIZE = 100;
    char map_buf[MAP_BUF_SIZE];
    char* uid_map;
    char* gid_map;

    uid_t uid = getuid();
    gid_t gid = getgid();

    // Set up container to hostOS UID and GID mappings
    snprintf(map_path, PATH_MAX, "/proc/%d/uid_map", child);
    snprintf(map_buf, MAP_BUF_SIZE, "0 %ld 1", (long)uid);
    uid_map = map_buf;
    update_map(uid_map, map_path);

    // Set GID Map
    proc_setgroups_write(child, "deny");
    snprintf(map_path, PATH_MAX, "/proc/%d/gid_map", child);
    snprintf(map_buf, MAP_BUF_SIZE, "0 %ld 1", (long)gid);
    gid_map = map_buf;
    update_map(gid_map, map_path);
  }

  return child;
}

static int _dettrace_child(const CloneArgs* clone_args) {
  if (!clone_args || !clone_args->opts) {
    return 1;
  }

  auto opts = clone_args->opts;

  // Properly set up propagation rules for mounts created by dettrace, that is
  // make this a slave mount (and all mounts underneath this one) so that
  // changes inside this mount are not propegated to the parent mount. This
  // makes sure we don't pollute the host OS' mount space with entries made by
  // us here.
  if ((opts->clone_ns_flags & CLONE_NEWNS) &&
      (opts->clone_ns_flags & CLONE_NEWUSER)) {
    doWithCheck(
        mount("none", "/", NULL, MS_SLAVE | MS_REC, 0),
        "failed to mount / as slave");
  }

  if ((opts->clone_ns_flags & CLONE_NEWPID) == CLONE_NEWPID) {
    pid_t first_pid;
    if ((first_pid = getpid()) != 1) {
      std::string errmsg("PID of first process expected to be 1, got: ");
      errmsg += to_string(first_pid);
      errmsg += "\n";
      runtimeError(errmsg);
    }
  }

  int pipefds[2];

  doWithCheck(pipe2(pipefds, O_CLOEXEC), "spawnTracerTracee pipe2 failed");

  // Create fifo files for /dev/random and /dev/urandom. We can't use the normal
  // C++ish way because we need to avoid any allocations before the `fork()`
  // happens.
  char devrandFifoPath[] = "/tmp/dt-XXXXXX";
  {
    int fd =
        doWithCheck(mkstemp(devrandFifoPath), "failed to mkstemp devrand fifo");
    unlink(devrandFifoPath);
    doWithCheck(
        mkfifo(devrandFifoPath, 0666), "failed creating /dev/random fifo");
    close(fd);
  }

  char devUrandFifoPath[] = "/tmp/dt-XXXXXX";
  {
    int fd = doWithCheck(
        mkstemp(devUrandFifoPath), "failed to mkstemp devurand fifo");
    unlink(devUrandFifoPath);
    doWithCheck(
        mkfifo(devUrandFifoPath, 0666), "failed creating /dev/urandom fifo");
    close(fd);
  }

  pid_t pid = fork();
  if (pid < 0) {
    runtimeError("fork() failed.\n");
    exit(EXIT_FAILURE);
  } else if (pid > 0) {
    // We must mount proc so that the tracer sees the same PID and /proc/
    // directory as the tracee. The tracee will do the same so it sees /proc/
    // under it's chroot.
    if ((opts->clone_ns_flags & CLONE_NEWNS) == CLONE_NEWNS &&
        (opts->clone_ns_flags & CLONE_NEWPID) == CLONE_NEWPID) {
      doWithCheck(
          mount("none", "/proc/", "proc", MS_MGC_VAL, nullptr),
          "tracer mounting proc failed");
    }

    if ((opts->clone_ns_flags & CLONE_NEWNS) == CLONE_NEWNS) {
      doWithCheck(
          mount(
              "none", "/dev/pts", "devpts", MS_MGC_VAL,
              "newinstance,ptmxmode=0666"),
          "tracer mounting devpts failed");
      mountDir("/dev/ptmx", "/dev/pts/ptmx");
    }

    if (!fileExists(devrandFifoPath)) {
      runtimeError("cannot create psudo /dev/random fifo");
    }

    if (!fileExists(devUrandFifoPath)) {
      runtimeError("cannot create psudo /dev/urandom fifo");
    }

    // Make the threads for /dev/random and /dev/urandom. We change the seed
    // such that they output different numbers as one would expect.
    auto dev_random =
        RandThread{devrandFifoPath,
                   static_cast<unsigned short>(opts->prng_seed + 1234567890)};
    auto dev_urandom =
        RandThread{devUrandFifoPath,
                   static_cast<unsigned short>(opts->prng_seed + 234567890)};

    // allow tracee to unblock. it maybe dangerous if tracee runs too early,
    // when devrandPthread and/or devUrandPthread is not ready: the tracee could
    // have exited before the pthreads are created, hence the FifoPath might
    // have be deleted by the tracee already.
    int ready = 1;
    doWithCheck(
        write(pipefds[1], (const void*)&ready, sizeof(int)),
        "spawnTracerTracee, pipe write");

    const char* log_file = opts->log_file ? opts->log_file : "";

    execution exe{opts->debug_level,
                  pid,
                  opts->use_color,
                  log_file,
                  opts->print_statistics,
                  clone_args->vdso,
                  clone_args->nb_vdso,
                  opts->prng_seed,
                  opts->allow_network,
                  logical_clock::from_time_t(opts->epoch),
                  chrono::microseconds(opts->clock_step),
                  opts->sys_enter,
                  opts->sys_exit,
                  opts->user_data};

    globalExeObject = &exe;
    struct sigaction sa;
    sa.sa_handler = sigalrmHandler;
    doWithCheck(sigemptyset(&sa.sa_mask), "sigemptyset");
    sa.sa_flags = 0;
    doWithCheck(sigaction(SIGALRM, &sa, NULL), "sigaction(SIGALRM)");
    alarm(opts->timeout);

    int exit_code = exe.runProgram();

    // Clean up
    dev_random.shutdown();
    dev_urandom.shutdown();

    for (int fd = 3; fd < 256; fd++) {
      // Close all file descriptors
      close(fd);
    }

    umount("/tmp");

    unlink(devrandFifoPath);
    unlink(devUrandFifoPath);

    return exit_code;
  } else if (pid == 0) {
    int ready = 0;
    doWithCheck(
        read(pipefds[0], &ready, sizeof(int)), "spawnTracerTracee, pipe read");
    VERIFY(ready == 1);
    return runTracee(*opts, devrandFifoPath, devUrandFifoPath);
  }

  return -1;
}

// This function runs in the child (i.e., the tracee).
static int runTracee(
    const TraceOptions& opts,
    const char* devrandFifoPath,
    const char* devUrandFifoPath) {
  // Set stdio file descriptors. This gives the parent process the ability to
  // control the stdio file descriptors. Note that dup2 closes the destination
  // file descriptor and will do nothing if both file descriptor arguments are
  // the same.
  if (opts.stdin != -1) {
    doWithCheck(dup2(opts.stdin, STDIN_FILENO), "dup2 stdin");
  }
  if (opts.stdout != -1) {
    doWithCheck(dup2(opts.stdout, STDOUT_FILENO), "dup2 stdout");
  }
  if (opts.stderr != -1) {
    doWithCheck(dup2(opts.stderr, STDERR_FILENO), "dup2 stderr");
  }

  if (!opts.with_aslr) {
    // Disable ASLR for our child
    doWithCheck(
        personality(PER_LINUX | ADDR_NO_RANDOMIZE), "Unable to disable ASLR");
  }

  if ((opts.clone_ns_flags & CLONE_NEWNS) == CLONE_NEWNS) {
    if (!fileExists("/dev/null")) {
      // we're running under reprotest as sudo, so we can use real mknod
      // hat tip to:
      // https://unix.stackexchange.com/questions/27279/how-to-create-dev-null
      dev_t dev = makedev(1, 3);
      mode_t mode =
          S_IFCHR | S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH;
      doWithCheck(mknod("/dev/null", mode, dev), "mknod");
    }

    if (opts.with_devrand_overrides) {
      createFileIfNotExist("/dev/random");
      mountDir(devrandFifoPath, "/dev/random");
      createFileIfNotExist("/dev/urandom");
      mountDir(devUrandFifoPath, "/dev/urandom");
    }

    // if (opts.mount.chroot_dir) {
    //  const auto pathToChroot = std::string{opts.mount.chroot_dir};

    //  if (opts.mount.with_proc_overrides) {
    //    mountDir(pathToChroot + "/proc/meminfo", "/proc/meminfo");
    //    mountDir(pathToChroot + "/proc/stat", "/proc/stat");
    //    mountDir(pathToChroot + "/proc/filesystems", "/proc/filesystems");
    //  }

    //  if (opts.mount.with_etc_overrides) {
    //    mountDir(pathToChroot + "/etc/hosts", "/etc/hosts");
    //    mountDir(pathToChroot + "/etc/passwd", "/etc/passwd");
    //    mountDir(pathToChroot + "/etc/group", "/etc/group");
    //    mountDir(pathToChroot + "/etc/ld.so.cache", "/etc/ld.so.cache");
    //  }
    //}

    if (opts.mounts) {
      auto mounts = opts.mounts;

      while (const Mount* m = *mounts) {
        if (mount(m->source, m->target, m->fstype, m->flags, m->data) == -1) {
          auto err = "Unable to bind mount: " +
                     std::string{m->source ? m->source : "none"} + " to " +
                     std::string{m->target ? m->target : "none"};
          sysError(err.c_str());
        }
        ++mounts;
      }
    }

    // chroot
    if (opts.chroot_dir) {
      if (chroot(opts.chroot_dir) == -1) {
        auto err = std::string{"unable to chroot to "} + opts.chroot_dir;
        sysError(err.c_str());
      }
    }

    // this have to be done before mount /dev/{u}random because the source file
    // is under previous /tmp
    doWithCheck(
        mount("none", "/tmp", "tmpfs", 0, NULL), "mount /tmp as tmpfs failed");
  }

  // set working dir
  if (opts.workdir) {
    if (chdir(opts.workdir) == -1) {
      auto err = std::string{"unable to chdir to "} + opts.workdir;
      sysError(err.c_str());
    }
  }

  // trap on rdtsc/rdtscp insns
  doWithCheck(
      prctl(PR_SET_TSC, PR_TSC_SIGSEGV, 0, 0, 0), "Pre-clone prctl error");
  doWithCheck(
      prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0),
      "Pre-clone prctl error: setting no new privs");

  // Perform execve based on user command.
  ptracer::doPtrace(PTRACE_TRACEME, 0, NULL, NULL);

  // Set up seccomp + bpf filters using libseccomp.
  // Default action to take when no rule applies to system call. We send a
  // PTRACE_SECCOMP event message to the tracer with a unique data: INT16_MAX
  seccomp myFilter{opts.debug_level, opts.convert_uids};

  // Stop ourselves until the tracer is ready. This ensures the tracer has time
  // to get set up.
  raise(SIGSTOP);

  myFilter.loadFilterToKernel();

  // execvpe() duplicates the actions of the shell in searching for an
  // executable file if the specified filename does not contain a slash (/)
  // character.
  int val = execvpe(opts.program, opts.argv, opts.envs);
  if (val == -1) {
    if (errno == ENOENT) {
      cerr << "Unable to exec your program (" << opts.program
           << "). No such executable found\n"
           << endl;
      cerr << "This program may not exist inside the chroot." << endl;
      cerr << "Only programs in bin/ or in this directory tree are mounted."
           << endl;
    }
    cerr << "Unable to exec your program. Reason:\n  "
         << std::string{strerror(errno)} << endl;
    cerr << "Ending tracer with SIGABTR signal." << endl;

    // Parent is waiting for us to exec so it can trace traceeCommand, this
    // isn't going to happen. End parent with signal.
    pid_t ppid = getppid();
    syscall(SYS_tgkill, ppid, ppid, SIGABRT);
  }

  return 0;
}

static void update_map(char* mapping, char* map_file) {
  int fd = open(map_file, O_WRONLY);
  if (fd == -1) {
    fprintf(stderr, "ERROR: open %s: %s\n", map_file, strerror(errno));
    exit(EXIT_FAILURE);
  }
  ssize_t map_len = strlen(mapping);
  if (write(fd, mapping, map_len) != map_len) {
    fprintf(stderr, "ERROR: write %s: %s\n", map_file, strerror(errno));
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
static void proc_setgroups_write(pid_t pid, const char* str) {
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
      fprintf(stderr, "ERROR: open %s: %s\n", setgroups_path, strerror(errno));
    return;
  }

  if (write(fd, str, strlen(str)) == -1)
    fprintf(stderr, "ERROR: write %s: %s\n", setgroups_path, strerror(errno));

  close(fd);
}
