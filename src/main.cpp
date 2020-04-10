#include <getopt.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/types.h>
#include <sys/wait.h>

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>

#include <cstdlib>
#include <iostream>
#include <string>
#include <vector>

#include "dettrace.hpp"
#include "logicalclock.hpp"
#include "util.hpp"
#define CXXOPTS_NO_RTTI 1 // no rtti for cxxopts, this should be default.
#define CXXOPTS_VECTOR_DELIMITER '\0'
#include <cxxopts.hpp>

// Allow the build to override the location of the root file system. Useful if
// the installer needs to put the rootfs elsewhere.
#ifndef DETTRACE_ROOTFS
#define DETTRACE_ROOTFS ""
#endif

/** * Useful link for understanding ptrace as it works with execve.
 * https://stackoverflow.com/questions/7514837/why-does
 * https://stackoverflow.com/questions/47006441/ptrace-catching-many-traps-for-execve/47039345#47039345
 */

using namespace std;

struct MountPoint {
  string source;
  string target;
  string fstype;
  unsigned long flags = MS_BIND;
  string data;
  bool is_valid(void) const { return !source.empty() && !target.empty(); }
};

struct programArgs {
  int argc;
  char** argv;

  std::vector<std::string> args;
  int debugLevel;
  std::string pathToChroot;
  std::vector<MountPoint> volume;
  std::string logFile;
  std::string workdir;

  bool useColor;
  bool printStatistics;
  // We sometimes want to run dettrace inside a chrooted environment.
  // Annoyingly, Linux does not let us create a user namespace if the current
  // process is chrooted. This is a feature. So we handle this special case, by
  // allowing dettrace to treat the current environment as a chroot.
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
  time_t epoch;
  unsigned long clock_step;
  unsigned long clone_ns_flags;

  unsigned short prng_seed;
  bool in_docker;

  programArgs(int argc, char* argv[]) {
    this->argc = argc;
    this->argv = argv;
    this->debugLevel = 0;
    this->pathToChroot = DETTRACE_ROOTFS;
    this->useContainer = false;
    this->useColor = true;
    this->logFile = "";
    this->printStatistics = false;
    this->convertUids = false;
    this->alreadyInChroot = false;
    this->timeoutSeconds = 0;
    this->epoch = 744847200UL;
    this->clock_step = 1;
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
static int run_main(programArgs& args);

static std::vector<std::unique_ptr<char[]>> make_argv(
    std::vector<std::string>& args);
static std::vector<std::unique_ptr<char[]>> make_envp(
    std::unordered_map<std::string, std::string>& envvars);
static std::vector<std::unique_ptr<Mount>> make_mounts(
    const std::vector<MountPoint>& mounts);

// =======================================================================================

/**
 * Given a program through the command line, spawn a child thread, call PTRACEME
 * and exec the given program. The parent will use ptrace to intercept and
 * determinize the through system call interception.
 */
int main(int argc, char** argv) {
  programArgs args = parseProgramArguments(argc, argv);

  return run_main(args);
}

static int run_main(programArgs& args) {
  // Check for debug environment variable.
  char* debugEnvvar = secure_getenv("dettraceDebug");
  if (debugEnvvar != nullptr) {
    string str{debugEnvvar};
    try {
      args.debugLevel = stoi(str);
    } catch (...) {
      runtimeError("Invalid integer: " + str);
    }

    if (args.debugLevel < 0 || args.debugLevel > 5) {
      runtimeError("Debug level must be between [0,5].");
    }
  }

  // Set up new user namespace. This is needed as we will have root access
  // withing our own user namespace. Other namepspace commands require
  // CAP_SYS_ADMIN to work. Namespaces must must be done before fork. As changes
  // don't apply until after fork, to all child processes.
  if (args.alreadyInChroot) {
    args.clone_ns_flags &= ~CLONE_NEWUSER;
  }
  int cloneFlags = args.clone_ns_flags;

  // Requires SIGCHILD otherwise parent won't be notified of parent exit.
  // We use clone instead of unshare so that the current process does not live
  // in the new user namespace, this is a requirement for writing multiple UIDs
  // into the uid mappings.

  // Create program arguments.
  auto argv = make_argv(args.args);
  VERIFY(argv.size() > 0);

  // Create environment.
  // NOTE: gcc needs to be somewhere along PATH or it gets very confused, see
  // https://github.com/dettrace/dettrace/issues/23
  auto envs = make_envp(args.envs);

  // Create our list of mounts.
  std::vector<MountPoint> mounts;

  if (args.with_proc_overrides) {
    mounts.push_back(MountPoint{.source = args.pathToChroot + "/proc/meminfo",
                                .target = "/proc/meminfo"});
    mounts.push_back(MountPoint{.source = args.pathToChroot + "/proc/stat",
                                .target = "/proc/stat"});
    mounts.push_back(
        MountPoint{.source = args.pathToChroot + "/proc/filesystems",
                   .target = "/proc/filesystems"});
  }

  if (args.with_etc_overrides) {
    mounts.push_back(MountPoint{.source = args.pathToChroot + "/etc/hosts",
                                .target = "/etc/hosts"});
    mounts.push_back(MountPoint{.source = args.pathToChroot + "/etc/passwd",
                                .target = "/etc/passwd"});
    mounts.push_back(MountPoint{.source = args.pathToChroot + "/etc/group",
                                .target = "/etc/group"});
    mounts.push_back(
        MountPoint{.source = args.pathToChroot + "/etc/ld.so.cache",
                   .target = "/etc/ld.so.cache"});
  }

  // Add all the user-specified mounts *after* so that they can override our
  // defaults if needed.
  mounts.insert(mounts.end(), args.volume.begin(), args.volume.end());

  auto mountPtrs = make_mounts(mounts);

  TraceOptions options{
      .program = argv[0].get(),
      .argv = (char* const*)(argv.data()),
      .envs = (char* const*)(envs.data()),
      .workdir = args.workdir.c_str(),
      .stdin = -1, // inherit stdin
      .stdout = -1, // inherit stdout
      .stderr = -1, // inherit stderr
      .clone_ns_flags = cloneFlags,
      .timeout = args.timeoutSeconds,
      .sys_enter = nullptr,
      .sys_exit = nullptr,
      .user_data = nullptr,
      .epoch = args.epoch,
      .clock_step = args.clock_step,
      .prng_seed = args.prng_seed,
      .allow_network = args.allow_network,
      .with_aslr = args.with_aslr,
      .convert_uids = args.convertUids,
      .mounts = (Mount* const*)(mountPtrs.data()),
      .chroot_dir = nullptr,
      .with_devrand_overrides = args.with_devrand_overrides,
      .debug_level = args.debugLevel,
      .use_color = args.useColor,
      .print_statistics = args.printStatistics,
      .log_file = args.logFile.c_str(),
  };

  pid_t pid = dettrace(&options);
  if (pid == -1) {
    return 1;
  }

  // Propagate Child's exit status to use as our own exit status.
  int status;
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
  char path[1 + REAL_PATH_LEN] = {
      0,
  };
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

  while (nb >= 0 && path[nb] != '/') --nb;
  path[nb] = '\0';
  return path;
#undef REAL_PATH_LEN
#undef PROC_PID_EXE_LEN
}

/**
 * Creates vector of environment variables whose binary representation is
 * compatible with execvpe. Using a vector of unique pointers ensures that it is
 * deallocated in case execvpe fails.
 */
static std::vector<std::unique_ptr<char[]>> make_envp(
    std::unordered_map<std::string, std::string>& envvars) {
  // Use a unique ptr to ensure that everything gets deallocated properly.
  std::vector<std::unique_ptr<char[]>> envs;
  envs.reserve(envvars.size() + 1);

  for (const auto& v : envvars) {
    // Add +2 for the '=' and '\0'.
    const auto size = v.first.size() + v.second.size() + 2;
    auto p = new char[size];
    snprintf(p, size, "%s=%s", v.first.c_str(), v.second.c_str());
    envs.push_back(std::unique_ptr<char[]>(p));
  }

  envs.push_back(nullptr);

  return envs;
}

/**
 * Creates a vector of pointers to the given mounts. Note that the mounts passed
 * in must outlive the returned vector of pointers.
 */
static std::vector<std::unique_ptr<Mount>> make_mounts(
    const std::vector<MountPoint>& mounts) {
  std::vector<std::unique_ptr<Mount>> ptrs;
  ptrs.reserve(mounts.size() + 1);

  for (const auto& v : mounts) {
    auto mount = new Mount;
    mount->source = v.source.empty() ? nullptr : v.source.c_str();
    mount->target = v.target.empty() ? nullptr : v.target.c_str();
    mount->fstype = v.fstype.empty() ? nullptr : v.fstype.c_str();
    mount->flags = v.flags;
    mount->data = v.data.empty() ? nullptr : v.data.c_str();
    ptrs.push_back(std::unique_ptr<Mount>(mount));
  }

  ptrs.push_back(nullptr);

  return ptrs;
}

/**
 * Creates vector of arguments whose binary representation is compatible with
 * execvpe. Using a vector of unique pointers ensures that it is deallocated in
 * case execvpe fails.
 */
static std::vector<std::unique_ptr<char[]>> make_argv(
    std::vector<std::string>& args) {
  std::vector<std::unique_ptr<char[]>> argv;
  argv.reserve(argv.size() + 1);

  for (const auto& arg : args) {
    const auto size = arg.size() + 1;
    auto p = new char[size];
    std::memcpy(p, arg.c_str(), size);
    argv.push_back(std::unique_ptr<char[]>(p));
  }

  argv.push_back(nullptr);

  return argv;
}

// unwrap_or (default) OptionValue
class OptionValue1 : public cxxopts::OptionValue {
public:
  explicit OptionValue1(cxxopts::OptionValue value) {
    m_value = std::move(value);
  }
  template <typename T>
  const T& unwrap_or(const T& default_value) const {
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
programArgs parseProgramArguments(int argc, char* argv[]) {
  programArgs args(argc, argv);

  // clang-format off
  cxxopts::Options options("dettrace",
	 "Provides a container for dynamic determinism enforcement.\n"
	 "Arbitrary programs run inside (guests) become deterministic \n"
	 "functions of their inputs. Configuration flags control which inputs \n"
	 "are allowed to affect the guest’s execution.\n");

  options
    .positional_help("[-- program [programArgs..]]");

  options.add_options()
    ( "help",
      "Displays this help dialog.")
    ( "version",
      "Displays version information.");

  options.add_options(
     "1. Container Initial Conditions\n"
    " -------------------------------\n"
    " The host file system is visible to the guest by default, excluding\n"
    " /proc and /dev. The guest computation is a function of host file\n"
    " contents, but not timestamps (or inodes). Typically, an existing\n"
    " container or chroot system is used to control the visible files.\n"
    " \n"
    " Aside from files, the below flags control other aspects of the guest\n"
    " starting state.\n\n")

    ( "epoch",
      "Set system epoch (start) time. Accepts `yyyy-mm-dd,HH:MM:SS` (utc). "
      // RN: This is not true YET:
      // "The epoch time also becomes the initial atime/mtime on all files visible in"
      // "the container. These timestamps change deterministically as execution proceeds."
      "The default is `1993-08-08,22:00:00`. Also accepts a `now` value which "
      "permits nondeterministically setting the initial system time to the host time. ",
      cxxopts::value<std::string>())
    ( "clock-step",
      "The number of microseconds to increment the clock each time it is queried.",
      cxxopts::value<unsigned long>())

    ( "prng-seed",
      "Use this string to seed to the PRNG that is used to supply all "
      "randomness accessed by the guest. This affects both /dev/[u]random and "
      "system calls that create randomness. (The rdrand instruction is disabled for "
      "the guest.) The default PRNG seed is `4660`. ",
      cxxopts::value<unsigned int>())
    ( "base-env",
      "empty|minimal|host (default is minimal). "
      "The base environment that is set before adding additions via --env. "
      "In the `host` setting, we directly inherit the parent process\'s environment. "
      "Setting `host` is equivalent to passing `--env V` for each variable in the "
      "current environment. "
      "The `minimal` setting provides a minimal deterministic environment, setting "
      "only PATH, HOSTNAME, and HOME. ",
      // cxxopts mangles the formatting here, so leaving this out for now -RN:
      // "HOME to the following  \n"
      // "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
      // "HOSTNAME=nowhere"
      // "HOME=/root"
      // "\n"
      // "Setting `minimal` is equivalent to passing the above variables via --env. ",
      cxxopts::value<string>()->default_value("minimal"))
    ( "e,env",
      "Set an environment variable for the guest. If the `=str` value "
      "is elided, then the variable is read from the user's environment. "
      "This flag can be added multiple times to add multiple envvars. ",
      cxxopts::value<std::vector<string>>())
    ( "v,volume",
      "Specify a directory to bind mount . "
      "The syntax of the argument is `hostdir:targetdir`. "
      "The `targetdir` mount point must already exist.",
      cxxopts::value<std::vector<std::string>>())
    ( "w,workdir",
      "Specify working directory (CWD) dettrace should use. "
      "default it is host's `$PWD`.",
      cxxopts::value<std::string>())
    ( "in-docker",
      "A convenience feature for when launching dettrace in a fresh docker "
      "container, e.g. `docker run dettrace --in-docker cmd`. This is a shorthand for "
      // RN: --fs-host was part of this originally. Might be again:
      "  `--host-userns --host-pidns --host-mountns --base-env=host`. "
      "Docker creates fresh namespaces and controls the base file system, making it "
      "safe to disable these corresponding dettrace features. However, it "
      "is important to not “docker exec” additional processes into the container, as "
      "it will pollute the deterministic namespaces. ",
      cxxopts::value<bool>()->default_value("false"));

  options.add_options(
     "2. Opt-in non-deterministic inputs\n"
    " ----------------------------------\n"
    " All sources of nondeterminism are disabled by default. This ensures\n"
    " the application is maximally isolated from unintended deviation in\n"
    " internal state or outputs caused from environmental deviation. Activating\n"
    " these flags opts in to individual nondeterministic inputs, allowing\n"
    " implicit, non-reproducible inputs to the guest. By doing so, you take it\n"
    " upon yourself to guarantee that the guest application either does not use, or\n"
    " is invariant to, these sources of input.\n"
    "\n"
    " All boolean values can be set to `true` or `false`.\n"
    " Setting `--flag` alone is equivalent to `--flag=true`.\n\n"
     )

    ( "network",
      "By default, networking is disallowed inside the guest, as it is generally "
      "non-reproducible. This flag allows networking syscalls like "
      "socket/send/recv, which become additional implicit inputs to the guest "
      "computation.",
      cxxopts::value<bool>()->default_value("false"))
    ( "real-proc",
      "When set, the program can access the full, nondeterministic /proc and /dev "
      "interfaces. In the default, disabled setting, deterministic information is "
      "presented in these paths instead. This overlay presents a canonical virtual "
      "hardware platform to the application.",
      cxxopts::value<bool>()->default_value("false"))
    ( "aslr",
      "Enable Address Space Layout Randomization. ASLR is disabled by default "
      "as it is intrinsically a source of nondeterminism.",
      cxxopts::value<bool>())
    ( "host-userns",
      "Allow access to the host’s user namespace. By default, dettrace creates "
      "a fresh, deterministic user-namespace when launching the guest, that is, "
      "CLONE_NEWUSER is set when cloning the guest process."
      "It is safe to set --host-userns to `true` when the dettrace process is already "
      "executing in a fresh container, e.g. the root process in a Docker container.",
      cxxopts::value<bool>())
    ( "host-pidns",
      "Allow access to the host’s PID namespace. By default, dettrace creates "
      "a fresh, deterministic PID namespace when launching the guest. It is safe "
      "to set this to `true` when the dettrace process is executing inside a fresh "
      "container as the root process.",
      cxxopts::value<bool>())
    ( "host-mountns",
      "Allow dettrace to inherit the mount namespace from the host. By default, "
      "when this is disabled, dettrace creates a fresh mount namespace. "
      "Setting to `true` is potentially dangerous. dettrace may pollute the host "
      "system’s mount namespace and not successfully clean up all of these mounts.",
      cxxopts::value<bool>());

  options.add_options(
     "3. Debugging and logging\n"
    " ------------------------\n")
    ( "debug",
      "set debugging level[0..5]. The default is `0` (off).",
      cxxopts::value<int>()->default_value("0"))
    ( "log-file",
      "Path to write log to. If writing to a file, the filename "
      "has a unique suffix appended. The default is stderr. ",
      cxxopts::value<std::string>())
    ( "with-color",
      "Allow use of ANSI colors in log output. Useful when piping log to a file. The default is `true`. ",
      cxxopts::value<bool>())
    ( "print-statistics",
      "Print metadata about process that just ran including: number of system call events "
      "read/write retries, rdtsc, rdtscp, cpuid. The default is `false`.",
      cxxopts::value<bool>()->default_value("false"));

  // internal options
  options.add_options(
     "4. Internal/Advanced flags you are unlikely to use\n"
    " --------------------------------------------------\n")
    ( "already-in-chroot",
      "The current environment is already the desired chroot. For some reason the "
      " current mount namespace is polluted with our bind mounts (even though we create "
      " our own namespace). Therefore make sure to unshare -m before running dettrace with "
      " this command, either when chrooting or when calling dettrace. The default is `false`.",
      cxxopts::value<bool>()->default_value("false"))
    ( "convert-uids",
      "Some programs attempt to use UIDs not mapped in our namespace. Catch "
      "this behavior for lchown, chown, fchown, fchowat, and dynamically change the UIDS to "
      "0 (root). The default is `false`.",
      cxxopts::value<bool>()->default_value("false"))
    ( "timeoutSeconds",
      "Tear down all tracee processes with SIGKILL after this many seconds. The default is `0` (i.e., indefinite).",
      cxxopts::value<unsigned long>()->default_value("0"))
    ( "program",
      "program to run",
      cxxopts::value<std::string>())
    ( "programArgs",
      "program arguments",
      cxxopts::value<std::vector<std::string>>());
  // clang-format on

  try {
    options.parse_positional("program", "programArgs");
    auto result = options.parse(argc, argv);

    const std::string emptyString("");

    // Display the version if --version is present. This should be in semver
    // format such that it can be parsed by another program.
    if (result.count("version")) {
      std::cout << (APP_VERSION "+build." APP_BUILDID) << std::endl;
      exit(0);
    }

    if (result["help"].count() > 0) {
      std::cout << options.help() << std::endl;
      exit(0);
    }

    args.alreadyInChroot =
        (static_cast<OptionValue1>(result["already-in-chroot"]))
            .unwrap_or(false);
    args.debugLevel = (static_cast<OptionValue1>(result["debug"])).unwrap_or(0);
    args.useColor =
        (static_cast<OptionValue1>(result["with-color"])).unwrap_or(false);
    args.logFile =
        (static_cast<OptionValue1>(result["log-file"])).unwrap_or(emptyString);
    args.printStatistics =
        (static_cast<OptionValue1>(result["print-statistics"]))
            .unwrap_or(false);
    args.convertUids =
        (static_cast<OptionValue1>(result["convert-uids"])).unwrap_or(false);
    args.timeoutSeconds =
        (static_cast<OptionValue1>(result["timeoutSeconds"])).unwrap_or(0);
    args.allow_network =
        (static_cast<OptionValue1>(result["network"])).unwrap_or(false);
    args.with_aslr =
        (static_cast<OptionValue1>(result["aslr"])).unwrap_or(false);
    auto use_real_proc = result["real-proc"].as<bool>(); // must have default!
    auto base_env = result["base-env"].as<std::string>();
    args.prng_seed =
        (static_cast<OptionValue1>(result["prng-seed"])).unwrap_or(0x1234);

    char* cwd = get_current_dir_name();
    string host_cwd(cwd);
    free(cwd);
    args.workdir =
        (static_cast<OptionValue1>(result["workdir"])).unwrap_or(host_cwd);

    // userns|pidns|mountns default vaules are true
    bool host_userns =
        (static_cast<OptionValue1>(result["host-userns"])).unwrap_or(false);
    bool host_pidns =
        (static_cast<OptionValue1>(result["host-pidns"])).unwrap_or(false);
    bool host_mountns =
        (static_cast<OptionValue1>(result["host-mountns"])).unwrap_or(false);
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
          args.epoch = logical_clock::to_time_t(logical_clock::now());
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

    if (result["clock-step"].count()) {
      args.clock_step = result["clock-step"].as<unsigned long>();
    }

    if (result["in-docker"].as<bool>()) {
      args.in_docker = true;
      args.clone_ns_flags = 0;
      base_env = "host";
    }

    if (result["volume"].count()) {
      auto mounts = result["volume"].as<std::vector<std::string>>();
      for (auto v : mounts) {
        MountPoint mountPoint;
        int j = v.find(':');
        if (j == string::npos) {
          mountPoint.source = v;
          mountPoint.target = v;
        } else {
          auto key = v.substr(0, j);
          auto value = v.substr(1 + j);
          mountPoint.source = key;
          mountPoint.target = value;
        }
        args.volume.push_back(mountPoint);
      }
    }

    if (base_env == "host") {
      extern char** environ;
      for (int i = 0; environ[i]; i++) {
        string kv(environ[i]);
        auto j = kv.find('=');
        auto k = kv.substr(0, j);
        auto v = kv.substr(1 + j);
        args.envs.insert({k, v});
      }
    } else if (base_env == "minimal") {
      args.envs.insert(
          {"PATH",
           "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"});
      args.envs.insert({"HOSTNAME", "nowhare"});
      args.envs.insert({"HOME", "/root"});
    } else if (base_env == "empty") {
    } else {
      throw cxxopts::argument_incorrect_type("base-env=" + base_env);
    }

    if (args.clone_ns_flags & CLONE_NEWUSER || args.alreadyInChroot) {
      if (args.envs.find("HOME") != args.envs.end()) {
        args.envs["HOME"] = "/root";
      }
    }

    if (result["env"].count() > 0) {
      auto kvs = result["env"].as<std::vector<std::string>>();
      for (auto kv : kvs) {
        auto j = kv.find('=');
        auto k = kv.substr(0, j);

        if (j == std::string::npos) {
          // If no '=' was specified, get the variable from the host
          // environment. If the host environment variable doesn't exist, don't
          // set it at all.
          if (auto host_env = secure_getenv(k.c_str())) {
            args.envs[k] = std::string(host_env);
          }
        } else {
          args.envs[k] = kv.substr(1 + j);
        }
      }
    }

    args.args.clear();
    if (!result["program"].count()) {
      std::cout << options.help() << std::endl;
      exit(1);
    }
    args.args.push_back(result["program"].as<std::string>());

    const std::vector<std::string> emptyArgs;
    auto traceeArgs =
        (static_cast<OptionValue1>(result["programArgs"])).unwrap_or(emptyArgs);
    std::copy(
        traceeArgs.begin(), traceeArgs.end(), std::back_inserter(args.args));

    if (args.pathToChroot == "") {
      args.pathToChroot = getExePath() + "/../root/";
    }

    // Detect if we're inside a chroot by attempting to make a user namespace.
    if (args.alreadyInChroot) {
      if (unshare(CLONE_NEWUSER) != -1) {
        fprintf(
            stderr,
            "We detected you are not currently running inside a chroot env.\n");
        exit(1);
      }
      // Treat current environment as our chroot.
      args.pathToChroot = "/";
    }
  } catch (cxxopts::option_not_exists_exception& e) {
    std::cerr << "command line parsing exception: " << e.what() << std::endl;
    std::cerr << options.help() << std::endl;
    exit(1);
  }
  return args;
}
