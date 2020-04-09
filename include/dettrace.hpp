#ifndef DETTRACE_H
#define DETTRACE_H

#include <time.h>

extern "C" {

struct SyscallState {
  bool noop;
};

typedef long (*SysEnter)(
    void* data,
    struct SyscallState* s,
    int pid,
    int tid,
    int syscallno,
    unsigned long arg0,
    unsigned long arg1,
    unsigned long arg2,
    unsigned long arg3,
    unsigned long arg4,
    unsigned long arg5);

typedef long (*SysExit)(
    void* data,
    struct SyscallState* s,
    int pid,
    int tid,
    int syscallno,
    unsigned long retval,
    unsigned long arg0,
    unsigned long arg1,
    unsigned long arg2,
    unsigned long arg3,
    unsigned long arg4,
    unsigned long arg5);

/// Represents a mount. These parameters are passed directly to mount(2).
typedef struct {
  const char* source;
  const char* target;
  const char* fstype;
  unsigned long flags;
  const void* data;
} Mount;

/**
 * Options for Dettrace.
 */
typedef struct {
  // Name of the program.
  const char* program;

  // List of arguments. The first argument should be a pointer to the program
  // name. As expected by execvpe, this needs to be a NULL terminated array.
  char* const* argv;

  // The environment variables. As expected by execvpe, this needs to be a NULL
  // terminated array.
  char* const* envs;

  // Working directory to chdir() into before the execvpe().
  const char* workdir;

  // stdio file descriptors.
  int stdin;
  int stdout;
  int stderr;

  // Flags to use to when clone()ing.
  int clone_ns_flags;

  // The timeout in seconds before the tracee is killed. Set to 0 for no
  // timeout (i.e., indefinite).
  unsigned int timeout;

  // Callback function to run before each time a syscall is made. If NULL, the
  // callback is not executed.
  SysEnter sys_enter;

  // Callback function to run after each time a syscall is made. If NULL, the
  // callback is not executed.
  SysExit sys_exit;

  // Pointer to some data that will be passed to each sys_enter and sys_exit
  // call.
  void* user_data;

  // The beginning of time we will use.
  time_t epoch;

  // The number of microseconds to increment the clock.
  unsigned long clock_step;

  // The seed to use for /dev/[u]random and other random-related system calls.
  unsigned short prng_seed;

  // Whether or not to allow networking.
  bool allow_network;

  // Whether or not ASLR should be on or off.
  bool with_aslr;

  bool convert_uids;

  // NULL terminated array of mounts.
  Mount* const* mounts;

  // Directory to chroot into.
  const char* chroot_dir;

  // Mount our own deterministic /dev/[u]random fifo pipes.
  bool with_devrand_overrides;

  // Logging options
  int debug_level;
  bool use_color;
  bool print_statistics;
  const char* log_file;
} TraceOptions;

/**
 * Spawns the tracee process. If no mount options are provided, we assume that
 * the container has already been created and we are chrooted.
 *
 * If the return value is -1, an error has occured attempting to spawn
 * the process. Otherwise, the pid of the child is returned.
 */
pid_t dettrace(const TraceOptions* options);

} // extern "C"

#endif // DETTRACE_H
