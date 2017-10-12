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

#include <iostream>

#include "logger.hpp"
#include "valueMapper.hpp"
#include "systemCallList.hpp"
#include "util.hpp"
#include <stdarg.h>

using namespace std;
// =======================================================================================
#define STRINGIZE(x) STRINGIZE2(x)
#define STRINGIZE2(x) #x
#define __LINE_STRING__ STRINGIZE(__LINE__)

// error check macro c/o http://stackoverflow.com/questions/6932401/elegant-error-checking
#define CHECK(x) do {					\
    int retval = (x);					\
    if (retval != 0) {					\
      perror(#x " " __FILE__ ":" __LINE_STRING__);	\
      exit(EXIT_FAILURE);				\
    }							\
  } while (0)

#define Swap4Bytes(val)							\
  ( (((val) >> 24) & 0x000000FF) | (((val) >>  8) & 0x0000FF00) |	\
    (((val) <<  8) & 0x00FF0000) | (((val) << 24) & 0xFF000000) )

#define Swap8Bytes(val)							\
  ( (((val) >> 56) & 0x00000000000000FF) | (((val) >> 40) & 0x000000000000FF00) | \
    (((val) >> 24) & 0x0000000000FF0000) | (((val) >>  8) & 0x00000000FF000000) | \
    (((val) <<  8) & 0x000000FF00000000) | (((val) << 24) & 0x0000FF0000000000) | \
    (((val) << 40) & 0x00FF000000000000) | (((val) << 56) & 0xFF00000000000000) )
// =======================================================================================
// Stolen from libdet.c...
extern const char *__progname; // Saved by glibc.
// =======================================================================================

string handleSyscall(pid_t tracee, long syscallNumber, struct user_regs_struct* regs,
		     int debugLevel);
pair<int, int> parseProgramArguments(int argc, char* argv[]);
// =======================================================================================
int main(int argc, char** argv) {
  pid_t tracee;
  bool setOptionsOnTracee = false;
  int optIndex, debugLevel;
  tie(optIndex, debugLevel) = parseProgramArguments(argc, argv);

  // Plus one for exectuable's name, Plus one for NULL at the end.
  int newArgc = argc - optIndex + 1 + 1;

  tracee = fork();
  if(tracee == 0){
    CHECK(ptrace(PTRACE_TRACEME, 0, NULL, NULL));

    char* traceeCommand[newArgc];
    memcpy(traceeCommand, & argv[optIndex], newArgc * sizeof(char*));
    traceeCommand[newArgc - 1] = NULL;

    execvp(traceeCommand[0], traceeCommand);

  } else { // tracer
    while (1) {
      int status;
      tracee = wait(&status);

      // check if tracee has exited
      if (WIFEXITED(status)) { break; }

      // set options
      if (!setOptionsOnTracee) {
        CHECK(ptrace(PTRACE_SETOPTIONS, tracee, NULL, PTRACE_O_TRACECLONE | PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK));
        setOptionsOnTracee = true;
      }

      struct user_regs_struct regs;
      CHECK(ptrace(PTRACE_GETREGS, tracee, NULL, &regs));

      string syscallName = handleSyscall(tracee, regs.orig_rax, &regs, debugLevel);

      // let tracee run until its next syscall
      CHECK(ptrace(PTRACE_SYSCALL, tracee, NULL, NULL));
    }
  }
  return 0;
}
// =======================================================================================
/** Reads a NULL-delimited string from the given tracee. The contents of the
    string are returned as a C++ string. */

// TODO: This function seems more complicated than need be?
string readTraceeCString(pid_t tracee, uint64_t cstringPtr) {
  string r;
  bool done = false;
  while (!done) {
    // NB: a long is 8B on a 64-bit platform
    long result = ptrace(PTRACE_PEEKDATA, tracee, cstringPtr, NULL);
    const char* p = (const char*) &result;
    const size_t len = strnlen(p, sizeof(long));
    if (sizeof(long) != len) {
      done = true;
    }
    for (unsigned i = 0; i < len; i++) {
      r += p[i];
    }
    cstringPtr += len;
  }

  return r;
}
// =======================================================================================
void copyFromTracee(long* dst, long* src, const pid_t tracee, const uint32_t bytesToCopy) {
  uint32_t bytesTransferred = 0;
  long *myDst = dst, *traceeSrc = src;
  while (bytesTransferred < bytesToCopy) {
    // NB: this will potentially read >bytesToCopy bytes from tracee, but writes only bytesToCopy bytes to dst
    long result = ptrace(PTRACE_PEEKDATA, tracee, traceeSrc, NULL);
    memcpy(myDst, &result,
	   min(bytesToCopy-bytesTransferred,(uint32_t)sizeof(long)));
    bytesTransferred += sizeof(long);
    myDst++;
    traceeSrc++;
  }
}
// =======================================================================================
void copyToTracee(long* dst, long* src, const pid_t tracee, const uint32_t bytesToCopy) {
  uint32_t bytesTransferred = 0;
  long *traceeDst = dst, *mySrc = src;
  while (bytesTransferred < bytesToCopy) {

    if (bytesToCopy - bytesTransferred >= sizeof(long)) {
      CHECK(ptrace(PTRACE_POKEDATA, tracee, traceeDst, *mySrc));
      bytesTransferred += sizeof(long);

    } else { // handle final transfer of <sizeof(long) bytes
      uint32_t transferSize = bytesToCopy - bytesTransferred;
      // read existing memory from tracee
      long origTraceeMem = ptrace(PTRACE_PEEKDATA, tracee, traceeDst, NULL);
      // overwrite the bytes we need to change
      memcpy(&origTraceeMem, src, transferSize);
      // copy merged result back to tracee
      CHECK(ptrace(PTRACE_POKEDATA, tracee, traceeDst, origTraceeMem));
      bytesTransferred += transferSize;
    }

    traceeDst++;
    mySrc++;
  }
}
// =======================================================================================
void killTracee(string syscallName, pid_t tracee){
  cerr << "killing tracee " << tracee << " that made unsupported syscall: "
       << syscallName << endl;
  CHECK(kill(tracee, SIGKILL));
}
// =======================================================================================
// This function is exectuted twice by Ptrace. Once before the system call is executed
// and again after. We use our static variable @preSyscall to tell which case we are in.

// Note: syscall arguments are passed in %rdi, %rsi, %rdx, %r10, %r8 and %r9,
// (in that order).

// These system calls were greped from ... in Linux Kernel Version ...
string handleSyscall(pid_t tracee, long syscallNumber, struct user_regs_struct* regs,
		     int debugLevel){
  static bool preSyscall = true;
  bool syscallReturns = true;

  // FILE* fout = fopen("detbox.log", "w");
  static logger myLog = logger(stderr, debugLevel);

  // Holds mappings from real PIDs to Virtual PIDs (VPIDs).
  static valueMapper pidMap = valueMapper(myLog, "pidMap");

  // Unkown system call.
  if(syscallNumber > 0 && syscallNumber > SYSTEM_CALL_COUNT){
    myLog.writeToLog(Importance::error, "Error: Unknow system call number: %d\n",
		     syscallNumber);
    exit(1);
  }

  string syscallName = systemCallMappings[syscallNumber];

  // TODO: BUG: Something is wrong with the alternating between preSyscall and postSyscall:
  // Check out the output from running:
  // ./detTrace --debug 4 ls
  // [Detbox 12879] Intercepted call to: execve
  // [Detbox 12879] Completed call to: brk
  // [Detbox 12879] Intercepted call to: brk

  // Notice how the order goes awry after execve, this is probably because execve does
  // not return.


  if(preSyscall){
    myLog.writeToLog(Importance::inter, "Intercepted call to: %s\n", syscallName.c_str());
    myLog.setPadding();
  }else{
    myLog.writeToLog(Importance::inter, "Completed call to: %s\n", syscallName.c_str());
    myLog.unsetPadding();
  }

  switch(syscallNumber){
  case SYS__sysctl:
    break;
  case SYS_accept:
    break;
  case SYS_accept4:
    break;
  case SYS_access:
    break;
  case SYS_acct:
    break;
  case SYS_add_key:
    break;
  case SYS_adjtimex:
    break;
  case SYS_afs_syscall:
    break;
  case SYS_alarm:
    break;
  case SYS_arch_prctl:
    break;
  case SYS_bind:
    break;
  case SYS_bpf:
    break;
  case SYS_brk:
    break;
  case SYS_capget:
    break;
  case SYS_capset:
    break;
  case SYS_chdir:
    break;
  case SYS_chmod:
    break;
  case SYS_chown:
    break;
  case SYS_chroot:
    break;
  case SYS_clock_adjtime:
    break;
  case SYS_clock_getres:
    break;
  case SYS_clock_gettime:
    break;
  case SYS_clock_nanosleep:
    break;
  case SYS_clock_settime:
    break;
  case SYS_clone:
    break;
  case SYS_close:
    break;
  case SYS_connect:
    break;
  case SYS_creat:
    break;
  case SYS_create_module:
    break;
  case SYS_delete_module:
    break;
  case SYS_dup:
    break;
  case SYS_dup2:
    break;
  case SYS_dup3:
    break;
  case SYS_epoll_create:
    break;
  case SYS_epoll_create1:
    break;
  case SYS_epoll_ctl:
    break;
  case SYS_epoll_ctl_old:
    break;
  case SYS_epoll_pwait:
    break;
  case SYS_epoll_wait:
    break;
  case SYS_epoll_wait_old:
    break;
  case SYS_eventfd:
    break;
  case SYS_eventfd2:
    break;
  case SYS_execve:
    break;
  case SYS_execveat:
    break;
  case SYS_exit:
    break;
  case SYS_exit_group:
    break;
  case SYS_faccessat:
    break;
  case SYS_fadvise64:
    break;
  case SYS_fallocate:
    break;
  case SYS_fanotify_init:
    break;
  case SYS_fanotify_mark:
    break;
  case SYS_fchdir:
    break;
  case SYS_fchmod:
    break;
  case SYS_fchmodat:
    break;
  case SYS_fchown:
    break;
  case SYS_fchownat:
    break;
  case SYS_fcntl:
    break;
  case SYS_fdatasync:
    break;
  case SYS_fgetxattr:
    break;
  case SYS_finit_module:
    break;
  case SYS_flistxattr:
    break;
  case SYS_flock:
    break;
  case SYS_fork:
    break;
  case SYS_fremovexattr:
    break;
  case SYS_fsetxattr:
    break;
  case SYS_fstat:
    break;
  case SYS_fstatfs:
    break;
  case SYS_fsync:
    break;
  case SYS_ftruncate:
    break;
  case SYS_futex:
    break;
  case SYS_futimesat:
    break;
  case SYS_get_kernel_syms:
    break;
  case SYS_get_mempolicy:
    break;
  case SYS_get_robust_list:
    break;
  case SYS_get_thread_area:
    break;
  case SYS_getcpu:
    break;
  case SYS_getcwd:
    break;
  case SYS_getdents:
    break;
  case SYS_getdents64:
    break;
  case SYS_getegid:
    break;
  case SYS_geteuid:
    break;
  case SYS_getgid:
    break;
  case SYS_getgroups:
    break;
  case SYS_getitimer:
    break;
  case SYS_getpeername:
    break;
  case SYS_getpgid:
    break;
  case SYS_getpgrp:
    break;
  case SYS_getpid:
    break;
  case SYS_getpmsg:
    break;
  case SYS_getppid:
    break;
  case SYS_getpriority:
    break;
  case SYS_getrandom:
    break;
  case SYS_getresgid:
    break;
  case SYS_getresuid:
    break;
  case SYS_getrlimit:
    break;
  case SYS_getrusage:
    break;
  case SYS_getsid:
    break;
  case SYS_getsockname:
    break;
  case SYS_getsockopt:
    break;
  case SYS_gettid:
    break;
  case SYS_gettimeofday:
    break;
  case SYS_getuid:
    break;
  case SYS_getxattr:
    break;
  case SYS_init_module:
    break;
  case SYS_inotify_add_watch:
    break;
  case SYS_inotify_init:
    break;
  case SYS_inotify_init1:
    break;
  case SYS_inotify_rm_watch:
    break;
  case SYS_io_cancel:
    break;
  case SYS_io_destroy:
    break;
  case SYS_io_getevents:
    break;
  case SYS_io_setup:
    break;
  case SYS_io_submit:
    break;
  case SYS_ioctl:
    break;
  case SYS_ioperm:
    break;
  case SYS_iopl:
    break;
  case SYS_ioprio_get:
    break;
  case SYS_ioprio_set:
    break;
  case SYS_kcmp:
    break;
  case SYS_kexec_file_load:
    break;
  case SYS_kexec_load:
    break;
  case SYS_keyctl:
    break;
  case SYS_kill:
    break;
  case SYS_lchown:
    break;
  case SYS_lgetxattr:
    break;
  case SYS_link:
    break;
  case SYS_linkat:
    break;
  case SYS_listen:
    break;
  case SYS_listxattr:
    break;
  case SYS_llistxattr:
    break;
  case SYS_lookup_dcookie:
    break;
  case SYS_lremovexattr:
    break;
  case SYS_lseek:
    break;
  case SYS_lsetxattr:
    break;
  case SYS_lstat:
    break;
  case SYS_madvise:
    break;
  case SYS_mbind:
    break;
  case SYS_membarrier:
    break;
  case SYS_memfd_create:
    break;
  case SYS_migrate_pages:
    break;
  case SYS_mincore:
    break;
  case SYS_mkdir:
    break;
  case SYS_mkdirat:
    break;
  case SYS_mknod:
    break;
  case SYS_mknodat:
    break;
  case SYS_mlock:
    break;
  case SYS_mlock2:
    break;
  case SYS_mlockall:
    break;
  case SYS_mmap:
    break;
  case SYS_modify_ldt:
    break;
  case SYS_mount:
    break;
  case SYS_move_pages:
    break;
  case SYS_mprotect:
    break;
  case SYS_mq_getsetattr:
    break;
  case SYS_mq_notify:
    break;
  case SYS_mq_open:
    break;
  case SYS_mq_timedreceive:
    break;
  case SYS_mq_timedsend:
    break;
  case SYS_mq_unlink:
    break;
  case SYS_mremap:
    break;
  case SYS_msgctl:
    break;
  case SYS_msgget:
    break;
  case SYS_msgrcv:
    break;
  case SYS_msgsnd:
    break;
  case SYS_msync:
    break;
  case SYS_munlock:
    break;
  case SYS_munlockall:
    break;
  case SYS_munmap:
    break;
  case SYS_name_to_handle_at:
    break;
  case SYS_nanosleep:
    break;
  case SYS_newfstatat:
    break;
  case SYS_nfsservctl:
    break;
  case SYS_open:
    // This is exectuable before the system call happens.
    if (preSyscall) {
      string file = readTraceeCString(tracee, regs->rdi);
      myLog.writeToLog(Importance::info, "Opening file: %s\n", file.c_str());

    } else {
      // This is executed once the system call has happened.
    }
    break;
  case SYS_open_by_handle_at:
    break;
  case SYS_openat:
    break;
  case SYS_pause:
    break;
  case SYS_perf_event_open:
    break;
  case SYS_personality:
    break;
  case SYS_pipe:
    break;
  case SYS_pipe2:
    break;
  case SYS_pivot_root:
    break;
  case SYS_poll:
    break;
  case SYS_ppoll:
    break;
  case SYS_prctl:
    break;
  case SYS_pread64:
    break;
  case SYS_preadv:
    break;
  case SYS_prlimit64:
    break;
  case SYS_process_vm_readv:
    break;
  case SYS_process_vm_writev:
    break;
  case SYS_pselect6:
    break;
  case SYS_ptrace:
    break;
  case SYS_putpmsg:
    break;
  case SYS_pwrite64:
    break;
  case SYS_pwritev:
    break;
  case SYS_query_module:
    break;
  case SYS_quotactl:
    break;
  case SYS_read:
    break;
  case SYS_readahead:
    break;
  case SYS_readlink:
    break;
  case SYS_readlinkat:
    break;
  case SYS_readv:
    break;
  case SYS_reboot:
    break;
  case SYS_recvfrom:
    break;
  case SYS_recvmmsg:
    break;
  case SYS_recvmsg:
    break;
  case SYS_remap_file_pages:
    break;
  case SYS_removexattr:
    break;
  case SYS_rename:
    break;
  case SYS_renameat:
    break;
  case SYS_renameat2:
    break;
  case SYS_request_key:
    break;
  case SYS_restart_syscall:
    break;
  case SYS_rmdir:
    break;
  case SYS_rt_sigaction:
    break;
  case SYS_rt_sigpending:
    break;
  case SYS_rt_sigprocmask:
    break;
  case SYS_rt_sigqueueinfo:
    break;
  case SYS_rt_sigreturn:
    break;
  case SYS_rt_sigsuspend:
    break;
  case SYS_rt_sigtimedwait:
    break;
  case SYS_rt_tgsigqueueinfo:
    break;
  case SYS_sched_get_priority_max:
    break;
  case SYS_sched_get_priority_min:
    break;
  case SYS_sched_getaffinity:
    break;
  case SYS_sched_getattr:
    break;
  case SYS_sched_getparam:
    break;
  case SYS_sched_getscheduler:
    break;
  case SYS_sched_rr_get_interval:
    break;
  case SYS_sched_setaffinity:
    break;
  case SYS_sched_setattr:
    break;
  case SYS_sched_setparam:
    break;
  case SYS_sched_setscheduler:
    break;
  case SYS_sched_yield:
    break;
  case SYS_seccomp:
    break;
  case SYS_security:
    break;
  case SYS_select:
    break;
  case SYS_semctl:
    break;
  case SYS_semget:
    break;
  case SYS_semop:
    break;
  case SYS_semtimedop:
    break;
  case SYS_sendfile:
    break;
  case SYS_sendmmsg:
    break;
  case SYS_sendmsg:
    break;
  case SYS_sendto:
    break;
  case SYS_set_mempolicy:
    break;
  case SYS_set_robust_list:
    break;
  case SYS_set_thread_area:
    break;
  case SYS_set_tid_address:
    break;
  case SYS_setdomainname:
    break;
  case SYS_setfsgid:
    break;
  case SYS_setfsuid:
    break;
  case SYS_setgid:
    break;
  case SYS_setgroups:
    break;
  case SYS_sethostname:
    break;
  case SYS_setitimer:
    break;
  case SYS_setns:
    break;
  case SYS_setpgid:
    break;
  case SYS_setpriority:
    break;
  case SYS_setregid:
    break;
  case SYS_setresgid:
    break;
  case SYS_setresuid:
    break;
  case SYS_setreuid:
    break;
  case SYS_setrlimit:
    break;
  case SYS_setsid:
    break;
  case SYS_setsockopt:
    break;
  case SYS_settimeofday:
    break;
  case SYS_setuid:
    break;
  case SYS_setxattr:
    break;
  case SYS_shmat:
    break;
  case SYS_shmctl:
    break;
  case SYS_shmdt:
    break;
  case SYS_shmget:
    break;
  case SYS_shutdown:
    break;
  case SYS_sigaltstack:
    break;
  case SYS_signalfd:
    break;
  case SYS_signalfd4:
    break;
  case SYS_socket:
    break;
  case SYS_socketpair:
    break;
  case SYS_splice:
    break;
  case SYS_stat:
    break;
  case SYS_statfs:
    break;
  case SYS_swapoff:
    break;
  case SYS_swapon:
    break;
  case SYS_symlink:
    break;
  case SYS_symlinkat:
    break;
  case SYS_sync:
    break;
  case SYS_sync_file_range:
    break;
  case SYS_syncfs:
    break;
  case SYS_sysfs:
    break;
  case SYS_sysinfo:
    break;
  case SYS_syslog:
    break;
  case SYS_tee:
    break;
  case SYS_tgkill:
    break;
  case SYS_time:
    break;
  case SYS_timer_create:
    break;
  case SYS_timer_delete:
    break;
  case SYS_timer_getoverrun:
    break;
  case SYS_timer_gettime:
    break;
  case SYS_timer_settime:
    break;
  case SYS_timerfd_create:
    break;
  case SYS_timerfd_gettime:
    break;
  case SYS_timerfd_settime:
    break;
  case SYS_times:
    break;
  case SYS_tkill:
    break;
  case SYS_truncate:
    break;
  case SYS_tuxcall:
    break;
  case SYS_umask:
    break;
  case SYS_umount2:
    break;
  case SYS_uname:
    break;
  case SYS_unlink:
    break;
  case SYS_unlinkat:
    break;
  case SYS_unshare:
    break;
  case SYS_uselib:
    break;
  case SYS_userfaultfd:
    break;
  case SYS_ustat:
    break;
  case SYS_utime:
    break;
  case SYS_utimensat:
    break;
  case SYS_utimes:
    break;
  case SYS_vfork:
    break;
  case SYS_vhangup:
    break;
  case SYS_vmsplice:
    break;
  case SYS_vserver:
    break;
  case SYS_wait4:
    break;
  case SYS_waitid:
    break;
  case SYS_write:
    break;
  case SYS_writev:
    break;

  default:
    break;
  }

  if (syscallReturns) { preSyscall = !preSyscall; }

  return syscallName;
}
// =======================================================================================
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
    fprintf(stderr, "Missing executable argument to detTrace!");
    fprintf(stderr, "%s\n", usageMsg.c_str());
    exit(1);
  }

  return make_pair(optind, debugLevel);
}
