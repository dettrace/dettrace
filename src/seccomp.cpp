#include "seccomp.hpp"

#include <string>
#include <iostream>
#include <stdexcept>

#include <sys/personality.h>
#include <sys/ptrace.h>
#include <sys/reg.h>     /* For constants ORIgetpeernameG_EAX, etc */
#include <sys/syscall.h>    /* For SYS_write, etc */

using namespace std;

seccomp::seccomp(int debugLevel){
  ctx = seccomp_init(SCMP_ACT_TRACE(INT16_MAX));

  if(ctx == nullptr){
    throw runtime_error("Unable to init seccomp filter.\n");
  }

  loadRules(debugLevel >= 4);
}

void seccomp::loadRules(bool debug){
  // sets architecture-specific process or thread state.
  noIntercept(SYS_arch_prctl);
  // Change location of the program break.
  noIntercept(SYS_brk);
  // Bind seems safe enough to let though, specially since user is stuck in chroot.
  // There might be some slight issues with permission denied if we set up our
  // bind mounts wrong and might need to allow for recursive mounting. But it will
  // be obvious.
  noIntercept(SYS_bind);
  // Change owner of file
  noIntercept(SYS_chown);
  // like chown but does not dereference symbolic links.
  noIntercept(SYS_lchown);
  // Get clock resolution, TODO might be non deterministic.
  noIntercept(SYS_clock_getres);
  // Duplicate file descriptor.
  noIntercept(SYS_dup);
  noIntercept(SYS_dup2);
  // End process.
  noIntercept(SYS_exit);
  // End process group.
  noIntercept(SYS_exit_group);
  // Advise on access patter by program of file.
  noIntercept(SYS_fadvise64);
  // Variants of regular function that use file descriptor instead of char* path.
  noIntercept(SYS_fchdir);
  noIntercept(SYS_fchmod);
  noIntercept(SYS_fchmodat);
  noIntercept(SYS_fchown);
  noIntercept(SYS_fcntl);
  // TODO Flock may block! In the future this may lead to deadlock.
  // deal with it then :)
  noIntercept(SYS_flock);
  noIntercept(SYS_fsync);
  noIntercept(SYS_ftruncate);
  // TODO: Add to intercept with debug for path.
  noIntercept(SYS_fsetxattr);
  noIntercept(SYS_getuid);
  noIntercept(SYS_getgid);
  noIntercept(SYS_getegid);
  noIntercept(SYS_geteuid);
  noIntercept(SYS_getgroups);
  noIntercept(SYS_getpgrp);
  noIntercept(SYS_getpid);
  noIntercept(SYS_getppid);
  noIntercept(SYS_gettid);
  noIntercept(SYS_getuid);
  noIntercept(SYS_getxattr);
  noIntercept(SYS_madvise);
  noIntercept(SYS_mknod);
  noIntercept(SYS_munmap);
  noIntercept(SYS_mmap);
  noIntercept(SYS_mprotect);
  noIntercept(SYS_mremap);
  noIntercept(SYS_lseek);

  noIntercept(SYS_pread64);
  noIntercept(SYS_rt_sigprocmask);
  noIntercept(SYS_rt_sigaction);
  noIntercept(SYS_rt_sigsuspend);
  noIntercept(SYS_setpgid);
  noIntercept(SYS_set_tid_address);
  noIntercept(SYS_setxattr);
  noIntercept(SYS_sigaltstack);

  noIntercept(SYS_rt_sigreturn);
  noIntercept(SYS_rt_sigtimedwait);
  noIntercept(SYS_setgid);
  noIntercept(SYS_setrlimit);
  noIntercept(SYS_setrlimit);
  // This seems to be, surprisingly, deterministic. The affinity is set/get by
  // us so it should always be the same mask. User cannot actually observe differences.
  noIntercept(SYS_sched_getaffinity);
  noIntercept(SYS_socket);
  noIntercept(SYS_umask);

  // These system calls must be intercepted as to know when a fork even has happened:
  // We handle forks when see the system call pre exit.
  // Since this is the easiest time to tell a fork even happened. It's not trivial
  // to check the event as we might get a signal first from the child process.
  // See:
  // https://stackoverflow.com/questions/29997244/
  // occasionally-missing-ptrace-event-vfork-when-running-ptrace
  intercept(SYS_fork);
  intercept(SYS_vfork);
  intercept(SYS_clone);

  // These system calls cause an even that is caught by ptrace and determinized:
  intercept(SYS_access, debug);
  // Not used, let's figure out who does one!
  // intercept(SYS_alarm);
  intercept(SYS_chdir, debug);
  intercept(SYS_chmod, debug);
  intercept(SYS_creat);
  intercept(SYS_clock_gettime);
  intercept(SYS_close);
  // TODO: This system call
  intercept(SYS_connect);
  intercept(SYS_execve, debug);
  intercept(SYS_faccessat, debug);
  intercept(SYS_fgetxattr, debug);
  intercept(SYS_flistxattr, debug);
  intercept(SYS_fchownat);
  intercept(SYS_fstat);
  intercept(SYS_fstatfs);
  // TODO
  intercept(SYS_futex);
  intercept(SYS_getcwd);
  intercept(SYS_getdents);
  // TODO
  intercept(SYS_getdents64);
  intercept(SYS_getpeername);
#ifdef SYS_getrandom
  intercept(SYS_getrandom);
#endif
  intercept(SYS_getrlimit);
  intercept(SYS_getrusage);
  intercept(SYS_gettimeofday);
  // TODO IOCTL with seccomp instead of ptrace
  intercept(SYS_ioctl);
  // TODO
  intercept(SYS_llistxattr);
  // TODO
  intercept(SYS_lgetxattr);
  intercept(SYS_mkdir, debug);
  intercept(SYS_mkdirat, debug);
  // TODO Nano sleep
  intercept(SYS_nanosleep);
  intercept(SYS_newfstatat);
  intercept(SYS_lstat);
  // We usually intercept every system call that can create a new file or directory.
  // This is used to give a newer modified time to files. So ommiting this here or
  // in mkdir* is not neccessarily an error, since we don't expect process' to check
  // this. If they do, we will get some error, but it will not leave to nondeterminism.
  intercept(SYS_link);
  intercept(SYS_linkat);

  intercept(SYS_open);
  intercept(SYS_openat);
  // TODO Pipe
  intercept(SYS_pipe);
  intercept(SYS_pipe2);
  intercept(SYS_pselect6);
  // TODO not detetministic!
  intercept(SYS_poll);
  intercept(SYS_prlimit64);
  intercept(SYS_read);
  // TODO
  intercept(SYS_readv);
  intercept(SYS_readlink, debug);
  intercept(SYS_readlinkat, debug);
  // TODO
  intercept(SYS_recvmsg);

  intercept(SYS_rename);
  intercept(SYS_renameat);
  intercept(SYS_renameat2);

  intercept(SYS_rmdir);
  intercept(SYS_sendto);
  // Defintely not deteministic </3
  intercept(SYS_select);
  // TODO
  intercept(SYS_set_robust_list);
  intercept(SYS_stat);
  intercept(SYS_statfs);
  intercept(SYS_sysinfo);
  intercept(SYS_symlink, debug);
  intercept(SYS_symlinkat, debug);
  intercept(SYS_tgkill);
  intercept(SYS_time);
  intercept(SYS_times);
  intercept(SYS_utime);
  intercept(SYS_utimes);
  intercept(SYS_utimensat);
  intercept(SYS_uname);
  intercept(SYS_unlink);
  intercept(SYS_unlinkat);
  intercept(SYS_wait4);
  intercept(SYS_write);
  // TODO
  intercept(SYS_writev);
}

void seccomp::noIntercept(uint16_t systemCall){
  // Send system call number as data to tracer to avoid a ptrace(GET_REGS).
  int ret = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, systemCall, 0);
  if(ret < 0){
    throw runtime_error("Failed to add system call no interception rule! Reason: \n" +
			to_string(systemCall));
  }

  return;
}

void seccomp::intercept(uint16_t systemCall){
  // Send system call number as data to tracer to avoid a ptrace(GET_REGS).
  int ret = seccomp_rule_add(ctx, SCMP_ACT_TRACE(systemCall), systemCall, 0);
  if(ret < 0){
    throw runtime_error("Failed to add system call no interception rule! Reason: \n" +
			to_string(systemCall));
  }

  return;
}

void seccomp::intercept(uint16_t systemCall, bool cond){
  if(cond){
    intercept(systemCall);
  }else{
    noIntercept(systemCall);
  }

  return;
}

void seccomp::loadFilterToKernel(){
  int ret = seccomp_load(ctx);
  if(ret < 0){
    throw runtime_error("Unable to seccomp_load.\n Reason: " + string { strerror(- ret)});
  }

}

seccomp::~seccomp(){
  seccomp_release(ctx);
}
