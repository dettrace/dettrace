#include "seccomp.hpp"

#include <string>
#include <iostream>
#include <stdexcept>

#include <sys/personality.h>
#include <sys/ptrace.h>
#include <sys/reg.h>     /* For constants ORIG_EAX, etc */
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
  // This is a variant of loadRules which intercepts extra system calls for
  // debug purposes!
  noIntercept(SYS_arch_prctl);
  noIntercept(SYS_brk);
  noIntercept(SYS_close);
  noIntercept(SYS_dup);
  noIntercept(SYS_dup2);
  noIntercept(SYS_exit_group);
  noIntercept(SYS_fadvise64);
  noIntercept(SYS_fchmodat);
  noIntercept(SYS_fcntl);
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
  noIntercept(SYS_lgetxattr);
  noIntercept(SYS_madvise);
  noIntercept(SYS_munmap);
  noIntercept(SYS_mmap);
  noIntercept(SYS_mprotect);
  noIntercept(SYS_mremap);
  noIntercept(SYS_lseek);
  noIntercept(SYS_rt_sigprocmask);
  noIntercept(SYS_rt_sigaction);
  noIntercept(SYS_setpgid);
  noIntercept(SYS_set_tid_address);
  noIntercept(SYS_sigaltstack);
  noIntercept(SYS_rt_sigreturn);
  noIntercept(SYS_rename);
  noIntercept(SYS_renameat);
  noIntercept(SYS_renameat2);
  noIntercept(SYS_socket);
  noIntercept(SYS_umask);
  // TODO We do not allow user to observe metadata so it's fine if they write
  // it out.
  noIntercept(SYS_utimensat);
  noIntercept(SYS_utimes);


  // These system calls must intercepted as to know when a fork even has happened:
  // We handle forks when see the system call pre exit.
  // Since this is the easiest time to tell a fork even happened. It's not trivial
  // to check the event as we might get a signal first from the child process.
  // See:
  // https://stackoverflow.com/questions/29997244/
  // occasionally-missing-ptrace-event-vfork-when-running-ptrace
  intercept(SYS_fork);
  intercept(SYS_vfork);
  intercept(SYS_clone);

  // These system calls cause an even that is caught by ptrace and determinized.
  intercept(SYS_access, debug);
  intercept(SYS_alarm);
  intercept(SYS_chdir, debug);
  intercept(SYS_chmod, debug);
  intercept(SYS_clock_gettime);
  // TODO: This system call
  intercept(SYS_connect);
  intercept(SYS_execve, debug);
  intercept(SYS_faccessat, debug);
  intercept(SYS_fchownat);
  intercept(SYS_fstat);
  intercept(SYS_fstatfs);
  // TODO
  intercept(SYS_futex);
  intercept(SYS_getcwd);
  intercept(SYS_getdents);
  intercept(SYS_getpeername);
  intercept(SYS_getrandom);
  intercept(SYS_getrlimit);
  intercept(SYS_getrusage);
  intercept(SYS_gettimeofday);
  // TODO IOCTL with seccomp instead of ptrace
  intercept(SYS_ioctl);
  intercept(SYS_mkdir, debug);
  intercept(SYS_mkdirat, debug);
  // TODO Nano sleep
  intercept(SYS_nanosleep);
  intercept(SYS_newfstatat);
  intercept(SYS_lstat);
  intercept(SYS_open, debug);
  intercept(SYS_openat, debug);
  // TODO Pipe
  intercept(SYS_pipe);
  intercept(SYS_pselect6);
  // TODO not detetministic!
  intercept(SYS_poll);
  intercept(SYS_prlimit64);
  intercept(SYS_read);
  // TODO
  intercept(SYS_readv);
  intercept(SYS_readlink, debug);
  // TODO
  intercept(SYS_recvmsg);
  intercept(SYS_rename, debug);
  intercept(SYS_sendto);
  // Defintely not deteministic </3
  intercept(SYS_select);
  // TODO
  intercept(SYS_set_robust_list);
  intercept(SYS_stat);
  intercept(SYS_statfs);
  intercept(SYS_sysinfo);
  intercept(SYS_tgkill);
  intercept(SYS_time);
  intercept(SYS_uname);
  intercept(SYS_unlink, debug);
  intercept(SYS_unlinkat, debug);
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
