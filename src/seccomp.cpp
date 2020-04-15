#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>

#include <endian.h>
#include <sys/personality.h>
#include <sys/ptrace.h>
#include <sys/syscall.h> /* For SYS_write, etc */
#include <unistd.h>

#include "seccomp.hpp"
#include "util.hpp"

#define ALLOW BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_ALLOW)
#define DENY BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_KILL)
#define TRACE BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_TRACE)
#define TRAP BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_TRAP)

#define SYSCALL(nr, jt) BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, (nr), 0, 1), jt

/* Ensure that we load the logically correct offset. */
#if __BYTE_ORDER == __LITTLE_ENDIAN
#define ENDIAN(_lo, _hi) _lo, _hi
#define HI_IP offsetof(struct seccomp_data, instruction_pointer) + sizeof(__u32)
#define LO_IP offsetof(struct seccomp_data, instruction_pointer)
#elif __BYTE_ORDER == __BIG_ENDIAN
#define ENDIAN(_lo, _hi) _hi, _lo
#define HI_IP offsetof(struct seccomp_data, instruction_pointer)
#define LO_IP offsetof(struct seccomp_data, instruction_pointer) + sizeof(__u32)
#else
#error "Unknown endianness"
#endif

#define LOAD_SYSCALL_NR \
  BPF_STMT(BPF_LD + BPF_W + BPF_ABS, offsetof(struct seccomp_data, nr))

#define LOAD_SYSCALL_IP                          \
  BPF_STMT(BPF_LD + BPF_W + BPF_ABS, LO_IP),     \
      BPF_STMT(BPF_ST, 0), /* lo -> M[0] */      \
      BPF_STMT(BPF_LD + BPF_W + BPF_ABS, HI_IP), \
      BPF_STMT(BPF_ST, 1) /* hi -> M[1] */

#define EXPAND(...) __VA_ARGS__

#define JEQ64(lo, hi, jt)                                    \
  /* if (hi != arg.hi) goto NOMATCH; */                      \
  BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, (hi), 0, 5),           \
      BPF_STMT(BPF_LD + BPF_MEM, 0),                         \
      /* swap in lo */ /* if (lo != arg.lo) goto NOMATCH; */ \
      BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, (lo), 0, 2),       \
      BPF_STMT(BPF_LD + BPF_MEM, 1), jt, BPF_STMT(BPF_LD + BPF_MEM, 1)

#define JEQ(x, jt)                                                        \
  JEQ64(                                                                  \
      ((union arg64){.u64 = (x)}).lo32, ((union arg64){.u64 = (x)}).hi32, \
      EXPAND(jt))

union arg64 {
  struct {
    __u32 ENDIAN(lo32, hi32);
  };
  __u64 u64;
};

static void do_seccomp(void) {
  struct sock_filter seccomp_filter[] = {
      LOAD_SYSCALL_NR,
      SYSCALL(__NR_brk, ALLOW),
      SYSCALL(__NR_bind, ALLOW),
      SYSCALL(__NR_splice, ALLOW),
      SYSCALL(__NR_dup3, ALLOW),
      SYSCALL(__NR_capget, ALLOW),
      SYSCALL(__NR_capset, ALLOW),
      SYSCALL(__NR_clock_getres, ALLOW),
      SYSCALL(__NR_getresgid, ALLOW),
      SYSCALL(__NR_exit, ALLOW),
      SYSCALL(__NR_epoll_create1, ALLOW),
      SYSCALL(__NR_epoll_create, ALLOW),
      SYSCALL(__NR_fadvise64, ALLOW),
      SYSCALL(__NR_fallocate, ALLOW),
      SYSCALL(__NR_fchdir, ALLOW),
      SYSCALL(__NR_fchmod, ALLOW),
      SYSCALL(__NR_fchmodat, ALLOW),
      SYSCALL(__NR_fdatasync, ALLOW),
      SYSCALL(__NR_flock, ALLOW),
      SYSCALL(__NR_fsync, ALLOW),
      SYSCALL(__NR_ftruncate, ALLOW),
      SYSCALL(__NR_fsetxattr, ALLOW),
      SYSCALL(__NR_getresuid, ALLOW),
      SYSCALL(__NR_getgid, ALLOW),
      SYSCALL(__NR_getegid, ALLOW),
      SYSCALL(__NR_geteuid, ALLOW),
      SYSCALL(__NR_getgroups, ALLOW),
      SYSCALL(__NR_getpgrp, ALLOW),
      SYSCALL(__NR_getpid, ALLOW),
      SYSCALL(__NR_getpgid, ALLOW),
      SYSCALL(__NR_getppid, ALLOW),
      SYSCALL(__NR_gettid, ALLOW),
      SYSCALL(__NR_getuid, ALLOW),
      SYSCALL(__NR_getxattr, ALLOW),
      SYSCALL(__NR_madvise, ALLOW),
      SYSCALL(__NR_munmap, ALLOW),
      SYSCALL(__NR_mprotect, ALLOW),
      SYSCALL(__NR_mremap, ALLOW),
      SYSCALL(__NR_msync, ALLOW),
      SYSCALL(__NR_lseek, ALLOW),
      SYSCALL(__NR_prctl, ALLOW),
      SYSCALL(__NR_arch_prctl, ALLOW),
      SYSCALL(__NR_pread64, ALLOW),
      SYSCALL(__NR_pwrite64, ALLOW),
      SYSCALL(__NR_listxattr, ALLOW),
      SYSCALL(__NR_rt_sigreturn, ALLOW),
      SYSCALL(__NR_rt_sigpending, ALLOW),
      SYSCALL(__NR_setpgid, ALLOW),
      SYSCALL(__NR_set_tid_address, ALLOW),
      SYSCALL(__NR_setxattr, ALLOW),
      SYSCALL(__NR_sigaltstack, ALLOW),
      SYSCALL(__NR_setgid, ALLOW),
      SYSCALL(__NR_setgroups, ALLOW),
      SYSCALL(__NR_setrlimit, ALLOW),
      SYSCALL(__NR_setregid, ALLOW),
      SYSCALL(__NR_setresgid, ALLOW),
      SYSCALL(__NR_setresuid, ALLOW),
      SYSCALL(__NR_setreuid, ALLOW),
      SYSCALL(__NR_setuid, ALLOW),
      SYSCALL(__NR_sched_getaffinity, ALLOW),
      SYSCALL(__NR_sched_setaffinity, ALLOW),
      SYSCALL(__NR_sync, ALLOW),
      SYSCALL(__NR_umask, ALLOW),
      SYSCALL(__NR_getsockname, ALLOW),
      SYSCALL(__NR_getsockopt, ALLOW),
      SYSCALL(__NR_setsockopt, ALLOW),
      SYSCALL(__NR_socketpair, ALLOW),
      SYSCALL(__NR_mlock, ALLOW),
      SYSCALL(__NR_setsid, ALLOW),
      SYSCALL(__NR_sched_yield, ALLOW),
      SYSCALL(__NR_truncate, ALLOW),
      SYSCALL(__NR_eventfd2, ALLOW),
      SYSCALL(__NR_writev, ALLOW),
      SYSCALL(__NR_fork, ALLOW),
      SYSCALL(__NR_vfork, ALLOW),
      SYSCALL(__NR_clone, ALLOW),
      SYSCALL(__NR_mmap, ALLOW),
      SYSCALL(__NR_mbind, ALLOW),
      SYSCALL(__NR_membarrier, ALLOW),
      LOAD_SYSCALL_IP,
      JEQ(0x70000002, ALLOW),
      TRACE,
  };

  struct sock_fprog prog = {
      .len = sizeof(seccomp_filter) / sizeof(seccomp_filter[0]),
      .filter = seccomp_filter,
  };

  if (syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER, 0, &prog) < 0) {
    runtimeError("failed to install seccomp filter");
  }
}

seccomp::seccomp(int debugLevel, bool convertUids) { do_seccomp(); }
