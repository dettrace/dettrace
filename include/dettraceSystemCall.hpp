#ifndef DETTRACE_SYSTEM_CALL_H
#define DETTRACE_SYSTEM_CALL_H

#include "systemCall.hpp"

using namespace std;

/**
 * Hopefully this will server as documentation for all our system calls.
 * Please keep in alphabetical order.
 * For every system call we list the expected prototype, a short desription from the man
 * page, and what we expect to do to get it deterministic (if applicable).
 */

// =======================================================================================
/**
 * access()  checks  whether the calling process can access the file pathname.  If path‐
 *     name is a symbolic link, it is dereferenced.
 *
 * int access(const char *pathname, int mode);

 * TODO: This is filepath dependant. The user could learn information about the path
 * based on this information? In the future I think I want to chroot the process.
 * FILESYSTEM RELATED.
 */
class accessSystemCall : public systemCall{
public:
  accessSystemCall(long syscallName, string syscallNumber);
  /*
   * Nothing to do.
   */
  bool handleDetPre(state& s, ptracer& t) override;
  void handleDetPost(state& s, ptracer& t) override;
};
// =======================================================================================
/**
 * arch_prctl()
 * set architecture-specific process or thread state. code selects a subfunction and passes
 * argument addr to it; addr is interpreted  as  either an  unsigned  long  for the "set"
 * operations, or as an unsigned long *, for the "get" operations.
 *
 * int arch_prctl(int code, unsigned long addr);
 * int arch_prctl(int code, unsigned long *addr);
 *
 * This should be totally deterministic, but not portable across architectures. Which should
 * not be a problem for us.
 */
class arch_prctlSystemCall : public systemCall{
public:
  arch_prctlSystemCall(long syscallName, string syscallNumber);
  /*
   * Nothing to do.
   */
  bool handleDetPre(state& s, ptracer& t) override;
  void handleDetPost(state& s, ptracer& t) override;
};

// =======================================================================================
/**
 * brk()  and  sbrk() change the location of the program break, which defines the end of
 * the process's data segment (i.e., the program break is the first location  after  the
 * end  of the uninitialized data segment).  Increasing the program break has the effect
 * of allocating memory to the process; decreasing the break deallocates memory.
 *
 * Seems determinitic enough, specially under ASLR off.
 *
 * int brk(void *addr)
 */
class brkSystemCall : public systemCall{
public:
  brkSystemCall(long syscallName, string syscallNumber);
  bool handleDetPre(state& s, ptracer& t) override;
  void handleDetPost(state& s, ptracer& t) override;
};
// =======================================================================================
/**
 * long
 * clone(unsigned long flags,
 *       void *child_stack,
 *       int *ptid,
 *       int *ctid,
 *       unsigned long newtls);
 *
 * Underlying implementation for both creating threads and new processes.
 * Modern day fork() does a clone under the hood. Dettrace 
 */
class cloneSystemCall : public systemCall{
public:
  cloneSystemCall(long syscallName, string syscallNumber);
  bool handleDetPre(state& s, ptracer& t) override;
  void handleDetPost(state& s, ptracer& t) override;
};
// =======================================================================================
/*
 * close() closes a file descriptor, so that it no longer refers to any file and may be
 * reused.
 *
 * int close(int fd);
 *
 * Not deterministic due to return error when signal occurs! TODO.
 */
class closeSystemCall : public systemCall{
public:
  closeSystemCall(long syscallName, string syscallNumber);
  bool handleDetPre(state& s, ptracer& t) override;
  void handleDetPost(state& s, ptracer& t) override;
};
// =======================================================================================
/*
 *
 * int dup2(int oldfd, int newfd);
 *
 * The dup2() system call performs the same task as dup(), but instead of using the low‐
 * est-numbered unused file descriptor, it uses the file descriptor number specified  in
 * newfd.
 *
 * I keep forgetting if file descriptors are deterministic or not when we add threads.
 */
class dup2SystemCall : public systemCall{
public:
  dup2SystemCall(long syscallName, string syscallNumber);
  bool handleDetPre(state& s, ptracer& t) override;
  void handleDetPost(state& s, ptracer& t) override;
};
// =======================================================================================
/**
 * execve()  executes  the  program  pointed  to by filename.
 *
 * int execve(const char *filename, char *const argv[], char *const envp[]);
 *
 * TODO
 * FILESYSTEM RELATED.
 */
class execveSystemCall : public systemCall{
public:
  execveSystemCall(long syscallName, string syscallNumber);
  bool handleDetPre(state& s, ptracer& t) override;
  void handleDetPost(state& s, ptracer& t) override;
};
// =======================================================================================
/**
 *
 * void exit_group(int status);
 *
 * This  system  call  is  equivalent to _exit(2) except that it terminates not only the
 * calling thread, but all threads in the calling process's thread group.
 *
 * Deterministic!
 */
class exit_groupSystemCall : public systemCall{
public:
  exit_groupSystemCall(long syscallName, string syscallNumber);
  bool handleDetPre(state& s, ptracer& t) override;
  void handleDetPost(state& s, ptracer& t) override;
};
// =======================================================================================
/**
 * fstat()
 *
 * These functions return information about a file, in the buffer pointed to by statbuf.
 * No permissions are required on the file itself, but—in the case of stat(), fstatat(),
 * and  lstat()—execute  (search)  permission  is  required on all of the directories in
 * pathname that lead to the file.

 * fstat() is identical to stat(), except that the file about which information is to be
 * retrieved is specified by the file descriptor fd.
 *
 * int fstat(int fd, struct stat *statbuf);
 *
 * TODO
 * FILESYSTEM RELATED.
 */
class fstatSystemCall : public systemCall{
public:
  fstatSystemCall(long syscallName, string syscallNumber);
  bool handleDetPre(state& s, ptracer& t) override;
  void handleDetPost(state& s, ptracer& t) override;
};
// =======================================================================================
/**
 * int fstatfs(int fd, struct statfs *buf);
 *
 * The statfs() system call returns information about a mounted filesystem.  path is the
 * pathname of any file within the mounted filesystem.
 *
 * Very similar to statfs, except it takes a file descriptor instead of a file path.
 */
class fstatfsSystemCall : public systemCall{
public:
  fstatfsSystemCall(long syscallName, string syscallNumber);
  bool handleDetPre(state& s, ptracer& t) override;
  void handleDetPost(state& s, ptracer& t) override;
};
// =======================================================================================
/**
 *
 * int getdents(unsigned int fd, struct linux_dirent *dirp, unsigned int count);
 *
 * Reads several linux_dirent structures from the directory referred to by the open file
 * descriptor fd into the buffer pointed to by  dirp.
 * Reads files in directory.
 *
 * TODO: Contains linux_dirent struct with inode that we could virtualize.
 * FILESYSTEM RELATED
 */
class getdentsSystemCall : public systemCall{
public:
  getdentsSystemCall(long syscallName, string syscallNumber);
  bool handleDetPre(state& s, ptracer& t) override;
  void handleDetPost(state& s, ptracer& t) override;
};
// =======================================================================================
/**
 * pid_t getpid();
 *
 * Returns the pid of the calling process.
 *
 * Obviously nondeterministic. We instead keep a map of real pids to virtual pid mappings.
 * The running process only gets to observe virtual pids, but all system calls that
 * require pids, use real pids by mapping back.
 */
class getpidSystemCall : public systemCall{
public:
  getpidSystemCall(long syscallName, string syscallNumber);
  bool handleDetPre(state& s, ptracer& t) override;
  void handleDetPost(state& s, ptracer& t) override;
};
// =======================================================================================
/**
 *
 * int ioctl(int fd, unsigned long request, ...);
 *
 * The  ioctl()  function manipulates the underlying device parameters of special files.
 * Kitchen sink system call to talk to various devices or pseudo-devices through /dev/
 *
 * Definitely not deterministic but I don't think there is much we can do about it.
 *
 */
class ioctlSystemCall : public systemCall{
public:
  ioctlSystemCall(long syscallName, string syscallNumber);
  bool handleDetPre(state& s, ptracer& t) override;
  void handleDetPost(state& s, ptracer& t) override;
};
// =======================================================================================
/**
 *
 * int munmap(void *addr, size_t length);
 *
 * The  munmap()  system  call deletes the mappings for the specified address range, and
 * causes further references to addresses within the range to  generate  invalid  memory
 * references.   The  region  is  also automatically unmapped when the process is termi‐
 * nated.  On the other hand, closing the file descriptor does not unmap the region.
 *
 * This should be deterministic.
 *
 */
class munmapSystemCall : public systemCall{
public:
  munmapSystemCall(long syscallName, string syscallNumber);
  bool handleDetPre(state& s, ptracer& t) override;
  void handleDetPost(state& s, ptracer& t) override;
};
// =======================================================================================
/**
 * mmap()  creates  a  new  mapping in the virtual address space of the calling process.
 *
 * Disabling ASLR appears to make mmap deterministic.
 * So we don't have to do anything. We should be skeptical though. May require further
 * research.
 *
 * void *mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset);
 *
 */
class mmapSystemCall : public systemCall{
public:
  mmapSystemCall(long syscallName, string syscallNumber);
  bool handleDetPre(state& s, ptracer& t) override;
  void handleDetPost(state& s, ptracer& t) override;
};
// =======================================================================================
/**
 * mprotect ()
 *
 * mprotect() changes the access protections for the calling process's memory pages con‐
 * taining any part of the address range in the interval [addr, addr+len-1].  addr  must
 * be aligned to a page boundary.

 * If  the  calling process tries to access memory in a manner that violates the protec‐
 * tions, then the kernel generates a SIGSEGV signal for the process.

 * int mprotect(void *addr, size_t len, int prot);
 *
 * This should be deterministic as long as we have ASLR disabled. This system call works
 * in conjuction with mmap.
 */
class mprotectSystemCall : public systemCall{
public:
  mprotectSystemCall(long syscallName, string syscallNumber);
  bool handleDetPre(state& s, ptracer& t) override;
  void handleDetPost(state& s, ptracer& t) override;
};
// =======================================================================================
/**
 * Given  a  pathname for a file, open() returns a file descriptor, a small, nonnegative
 * integer for use in subsequent system calls (read(2),  write(2),  lseek(2),  fcntl(2),
 * etc.)
 *
 * The file descriptor returned by a successful call will be the lowest-numbered
 * file descriptor not currently open for the process.
 *
 * TODO
 * FILESYSTEM RELATED.
 */
class openSystemCall : public systemCall{
public:
  openSystemCall(long syscallName, string syscallNumber);
  bool handleDetPre(state& s, ptracer& t) override;
  void handleDetPost(state& s, ptracer& t) override;
};
// =======================================================================================
/**
 *
 * int openat(int dirfd, const char *pathname, int flags);
 * int openat(int dirfd, const char *pathname, int flags, mode_t mode);
 *
 * The openat() system call operates in exactly the same way as open(), except  for  the
 * differences described here.
 *
 * If the pathname given in pathname is relative, then it is interpreted relative
 * to the directory referred to by the file descriptor dirfd (rather  than  rela‐
 * tive  to  the  current working directory of the calling process, as is done by
 * open() for a relative pathname).
 *
 * If pathname is relative and dirfd is the special value AT_FDCWD, then pathname
 * is  interpreted  relative  to  the  current  working  directory of the calling
 * process (like open()).
 *
 * If pathname is absolute, then dirfd is ignored.
 *
 * TODO
 * FILESYSTEM RELATED.
 */
class openatSystemCall : public systemCall{
public:
  openatSystemCall(long syscallName, string syscallNumber);
  bool handleDetPre(state& s, ptracer& t) override;
  void handleDetPost(state& s, ptracer& t) override;
};
// =======================================================================================
/**
 *
 * int prlimit64(pid_t pid, int resource, const struct rlimit *new_limit,
                   struct rlimit *old_limit);
 *
 * get/set different types of process resource limits to new values. These resources
 * include, nice values, max memory size, core file size, etc.

 *
 * Definitely nondeterminism if used for get but realistically we need this. It also
 * probably won't cause too much issues.
 * The pid has to be converted from a vpid -> pid, except for the 0 case which means
 * *this* process. So we merely check if non zero and fail. (TODO: This may change later
 * if this becomes an issue).
 *
 */
class prlimit64SystemCall : public systemCall{
public:
  prlimit64SystemCall(long syscallName, string syscallNumber);
  bool handleDetPre(state& s, ptracer& t) override;
  void handleDetPost(state& s, ptracer& t) override;
};
// =======================================================================================
/**
 * TODO
 * FILESYSTEM RELATED.
 */
class readSystemCall : public systemCall{
public:
  readSystemCall(long syscallName, string syscallNumber);
  bool handleDetPre(state& s, ptracer& t) override;
  void handleDetPost(state& s, ptracer& t) override;
};
// =======================================================================================
/**
 * rt_sigprocmask()
 * is  used to fetch and/or change the signal mask of the calling thread.
 * The signal mask is the set of signals whose delivery is  currently  blocked  for  the
 * caller (see also signal(7) for more details).
 *
 * int rt_sigprocmask(int how, const kernel_sigset_t *set, kernel_sigset_t *oldset,
 *                    size_t sigsetsize);
 *
 * SIGNAL RELATED.
 */
class rt_sigprocmaskSystemCall : public systemCall{
public:
  rt_sigprocmaskSystemCall(long syscallName, string syscallNumber);
  bool handleDetPre(state& s, ptracer& t) override;
  void handleDetPost(state& s, ptracer& t) override;
};
// =======================================================================================
/**
 *
 * int sigaction(int signum, const struct sigaction *act, struct sigaction *oldact);
 *
 * Change the action taken by a process on receipt of a specific signal.
 *
 * This is probably how signal handlers are implemented under the hood.
 * This should be deterministic enough (assuming the signals we receive are deterministic,
 * but we will need to look further at the manpage to be sure TODO).
 *
 * Our unit test framework uses this system call. It's probably setting up handler for all
 * signals in case there is a failure thrown by a unit test.
 */
class rt_sigactionSystemCall : public systemCall{
public:
  rt_sigactionSystemCall(long syscallName, string syscallNumber);
  bool handleDetPre(state& s, ptracer& t) override;
  void handleDetPost(state& s, ptracer& t) override;
};
// =======================================================================================
/**
 *
 * long get_robust_list(int pid, struct robust_list_head **head_ptr,
                            size_t *len_ptr);
 * long set_robust_list(struct robust_list_head *head, size_t len);
 *
 * These  system calls deal with per-thread robust futex lists. See futex (2) for
 * more information!
 *
 * Seems to be deterministic.

 * TODO: Implement get_robust_list. We do have to make sure we map the vpid the user gives
 * us to a real pid.
 */
class set_robust_listSystemCall : public systemCall{
public:
  set_robust_listSystemCall(long syscallName, string syscallNumber);
  bool handleDetPre(state& s, ptracer& t) override;
  void handleDetPost(state& s, ptracer& t) override;
};

// =======================================================================================
/**
 *
 * long set_tid_address(int *tidptr);
 *
 * Sets the attribute tid_address (Thread specific id) to point to the passed address. This
 * is used by pthreads and clone.
 *
 * Should be deterministic.
 *
 */
class set_tid_addressSystemCall : public systemCall{
public:
  set_tid_addressSystemCall(long syscallName, string syscallNumber);
  bool handleDetPre(state& s, ptracer& t) override;
  void handleDetPost(state& s, ptracer& t) override;
};

// =======================================================================================
/**
 *
 * int sigaltstack(const stack_t *ss, stack_t *old_ss);
 *
 * sigaltstack() allows a process to define a new alternate signal stack and/or retrieve
 * the state of an existing alternate signal stack.  An alternate signal stack  is  used
 * during  the  execution  of a signal handler if the establishment of that handler (see
 * sigaction(2)) requested it.
 *
 * TODO.
 * SIGNAL RELATED.
 */
class sigaltstackSystemCall : public systemCall{
public:
  sigaltstackSystemCall(long syscallName, string syscallNumber);
  bool handleDetPre(state& s, ptracer& t) override;
  void handleDetPost(state& s, ptracer& t) override;
};
// =======================================================================================
/**
 * Implement various fields.
 * FILESYSTEM RELATED.
 */
class statfsSystemCall : public systemCall{
public:
  statfsSystemCall(long syscallName, string syscallNumber);
  bool handleDetPre(state& s, ptracer& t) override;
  void handleDetPost(state& s, ptracer& t) override;
};
// =======================================================================================
/**
 * TODO: Document and verify implementation.
 * TODO: Add logical clock for rt_sigprocmask.
 * Return results from our logical clock.
 */
class timeSystemCall : public systemCall{
public:
  timeSystemCall(long syscallName, string syscallNumber);
  bool handleDetPre(state& s, ptracer& t) override;
  void handleDetPost(state& s, ptracer& t) override;
};
// =======================================================================================
/**
 *
 * int utimensat(int dirfd, const char *pathname, const struct timespec times[2], int flags);
 *
 * Updates the timestamps of a file with nanosecond precision.
 * TODO FILESYSTEM RELATED.
 *
 * Definitely not deterministic! We use our logical clock to set the file timestamps.
 */
class utimensatSystemCall : public systemCall{
public:
  utimensatSystemCall(long syscallName, string syscallNumber);
  bool handleDetPre(state& s, ptracer& t) override;
  void handleDetPost(state& s, ptracer& t) override;
};

// =======================================================================================
/**
 *
 * ssize_t write(int fd, const void *buf, size_t count);
 *
 * write()  writes up to count bytes from the buffer pointed buf to the file referred to
 * by the file descriptor fd.
 *
 * TODO: Non deterministic due to errors being dependent on the underlying disk space
 * avaliable. This function can also fail due to many reasons, e.g. broken pipe.
 *
 * TODO: Check number of bytes written, and continue writting until _count_ bytes are
 * written. This may cause blocking issues in some cases.
 */
class writeSystemCall : public systemCall{
public:
  writeSystemCall(long syscallName, string syscallNumber);
  bool handleDetPre(state& s, ptracer& t) override;
  void handleDetPost(state& s, ptracer& t) override;
};
// =======================================================================================

#endif
