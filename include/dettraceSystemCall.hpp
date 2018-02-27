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
 * int chmod(const char *pathname, mode_t mode);
 *
 * The  chmod() and fchmod() system calls change a files mode bits.
 * FILESYSTEM RELATED.
 */
class chmodSystemCall : public systemCall{
public:
  chmodSystemCall(long syscallName, string syscallNumber);
  bool handleDetPre(state& s, ptracer& t) override;
  void handleDetPost(state& s, ptracer& t) override;
};

// =======================================================================================
/**
*
* int clock_gettime(clockid_t clk_id, struct timespec *tp); 
*
*/
class clock_gettimeSystemCall : public systemCall{
public:
  clock_gettimeSystemCall(long syscallName, string syscallNumber);
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
 * Modern day fork() does a clone under the hood. Dettrace.
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
/**
 *
 * int connect(int sockfd, const struct sockaddr *addr, socklen_t
 * addrlen);
 *  
 *  The connect() system call connects the socket referred to by the file descriptor sockfd to the address specified by addr. 
 *  The addrlen argument specifies the size of addr. The format of the address in addr is determined by the address space of the socket sockfd.
 *
 */
class connectSystemCall : public systemCall{
public:
  connectSystemCall(long syscallNAme, string syscallNumber);
  bool handleDetPre(state &s, ptracer &t) override;
  void handleDetPost(state &s, ptracer &t) override;
};
// =======================================================================================
/*
 *
 * int dup(int oldfd);
 *
 * The  dup() system call creates a copy of the file descriptor oldfd, using the lowest-
 * numbered unused file descriptor for the new descriptor.
 *
 * As long as our threads are determinstic, file descriptors should be deterministic too.
 *
 */
class dupSystemCall : public systemCall{
public:
  dupSystemCall(long syscallName, string syscallNumber);
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
 * As long as our threads are determinstic, file descriptors should be deterministic too.
 *
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
 *
 * int faccessat(int dirfd, const char *pathname, int mode, int flags);
 *
 * The faccessat() system call operates in exactly the same way as access(), except  for
 * the differences described here.

 * If the pathname given in pathname is relative, then it is interpreted relative to the
 * directory referred to by the file descriptor dirfd (rather than relative to the  cur‐
 * rent  working directory of the calling process, as is done by access() for a relative
 * pathname).
 *
 * FILESYSTEM RELATED.
 */
class faccessatSystemCall : public systemCall{
public:
  faccessatSystemCall(long syscallName, string syscallNumber);
  bool handleDetPre(state& s, ptracer& t) override;
  void handleDetPost(state& s, ptracer& t) override;
};
// =======================================================================================
/**
 *
 * int fcntl(int fd, int cmd, ... arg );
 *
 * performs  one  of the operations described below on the open file descriptor
 * fd.  The operation is determined by cmd. Duplicating a file descriptor,
 * File descriptor flags, File status flags, Advisory record locking, ...
 *
 * FILESYSTEM RELATED.
 *
 * Seems nondeterministic based on the per process record locking.
 */
class fcntlSystemCall : public systemCall{
public:
  fcntlSystemCall(long syscallName, string syscallNumber);
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
 * Notice we do the exact same thing for lstat, stat, and fstat.
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
 *    int futex(int *uaddr, int futex_op, int val, const struct timespec *timeout,
 *              int *uaddr2, int val3);
 *
 * Fast mutex.
 * TODO: Understand what these guys even do.
 */
class futexSystemCall : public systemCall{
public:
  futexSystemCall(long syscallName, string syscallNumber);
  bool handleDetPre(state& s, ptracer& t) override;
  void handleDetPost(state& s, ptracer& t) override;
};

// =======================================================================================
/**
 *
 * char* getcwd(char *buf, size_t size);
 *
 * FILESYSTEM RELATED.
 *
 * Nothing to do. I guess changes based on starting working directory? But this is part
 * the input to our program.
 */
class getcwdSystemCall : public systemCall{
public:
  getcwdSystemCall(long syscallName, string syscallNumber);
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
 *
 * uid_t geteuid(void);
 *
 * geteuid() returns the effective user ID of the calling process.
 * Deterministic and reproducible thanks to our user namespace!
 */
class geteuidSystemCall : public systemCall{
public:
  geteuidSystemCall(long syscallName, string syscallNumber);
  bool handleDetPre(state& s, ptracer& t) override;
  void handleDetPost(state& s, ptracer& t) override;
};
// =======================================================================================
/**
 *
 * gid_t getegid(void);
 *
 * getegid() returns the effective group ID of the calling process.
 *
 */
class getegidSystemCall : public systemCall{
public:
  getegidSystemCall(long syscallName, string syscallNumber);
  bool handleDetPre(state& s, ptracer& t) override;
  void handleDetPost(state& s, ptracer& t) override;
};
// =======================================================================================
/**
 *
 * int getgroups(int size, gid_t list[]);
 *
 * getgroups()  returns the supplementary group IDs of the calling process in list.
 *
 */
class getgroupsSystemCall : public systemCall{
public:
  getgroupsSystemCall(long syscallName, string syscallNumber);
  bool handleDetPre(state& s, ptracer& t) override;
  void handleDetPost(state& s, ptracer& t) override;
};
// =======================================================================================
/**
 *
 * pid_t getpgrp(void);
 *
 * getting and setting the process group ID (PGID) of a process.
 *
 */
class getpgrpSystemCall : public systemCall{
public:
  getpgrpSystemCall(long syscallName, string syscallNumber);
  bool handleDetPre(state& s, ptracer& t) override;
  void handleDetPost(state& s, ptracer& t) override;
};
// =======================================================================================
/**
 *
 * gid_t getgid(void);gid_t getgid(void);
 *
 * getgid() returns the real group ID of the calling process.
 * Deterministic and reproducible thanks to our user namespace!
 */
class getgidSystemCall : public systemCall{
public:
  getgidSystemCall(long syscallName, string syscallNumber);
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
 * pid_t getppid();
 *
 * Returns the pid of the calling process.
 *
 * Obviously nondeterministic. We instead keep a map of real pids to virtual pid mappings.
 * The running process only gets to observe virtual pids, but all system calls that
 * require pids, use real pids by mapping back.
 * TODO: ppid has interesting semantics where the return value actually depends on whether
 * the parent process has terminated or not. We will probably ignore this and always return
 * the original parent's pid.
 */
class getppidSystemCall : public systemCall{
public:
  getppidSystemCall(long syscallName, string syscallNumber);
  bool handleDetPre(state& s, ptracer& t) override;
  void handleDetPost(state& s, ptracer& t) override;
};
// =======================================================================================
/**
 *
 *
 *        The getrlimit() and setrlimit() system calls get and set resource
 *               limits respectively.  Each resource has an associated soft and hard
 *                      limit, as defined by the rlimit structure.
 *
 *
 *                                 
 *        int getrlimit(int resource, struct rlimit *rlim);                        
 *             
 *	                  
 *
 */ 
class getrlimitSystemCall : public systemCall{
public:
  getrlimitSystemCall(long syscallName, string syscallNumber);
  bool handleDetPre(state& s, ptracer& t) override;
  void handleDetPost(state& s, ptracer& t) override;
};
// =======================================================================================
/**
 *
 * int getrusage(int who, struct rusage *usage);
 *
 * returns resource usage measures for who.
 *
 */
class getrusageSystemCall : public systemCall{
public:
  getrusageSystemCall(long syscallName, string syscallNumber);
  bool handleDetPre(state& s, ptracer& t) override;
  void handleDetPost(state& s, ptracer& t) override;
};

// =======================================================================================
/**
 * uid_t getuid(void);
 *
 * getuid() returns the real user ID of the calling process.
 *
 * We pretend to be 65534 "nobody"
 */
class getuidSystemCall : public systemCall{
public:
  getuidSystemCall(long syscallName, string syscallNumber);
  bool handleDetPre(state& s, ptracer& t) override;
  void handleDetPost(state& s, ptracer& t) override;
};
// =======================================================================================
/**
 *
 *  ssize_t lgetxattr(const char *path, const char *name,
 *                   void *value, size_t size);
 *
 *
 *
 *  getxattr() retrieves the value of the extended attribute identified by name and associated with the given path in the file system. The length of the attribute value is returned.
 *
 *
 */
class getxattrSystemCall : public systemCall{
public:
  getxattrSystemCall(long syscallName, string syscallNumber);
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
 *  ssize_t lgetxattr(const char *path, const char *name,
 *                   void *value, size_t size);
 *
 * lgetxattr() is identical to getxattr(), except in the case of a symbolic link, where the link itself is interrogated, not the file that it refers to.
 *
 */
class lgetxattrSystemCall : public systemCall{
public:
  lgetxattrSystemCall(long syscallName, string syscallNumber);
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
 * int nanosleep(const struct timespec *req, struct timespec *rem);
 *
 * nanosleep()  suspends  the  execution of the calling thread until either at least the
 * time specified in *req has elapsed. rem is populated with the time left if this system
 * call was interrupted by a signal.

 * Surprisingly, I think this sytem was is deterministic for our purposes if we have a
 * handle on signals.
 */
class nanosleepSystemCall : public systemCall{
public:
  nanosleepSystemCall(long syscallName, string syscallNumber);
  bool handleDetPre(state& s, ptracer& t) override;
  void handleDetPost(state& s, ptracer& t) override;
};
// =======================================================================================
/**
 * off_t lseek(int fd, off_t offset, int whence);
 *
 * repositions the file offset of the open file description associated with the file
 * descriptor fd to the argument offset according  to  the  directive whence.
 *
 * Under threads, this could be non deterministic if two threads are using the same
 * file descriptior? But if we assume deterministic thread execution this shouldn't
 * be an issue :)
 * FILESYSTEM RELATED.
 *
 */
class lseekSystemCall : public systemCall{
public:
  lseekSystemCall(long syscallName, string syscallNumber);
  bool handleDetPre(state& s, ptracer& t) override;
  void handleDetPost(state& s, ptracer& t) override;
};
// =======================================================================================
/**
 * int lstat(const char *pathname, struct stat *statbuf);
 *
 * lstat()  is  identical to stat(), except that if pathname is a symbolic link,
 * then it returns information about the link itself, not the file that it refers to.
 *
 * FILESYSTEM RELATED.
 * Notice we do the exact same thing for lstat, stat, and fstat.
 */
class lstatSystemCall : public systemCall{
public:
  lstatSystemCall(long syscallName, string syscallNumber);
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
 * int pipe(int pipefd[2]);
 *
 * Create a pipe communication channel.
 * TODO
 */
class pipeSystemCall : public systemCall{
public:
  pipeSystemCall(long syscallName, string syscallNumber);
  bool handleDetPre(state& s, ptracer& t) override;
  void handleDetPost(state& s, ptracer& t) override;
};
// =======================================================================================
/**
 *
 * The  Linux  pselect6() system call modifies its timeout argument.  However, the glibc
 * wrapper function hides this behavior by using a local variable for the timeout  argu‐
 * ment  that is passed to the system call.  Thus, the glibc pselect() function does not
 * modify its timeout argument; this is the behavior required by POSIX.1-2001.
 *
 * The final argument of the pselect6() system call is not a sigset_t * pointer, but  is
 * instead a structure of the form:

 * struct {
 *   const kernel_sigset_t *ss;   Pointer to signal set
 *   size_t ss_len;               Size (in bytes) of object pointed to by 'ss'
 * };

 * This  allows the system call to obtain both a pointer to the signal set and its size,
 * while allowing for the fact that most architectures support a maximum of 6  arguments
 * to  a system call.  See sigprocmask(2) for a discussion of the difference between the
 * kernel and libc notion of the signal set.
 *
 * Create a pipe communication channel.
 * TODO
 */
class pselect6SystemCall : public systemCall{
public:
  pselect6SystemCall(long syscallName, string syscallNumber);
  bool handleDetPre(state& s, ptracer& t) override;
  void handleDetPost(state& s, ptracer& t) override;
};
// =======================================================================================
/**
 *
 *
 *  int poll(struct pollfd *fds, nfds_t nfds, int timeout);*
 *
 *  wait for one of a set of fds to become ready to perform I/O
 *
 */
class pollSystemCall : public systemCall{
public:
  pollSystemCall(long syscallName, string syscallNumber);
  bool handleDetPre(state &s, ptracer &t) override;
  void handleDetPost(state &s, ptracer &t) override;
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
 *
 * ssize_t readlink(const char *pathname, char *buf, size_t bufsiz);
 *
 * readlink() places the contents of the symbolic link pathname in the buffer buf, which
 * has size bufsiz.  readlink() does not append a null byte to buf.  It will  (silently)
 * truncate  the  contents (to a length of bufsiz characters), in case the buffer is too
 * small to hold all of the contents.
 *
 * FILESYSTEM RELATED.
 * TODO: This could be nondeterminism based on the value the symlink points to from
 * call to call.
 */
class readlinkSystemCall : public systemCall{
public:
  readlinkSystemCall(long syscallName, string syscallNumber);
  bool handleDetPre(state& s, ptracer& t) override;
  void handleDetPost(state& s, ptracer& t) override;
};
// =======================================================================================
/**
 *
 *
 * ssize_t readv(int fd, const struct iovec *iov, int iovcnt);
 *
 * read or write data into multiple buffers
 * 
 *
 */
class readvSystemCall : public systemCall{
public:
  readvSystemCall(long syscallName, string syscallNumber);
  bool handleDetPre(state &s, ptracer &t) override;
  void handleDetPost(state &s, ptracer &t) override;
};
// =======================================================================================
/**
 * ssize_t recvmsg(int sockfd, struct msghdr *msg, int flags);
 * 
 * recvmsg() call is used to receive messages from a socket and amy be used to receive
 * data on a socket whether or not it is connection-oriented.
 */
class recvmsgSystemCall : public systemCall{
public:
  recvmsgSystemCall(long syscallName, string syscallNumber);
  bool handleDetPre(state &s, ptracer &t) override;
  void handleDetPost(state &s, ptracer &t) override;
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
 *
 *  ssize_t sendto(int sockfd, const void *buf, size_t len, int flags,
 *                 const struct sockaddr *dest_addr, socklen_t addrlen);
 *
 * If sendto() is used on a connection-mode (SOCK_STREAM, SOCK_SEQPACKET) socket,
 * the arguments dest_addr and addrlen are ignored (and the error EISCONN may be
 * returned when they are not NULL and 0), and the error ENOTCONN is returned when
 * the socket was not actually connected. Otherwise, the address of the target is
 * given by dest_addr with addrlen specifying its size.  For sendmsg(), the address
 * of the target is given by msg.msg_name, with msg.msg_namelen specifying its size.
 *
 */
class sendtoSystemCall : public systemCall{
public:
  sendtoSystemCall(long syscallName, string syscallNumber);
  bool handleDetPre(state &s, ptracer &t) override;
  void handleDetPost(state &s, ptracer &t) override;
};
// =======================================================================================
/**
 *
 * int select(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds,
 *            struct timeval *timeout);
 *
 * select()  and pselect() allow a program to monitor multiple file descriptors, waiting
 * until one or more of the file descriptors become "ready" for some class of I/O opera‐
 * tion (e.g., input possible).
 *
 * TODO! Super non deterministic, the most non-deterministic of them all!
 */
class selectSystemCall : public systemCall{
public:
  selectSystemCall(long syscallName, string syscallNumber);
  bool handleDetPre(state &s, ptracer &t) override;
  void handleDetPost(state &s, ptracer &t) override;
};
// =======================================================================================
/**
 * int setpgid(pid_t pid, pid_t pgid);
 *
 * Set a process's PGID.
 *
 */
class setpgidSystemCall : public systemCall{
public:
  setpgidSystemCall(long syscallName, string syscallNumber);
  bool handleDetPre(state &s, ptracer &t) override;
  void handleDetPost(state &s, ptracer &t) override;
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
 *
 * int socket(int domain, int type, int protocol);
 * 
 * socket() creates an endpoint for communication and returns a file
 * descriptor that refers to that endpoint.  The file descriptor
 * returned by a successful call will be the lowest-numbered file
 * descriptor not currently open for the process.
 *
 */
class socketSystemCall : public systemCall{
public:
  socketSystemCall(long syscallName, string syscallNumber);
  bool handleDetPre(state &s, ptracer &t) override;
  void handleDetPost(state &s, ptracer &t) override;
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
 *
 * int stat(const char *pathname, struct stat *statbuf);
 *
 * stat() and retrieve information about the file pointed to by pathname.
 *
 * FILESYSTEM RELATED.
 * TODO: Figure out semantics of all fields in struct stat* statbuf.
 * Notice we do the exact same thing for lstat, stat, and fstat.
 */
class statSystemCall : public systemCall{
public:
  statSystemCall(long syscallName, string syscallNumber);
  bool handleDetPre(state& s, ptracer& t) override;
  void handleDetPost(state& s, ptracer& t) override;
};
// =======================================================================================
/**
 *
 * int sysinfo(struct sysinfo *info);
 *
 * sysinfo()  returns  certain  statistics on memory and swap usage, as well as the load
 * average.
 *
 */
class sysinfoSystemCall : public systemCall{
public:
  sysinfoSystemCall(long syscallName, string syscallNumber);
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
 * mode_t umask(mode_t mask);
 *
 * umask()  sets  the  calling  process's file mode creation mask (umask) to mask & 0777
 * (i.e., only the file permission bits of mask are  used),  and  returns  the  previous
 * value of the mask.
 *
 * As explained in the notes, this is suffers from race conditions with threads. If we
 * have deterministic threading, this shouldn't be an issue.
 *
 * The mask could change from subsequent call to call, but if we consider the file
 * metadata part of our input, it should be fine.
 * FILESYSTEM RELATED
 */
class umaskSystemCall : public systemCall{
public:
  umaskSystemCall(long syscallName, string syscallNumber);
  bool handleDetPre(state& s, ptracer& t) override;
  void handleDetPost(state& s, ptracer& t) override;
};
// =======================================================================================
/**
 *
 * int uname(struct utsname *buf);
 *
 * uname()  returns  system information in the structure pointed to by buf.
 *
 *
 */
class unameSystemCall : public systemCall{
public:
  unameSystemCall(long syscallName, string syscallNumber);
  bool handleDetPre(state& s, ptracer& t) override;
  void handleDetPost(state& s, ptracer& t) override;
};
// =======================================================================================
/**
 *
 * int unlink(const char *pathname);
 *
 * unlink()  deletes  a  name  from the filesystem.  If that name was the last link to a
 * file and no processes have the file open, the file is deleted and the  space  it  was
 * using is made available for reuse.
 *
 * Similarly to other system calls, under deterministic threads and processes, this
 * should be deterministic.
 * FILESYSTEM RELATED
 */
class unlinkSystemCall : public systemCall{
public:
  unlinkSystemCall(long syscallName, string syscallNumber);
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
 * This is an issue for the case where both times entries are null. From utimensat(2):
 * > If times is NULL, then both timestamps are set to the current time.
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
 * pid_t vfork(void);
 *
 * The vfork() function has the same effect as fork(2), except that the
 * behavior is undefined if the process created by  vfork()  either  modifies  any  data
 * other  than  a variable of type pid_t used to store the return value from vfork(), or
 * returns from the function in which vfork() was called, or calls  any  other  function
 * before successfully calling _exit(2) or one of the exec(3) family of functions.
 *
 * vfork() is a special case of clone(2).  It is used to create  new  processes  without
 * copying  the page tables of the parent process.  It may be useful in performance-sen‐
 * sitive applications where a  child  is  created  which  then  immediately  issues  an
 * execve(2).
 *
 * This system call should be deterministic as long as we have the child run to completion
 * before letting the parent run, notice this is not the exact behavior of vfork, as if
 * the child execve's then the parent will no longer be suspended.
 */
class vforkSystemCall : public systemCall{
public:
  vforkSystemCall(long syscallName, string syscallNumber);
  bool handleDetPre(state& s, ptracer& t) override;
  void handleDetPost(state& s, ptracer& t) override;
};
// =======================================================================================
/**
 *
 * pid_t wait4(pid_t pid, int *wstatus, int options, struct rusage *rusage);
 *
 * Wait for the specified process, usually blocks but depends on `options` parameter.
 * Populates `wstatus` with information on the process `pid` that we `wait4` for.
 *
 * TODO: So far, all I do is translate the vpid to a real pid. There is probably more
 * to be done to make it fully deterministic!
 */
class wait4SystemCall : public systemCall{
public:
  wait4SystemCall(long syscallName, string syscallNumber);
  bool handleDetPre(state& s, ptracer& t) override;
  void handleDetPost(state& s, ptracer& t) override;
};
// =======================================================================================
/**
 *
 * ssize_t writev(int fd, const struct iovec *iov, int iovcnt)
 *
 * The  writev()  system call writes iovcnt buffers of data described by iov to the file
 * associated with the file descriptor fd ("gather output").
 *
 * Non deterministic!
 * Same problem as regular writes.
 *
 */
class writevSystemCall : public systemCall{
public:
  writevSystemCall(long syscallName, string syscallNumber);
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
