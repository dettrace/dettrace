#ifndef DETTRACE_SYSTEM_CALL_H
#define DETTRACE_SYSTEM_CALL_H

#include "systemCall.hpp"

using namespace std;

// TODO: chown
// TODO: fchown
// TODO: lchown
void writeVmTracee(void* localMemory, void* traceeMemory, size_t numberOfBytes,
                   pid_t traceePid);
void readVmTracee(void* traceeMemory, void* localMemory, size_t numberOfBytes,
                  pid_t traceePid);
void replaySystemcall(ptracer& t);
/**
 * Hopefully this will server as documentation for all our system calls.
 * Please keep in alphabetical order.
 * For every system call we list the expected prototype, a short desription from the man
 * page, and what we expect to do to get it deterministic (if applicable).
 */

// =======================================================================================
/**
 *
 * unsigned int alarm(unsigned int seconds);
 *
 * alarm()  arranges for a SIGALRM signal to be delivered to the calling process in sec‐
 * onds seconds.
 *
 * TODO: We must allow system call. Maybe deliver signal on next sytem call?
 */
class alarmSystemCall : public systemCall{
public:
  using systemCall::systemCall;
};
// =======================================================================================
/**
 * access()  checks  whether the calling process can access the file pathname.  If path‐
 * name is a symbolic link, it is dereferenced.
 */
class accessSystemCall : public systemCall{
public:
  using systemCall::systemCall;
  bool handleDetPre(state& s, ptracer& t, scheduler& sched) override;
};
// =======================================================================================
/**
 *
 * int chdir(const char *path);
 *
 * chdir() changes the current working directory of the calling process to the directory
       specified in path.
 *
 * This is deterministic and jailed thanks to our jail. We keep it here to print it's
 * path for debugging!
 *
 */
class chdirSystemCall : public systemCall{
public:
  using systemCall::systemCall;
  bool handleDetPre(state& s, ptracer& t, scheduler& sched) override;
};
// =======================================================================================
/**
 * int chmod(const char *pathname, mode_t mode);
 *
 * This is deterministic and jailed thanks to our jail. We keep it here to print it's
 * path for debugging!
 */
class chmodSystemCall : public systemCall{
public:
  using systemCall::systemCall;
  bool handleDetPre(state& s, ptracer& t, scheduler& sched) override;
};
// =======================================================================================
class chownSystemCall : public systemCall{
public:
  using systemCall::systemCall;
  bool handleDetPre(state& s, ptracer& t, scheduler& sched) override;
};
// =======================================================================================
/**
*
* int clock_gettime(clockid_t clk_id, struct timespec *tp);
*
*/
class clock_gettimeSystemCall : public systemCall{
public:
  using systemCall::systemCall;

  void handleDetPost(state& s, ptracer& t, scheduler& sched) override;
};
// =======================================================================================
/**
*
* int close(int fd);
*
*/
class closeSystemCall : public systemCall{
public:
  using systemCall::systemCall;

  void handleDetPost(state& s, ptracer& t, scheduler& sched) override;
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
 * Modern day fork() does a clone under the hood.

 * No need to do anything. We just need the signal from seccomp so tracer knows to
 * handle a forking event via @handleFork().
 */
class cloneSystemCall : public systemCall{
public:
  using systemCall::systemCall;

};
// =======================================================================================
/**
 *
 * int connect(int sockfd, const struct sockaddr *addr, socklen_t
 * addrlen);
 *
 * The connect() system call connects the socket referred to by the file descriptor sockfd
 * to the address specified by addr. The addrlen argument specifies the size of addr.
 * The format of the address in addr is determined by the address space of the socket sockfd.
 * TODO
 *
 */
class connectSystemCall : public systemCall{
public:
  using systemCall::systemCall;

  bool handleDetPre(state& s, ptracer& t, scheduler& sched) override;
  void handleDetPost(state& s, ptracer& t, scheduler& sched) override;
};
// =======================================================================================
/**
 *
 * int creat(const char *pathname, mode_t mode);
 *
 * A call to creat() is equivalent to calling open() with flags equal to
 * O_CREAT|O_WRONLY|O_TRUNC.
 */
class creatSystemCall : public systemCall{
public:
  using systemCall::systemCall;

  bool handleDetPre(state& s, ptracer& t, scheduler& sched) override;
  void handleDetPost(state& s, ptracer& t, scheduler& sched) override;
};
// =======================================================================================
/**
 * execve()  executes  the  program  pointed  to by filename.
 *
 * Deterministic. We print the path for debugging purposes here.
 */
class execveSystemCall : public systemCall{
  using systemCall::systemCall;

  bool handleDetPre(state& s, ptracer& t, scheduler& sched) override;
};
// =======================================================================================
/**
 * int faccessat(int dirfd, const char *pathname, int mode, int flags);
 *
 * Variant of access with f and at. See access.
 */
class faccessatSystemCall : public systemCall{
public:
  using systemCall::systemCall;
  bool handleDetPre(state& s, ptracer& t, scheduler& sched) override;
};
// =======================================================================================

/**
 * ssize_t fgetxattr(int fd, const char *name, void *value, size_t size);
 *
 * Get extended attribute for file for value.
 */
class fgetxattrSystemCall : public systemCall{
public:
  using systemCall::systemCall;
  void handleDetPost(state& s, ptracer& t, scheduler& sched) override;
};

// =======================================================================================
/**
 * ssize_t flistxattr(int fd, char *list, size_t size);
 *
 * List exted attributes for file descriptor.
 */
class flistxattrSystemCall : public systemCall{
public:
  using systemCall::systemCall;
  void handleDetPost(state& s, ptracer& t, scheduler& sched) override;
};
// =======================================================================================
/**
 * int fstat(int fd, struct stat *statbuf);
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
  using systemCall::systemCall;

  void handleDetPost(state& s, ptracer& t, scheduler& sched) override;
};
// =======================================================================================
/**
 * int fchownat(int dirfd, const char *pathname, uid_t owner, gid_t group, int flags);
 *
 * change owner of file with f and at variant. Deterministic thanks to light weight
 * container.
 *
 */
class fchownatSystemCall : public systemCall{
public:
  using systemCall::systemCall;

  bool handleDetPre(state& s, ptracer& t, scheduler& sched) override;
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
  using systemCall::systemCall;

  void handleDetPost(state& s, ptracer& t, scheduler& sched) override;
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
  using systemCall::systemCall;
  bool handleDetPre(state& s, ptracer& t, scheduler& sched) override;
  void handleDetPost(state& s, ptracer& t, scheduler& sched) override;
};
// =======================================================================================
/**
 *
 * char* getcwd(char *buf, size_t size);
 *
 * Deterministic. We print the path for debugging purposes here.
 *
 */
class getcwdSystemCall : public systemCall{
public:
  using systemCall::systemCall;

  bool handleDetPre(state& s, ptracer& t, scheduler& sched) override;
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
 */
class getdentsSystemCall : public systemCall{
public:
  using systemCall::systemCall;

  void handleDetPost(state& s, ptracer& t, scheduler& sched) override;
};
// =======================================================================================
class getdents64SystemCall : public systemCall{
public:
  using systemCall::systemCall;

  void handleDetPost(state& s, ptracer& t, scheduler& sched) override;
};
// =======================================================================================
/**
 *
 * int getpeername(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
 *
 * getpeername()  returns the address of the peer connected to the socket sockfd, in the
 * buffer pointed to by addr.
 *
 * We allow this system call to go through in the case where we it returns a non-zero
 * this happens on non-interactive bash mode. We might come back later if needed.
 *
 */
class getpeernameSystemCall : public systemCall{
public:
  using systemCall::systemCall;

  void handleDetPost(state& s, ptracer& t, scheduler& sched) override;
};
// =======================================================================================
/**
 *
 * ssize_t getrandom(void *buf, size_t buflen, unsigned int flags);
 *
 *
 * Nondeterministic. We fill the buffer with n deterministic bytes for the user :)
 *
 */
class getrandomSystemCall : public systemCall{
public:
  using systemCall::systemCall;

  void handleDetPost(state& s, ptracer& t, scheduler& sched) override;
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
  using systemCall::systemCall;

  void handleDetPost(state& s, ptracer& t, scheduler& sched) override;
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
  using systemCall::systemCall;

  void handleDetPost(state& s, ptracer& t, scheduler& sched) override;
};
// =======================================================================================
/**
 *
 * int gettimeofday(struct timeval *tv, struct timezone *tz);
 *
 * gives the number of seconds and microseconds since the Epoch
 *
 */
class gettimeofdaySystemCall : public systemCall{
public:
  using systemCall::systemCall;

  void handleDetPost(state& s, ptracer& t, scheduler& sched) override;
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
  using systemCall::systemCall;

  void handleDetPost(state& s, ptracer& t, scheduler& sched) override;
};
// =======================================================================================
/*
 * ssize_t llistxattr(const char *path, char *list, size_t size);
 *
 * Extended attributes are name:value pairs associated with inodes (files, directories,
 * symbolic links, etc.). They are extensions to the normal attributes which are
 * associated with all inodes in the system.
 * TODO
 */
class llistxattrSystemCall : public systemCall{
public:
  using systemCall::systemCall;

  void handleDetPost(state& s, ptracer& t, scheduler& sched) override;
};
// =======================================================================================
/*
 * ssize_t lgetxattr(const char *path, const char *name, void *value, size_t size);
 *
 * Extended attributes are name:value pairs associated with inodes (files, directories,
 * symbolic links, etc.). They are extensions to the normal attributes which are
 * associated with all inodes in the system.
 * TODO
 */
class lgetxattrSystemCall : public systemCall{
public:
  using systemCall::systemCall;

  void handleDetPost(state& s, ptracer& t, scheduler& sched) override;
};

// =======================================================================================
/**
 * int fstatat(int dirfd, const char *pathname, struct stat *statbuf, int flags);
 *
 * The fstatat() system call operates in exactly the same way as stat(), except for if
 * the pathname given in pathname is relative, then it is interpreted relative to the
 * directory referred to by the file descriptor dirfd (rather than relative to the  cur‐
 * rent  working  directory  of the calling process, as is done by stat() for a relative
 * pathname).
 *
 * Actual name of underlying system call is newfstatat.
 */
class newfstatatSystemCall : public systemCall{
public:
  using systemCall::systemCall;

  void handleDetPost(state& s, ptracer& t, scheduler& sched) override;
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
  using systemCall::systemCall;
  bool handleDetPre(state& s, ptracer& t, scheduler& sched) override;
  void handleDetPost(state& s, ptracer& t, scheduler& sched) override;
};
// =======================================================================================
/**
 *
 * int mkdir(const char *pathname, mode_t mode);
 *
 * mkdir() attempts to create a directory named pathname.
 *
 * Deterministic thanks to our container.
 */
class mkdirSystemCall : public systemCall{
public:
  using systemCall::systemCall;
  bool handleDetPre(state& s, ptracer& t, scheduler& sched) override;
};
// =======================================================================================
/**
 *
 *
 * "at" variat of mkdir. Same things apply.
 */
class mkdiratSystemCall : public systemCall{
public:
  using systemCall::systemCall;
  bool handleDetPre(state& s, ptracer& t, scheduler& sched) override;
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
  using systemCall::systemCall;
  bool handleDetPre(state& s, ptracer& t, scheduler& sched) override;
  void handleDetPost(state& s, ptracer& t, scheduler& sched) override;
};
// =======================================================================================
/**
 *
 * int open(const char *pathname, int flags);
 *
 * Given  a  pathname for a file, open() returns a file descriptor, a small, nonnegative
 * integer for use in subsequent system calls (read(2),  write(2),  lseek(2),  fcntl(2),
 * etc.).  The file descriptor returned by a successful call will be the lowest-numbered
 * file descriptor not currently open for the process.
 *
 */
class openSystemCall : public systemCall{
public:
  using systemCall::systemCall;

  bool handleDetPre(state& s, ptracer& t, scheduler& sched) override;
  void handleDetPost(state& s, ptracer& t, scheduler& sched) override;
};
// =======================================================================================
/**
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
 */
class openatSystemCall : public systemCall{
public:
  using systemCall::systemCall;

  bool handleDetPre(state& s, ptracer& t, scheduler& sched) override;
  void handleDetPost(state& s, ptracer& t, scheduler& sched) override;
};
// =======================================================================================
/**
 *
 * int pipe(int pipefd[2]);
 *
 * Create a pipe communication channel.
 */
class pipeSystemCall : public systemCall{
public:
  using systemCall::systemCall;
  bool handleDetPre(state& s, ptracer& t, scheduler& sched) override;
  void handleDetPost(state& s, ptracer& t, scheduler& sched) override;
};
// =======================================================================================
class pipe2SystemCall : public systemCall{
public:
  using systemCall::systemCall;
  bool handleDetPre(state& s, ptracer& t, scheduler& sched) override;
  void handleDetPost(state& s, ptracer& t, scheduler& sched) override;
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
  using systemCall::systemCall;
  bool handleDetPre(state& s, ptracer& t, scheduler& sched) override;
  void handleDetPost(state& s, ptracer& t, scheduler& sched) override;
};
// =======================================================================================
/**
 *
 * int poll(struct pollfd *fds, nfds_t nfds, int timeout);*
 *
 * Wait for one of a set of fds to become ready to perform I/O
 *
 * We use a general approach for all blocking IO system calls:
 * Turn it into a non blocking IO. Check if "it would have" blocked. If so, we preempt
 * the current running process and let another process run in it's place. Later we
 * come back to this process.
 *
 */
class pollSystemCall : public systemCall{
public:
  using systemCall::systemCall;
  bool handleDetPre(state& s, ptracer& t, scheduler& sched) override;
  void handleDetPost(state& s, ptracer& t, scheduler& sched) override;
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
  using systemCall::systemCall;
  bool handleDetPre(state& s, ptracer& t, scheduler& sched) override;
  void handleDetPost(state& s, ptracer& t, scheduler& sched) override;
};
// =======================================================================================
/**
 * TODO
 * FILESYSTEM RELATED.
 */
class readSystemCall : public systemCall{
public:
  using systemCall::systemCall;
  bool handleDetPre(state& s, ptracer& t, scheduler& sched) override;
  void handleDetPost(state& s, ptracer& t, scheduler& sched) override;
};
// =======================================================================================
/**
 *
 *
 * ssize_t readv(int fd, const struct iovec *iov, int iovcnt);
 *
 * read or write data into multiple buffers
 * Would be non determinitic based on number of bytes read is less than number of bytes
 * asked for.
 *
 * TODO
 */
class readvSystemCall : public systemCall{
public:
  using systemCall::systemCall;
  bool handleDetPre(state& s, ptracer& t, scheduler& sched) override;
  void handleDetPost(state& s, ptracer& t, scheduler& sched) override;
};
// =======================================================================================
/*
 * ssize_t readlink(const char *pathname, char *buf, size_t bufsiz);
 *
 * readlink, readlinkat - read value of a symbolic link
 * Deterministic thanks to our jail. Intercepted merely for debugging purposes.
 *
 * TODO
 */
class readlinkSystemCall : public systemCall{
public:
  using systemCall::systemCall;
  bool handleDetPre(state& s, ptracer& t, scheduler& sched) override;
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
  using systemCall::systemCall;
  bool handleDetPre(state& s, ptracer& t, scheduler& sched) override;
  void handleDetPost(state& s, ptracer& t, scheduler& sched) override;
};
// =======================================================================================
/**
 * int rename(const char *oldpath, const char *newpath);
 *
 *
 * No reason it shouldn't be deterministic.
 */
class renameSystemCall : public systemCall{
public:
  using systemCall::systemCall;
  bool handleDetPre(state& s, ptracer& t, scheduler& sched) override;
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
  using systemCall::systemCall;
  bool handleDetPre(state& s, ptracer& t, scheduler& sched) override;
  void handleDetPost(state& s, ptracer& t, scheduler& sched) override;
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
  using systemCall::systemCall;
  bool handleDetPre(state& s, ptracer& t, scheduler& sched) override;
  void handleDetPost(state& s, ptracer& t, scheduler& sched) override;
};
// =======================================================================================
/**
 * int setpgid(pid_t pid, pid_t pgid);
 *
 * Set a process's PGID.
 * TODO
 */
class set_robust_listSystemCall : public systemCall{
public:
  using systemCall::systemCall;
  bool handleDetPre(state& s, ptracer& t, scheduler& sched) override;
  void handleDetPost(state& s, ptracer& t, scheduler& sched) override;
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
  using systemCall::systemCall;
  bool handleDetPre(state& s, ptracer& t, scheduler& sched) override;
  void handleDetPost(state& s, ptracer& t, scheduler& sched) override;
};
// =======================================================================================
/**
 * Implement various fields.
 * FILESYSTEM RELATED.
 */
class statfsSystemCall : public systemCall{
public:
  using systemCall::systemCall;

  void handleDetPost(state& s, ptracer& t, scheduler& sched) override;
};
// =======================================================================================
/**
 *
 * int symlink(const char *target, const char *linkpath);
 *
 * symlink() creates a symbolic link named linkpath which contains the string target.
 *
 * Deterministic thanks to our container :)
 */
class symlinkSystemCall : public systemCall{
public:
  using systemCall::systemCall;

  bool handleDetPre(state& s, ptracer& t, scheduler& sched) override;
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
  using systemCall::systemCall;

  void handleDetPost(state& s, ptracer& t, scheduler& sched) override;
};
// =======================================================================================
/**
 *
 * int tgkill(int tgid, int tid, int sig);
 *
 * SIGNAL RELATED
 *
 * Should be deterministic in the sense that our pid namespace separates us from other
 * processes. So only processes in our tree can use it. However, if a process delivers
 * a signal to another process, how can we make that determinitic? Maybe we don't care
 * about those programs? If a signal was to be delivered from P1 -> P2, P2 has no
 * guarantee of when the signal will arrive, unless they do a wait*(), so maybe only
 * deliver the signal if P2 is waiting? Otherwise never deliver it since the signal
 * may take arbitrarily long to be delivered.
 * TODO
 */
class tgkillSystemCall : public systemCall{
public:
  using systemCall::systemCall;
  bool handleDetPre(state& s, ptracer& t, scheduler& sched) override;
  void handleDetPost(state& s, ptracer& t, scheduler& sched) override;
};
// =======================================================================================
/**
 * TODO: Document and verify implementation.
 * TODO: Add logical clock for rt_sigprocmask.
 * Return results from our logical clock.
 */
class timeSystemCall : public systemCall{
public:
  using systemCall::systemCall;

  void handleDetPost(state& s, ptracer& t, scheduler& sched) override;
};
// =======================================================================================
/**
 *
 * clock_t times(struct tms *buf);
 *
 * times()  stores the current process times in the struct tms that buf points to.  The
 * struct tms is as defined in <sys/times.h>:

 *        struct tms {
 *             clock_t tms_utime;  // user time
 *             clock_t tms_stime;  // system time
 *             clock_t tms_cutime; // user time of children
 *             clock_t tms_cstime; // system time of children
 *         };

 * We simply zero out everything for now :3
 */
class timesSystemCall : public systemCall{
public:
  using systemCall::systemCall;

  void handleDetPost(state& s, ptracer& t, scheduler& sched) override;
};
// =======================================================================================
/**
 *
 * int uname(struct utsname *buf);
 *
 * uname()  returns  system information in the structure pointed to by buf.
 * Definitely non deterministic.
 *
 *
 */
class unameSystemCall : public systemCall{
public:
  using systemCall::systemCall;

  void handleDetPost(state& s, ptracer& t, scheduler& sched) override;
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
 * We keep it here to print it's path.
 */
class unlinkSystemCall : public systemCall{
public:
  using systemCall::systemCall;
  bool handleDetPre(state& s, ptracer& t, scheduler& sched) override;

};
// =======================================================================================
/**
 *
 * int unlinkat(int dirfd, const char *pathname, int flags);
 *
 * The unlinkat() system call operates in exactly the same way  as  either  unlink()  or
 * rmdir(2)  (depending  on  whether or not flags includes the AT_REMOVEDIR flag) except
 * for the differences described here.

 * If the pathname given in pathname is relative, then it is interpreted relative to the
 * directory  referred to by the file descriptor dirfd (rather than relative to the cur‐
 * rent working directory of the calling process, as is done by  unlink()  and  rmdir(2)
 * for a relative pathname).

 * If  the  pathname  given  in  pathname  is  relative  and  dirfd is the special value
 * AT_FDCWD, then pathname is interpreted relative to the current working  directory  of
 * the calling process (like unlink() and rmdir(2)).

 * If the pathname given in pathname is absolute, then dirfd is ignored.

 * Seems deterministic enough :)
 */
class unlinkatSystemCall : public systemCall{
public:
  using systemCall::systemCall;
  bool handleDetPre(state& s, ptracer& t, scheduler& sched) override;
 };
// =======================================================================================
/**
 *
 * int utime(const char *filename, const struct utimbuf *times);
 *
 * The utime() system call changes the access and modification times of the inode speci‐
 * fied by filename to the actime and modtime fields of times respectively.
 *
 * The time the user uses should be determinitic. We only have to watch out for the zero
 * case when the user sets his own time.
 */
class utimeSystemCall : public systemCall{
public:
  using systemCall::systemCall;
  bool handleDetPre(state& s, ptracer& t, scheduler& sched) override;
  void handleDetPost(state& s, ptracer& t, scheduler& sched) override;
};

// =======================================================================================
/**
 *
 * int utimes(const char *filename, const struct timeval times[2]);
 *
 * The utimes() system call changes the access and modification times of the inode speci‐
 * fied by filename to the actime and modtime fields of times respectively.
 *
 * The time the user uses should be determinitic. We only have to watch out for the zero
 * case when the user sets his own time.
 */
class utimesSystemCall : public systemCall{
public:
  using systemCall::systemCall;
  bool handleDetPre(state& s, ptracer& t, scheduler& sched) override;
  void handleDetPost(state& s, ptracer& t, scheduler& sched) override;
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
  using systemCall::systemCall;
  bool handleDetPre(state& s, ptracer& t, scheduler& sched) override;
  void handleDetPost(state& s, ptracer& t, scheduler& sched) override;
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
  using systemCall::systemCall;

};
// =======================================================================================
class wait4SystemCall : public systemCall{
public:
  using systemCall::systemCall;
  bool handleDetPre(state& s, ptracer& t, scheduler& sched) override;
  void handleDetPost(state& s, ptracer& t, scheduler& sched) override;
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
  using systemCall::systemCall;
  bool handleDetPre(state& s, ptracer& t, scheduler& sched) override;
  void handleDetPost(state& s, ptracer& t, scheduler& sched) override;
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
  using systemCall::systemCall;
  bool handleDetPre(state& s, ptracer& t, scheduler& sched) override;
  void handleDetPost(state& s, ptracer& t, scheduler& sched) override;
};

// =======================================================================================
template <typename T>
void handleDents(state& s, ptracer& t, scheduler& sched){
  // Error, return system call to tracee.
  if((int64_t) t.getReturnValue() < 0){
    return;
  }

  // Use file descriptor to fetch correct entry in table.
  int fd = (int) t.arg1();
  uint8_t* traceeBuffer = (uint8_t*) t.arg2();
  size_t traceeBufferSize = t.arg3();

  // We have never seen this entry before! This is a new getdents call, not a
  // replay by us.
  if(s.dirEntries.count(fd) == 0){
    auto msg = "Tracee requested getdents for the first time for fd: %d.\n";
      s.log.writeToLog(Importance::info, msg, fd);

      s.dirEntries.emplace( fd, directoryEntries<linux_dirent>{s.dirEntriesBytes} );
  }

  // We have read zero bytes. We're done!
  if(t.getReturnValue() == 0){
    s.log.writeToLog(Importance::info, "All bytes have been read.\n");
    s.log.writeToLog(Importance::info, "Returning sorted entries to tracee.\n");

    // We want to fill up to traceeBufferSize which is the size the tracee originally
    // asked for.

    vector<int8_t> filledVector = s.dirEntries.at(fd).getSortedEntries(traceeBufferSize);
    s.log.writeToLog(Importance::info, "Returning %d bytes!\n", filledVector.size());

    // Write entry back to tracee!
    writeVmTracee(filledVector.data(), traceeBuffer, filledVector.size(), t.getPid());
    // Set return register!
    t.setReturnRegister(filledVector.size());
  }
  // We read some bytes but there might be more to read.
  else{
    s.log.writeToLog(Importance::info, "Reading directory entries...\n");

    // Read entries from tracee's buffer.
    // We only copy over the return value, which is how many bytes were actually filled
    // by the kernel into the tracee's buffer.
    size_t bytesToCopy = t.getReturnValue();
    uint8_t localBuffer[bytesToCopy];
    readVmTracee(traceeBuffer, localBuffer, bytesToCopy, t.getPid());
    vector<uint8_t> newChunk { localBuffer, localBuffer + bytesToCopy };

    // Copy chunks over to our directory entry for this file descriptor.
    s.dirEntries.at(fd).addChunk(newChunk);

    s.log.writeToLog(Importance::info, "Replaying system call to read more bytes...\n");
    replaySystemcall(t);
  }
  return;
}
// =======================================================================================
#endif
