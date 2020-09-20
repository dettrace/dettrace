#ifndef DETTRACE_SYSTEM_CALL_H
#define DETTRACE_SYSTEM_CALL_H

#include "globalState.hpp"
#include "scheduler.hpp"
#include "state.hpp"
#include "util.hpp"
#include "utilSystemCalls.hpp"

#include <signal.h>
#include <sys/syscall.h> /* For SYS_xxx definitions */

using namespace std;

#define ARCH_GET_CPUID 0x1011
#define ARCH_SET_CPUID 0x1012

/**
 * Hopefully this will server as documentation for all our system calls.
 * Please keep in alphabetical order.
 * For every system call we list the expected prototype, a short desription from
 * the man page, and what we expect to do to get it deterministic (if
 * applicable).
 */

// =======================================================================================
/**
 *
 * unsigned int alarm(unsigned int seconds);
 *
 * alarm() arranges for a SIGALRM signal to be delivered to the calling process
 * in a given number of seconds.
 */
class alarmSystemCall {
public:
  static bool handleDetPre(
      globalState& gs, state& s, ptracer& t, scheduler& sched);
  static void handleDetPost(
      globalState& gs, state& s, ptracer& t, scheduler& sched);

  const int syscallNumber = SYS_alarm;
  const string syscallName = "alarm";
};
// =======================================================================================
/**
 * int access(const char *pathname, int mode);
 *
 * access()  checks  whether the calling process can access the file pathname.
 * If path‐ name is a symbolic link, it is dereferenced.
 */
class accessSystemCall {
public:
  static bool handleDetPre(
      globalState& gs, state& s, ptracer& t, scheduler& sched);
  static void handleDetPost(
      globalState& gs, state& s, ptracer& t, scheduler& sched);

  const int syscallNumber = SYS_access;
  const string syscallName = "access";
};
// =======================================================================================
class brkSystemCall {
public:
  static bool handleDetPre(
      globalState& gs, state& s, ptracer& t, scheduler& sched);
  static void handleDetPost(
      globalState& gs, state& s, ptracer& t, scheduler& sched);

  const int syscallNumber = SYS_brk;
  const string syscallName = "brk";
};
// =======================================================================================
/**
 *
 * int chdir(const char *path);
 *
 * chdir() changes the current working directory of the calling process to the
 directory specified in path.
 *
 * This is deterministic and jailed thanks to our jail. We keep it here to print
 it's
 * path for debugging!
 *
 */
class chdirSystemCall {
public:
  static bool handleDetPre(
      globalState& gs, state& s, ptracer& t, scheduler& sched);
  static void handleDetPost(
      globalState& gs, state& s, ptracer& t, scheduler& sched);

  const int syscallNumber = SYS_chdir;
  const string syscallName = "chdir";
};
// =======================================================================================
/**
 * int chmod(const char *pathname, mode_t mode);
 *
 * This is deterministic and jailed thanks to our jail. We keep it here to print
 * it's path for debugging!
 */
class chmodSystemCall {
public:
  static bool handleDetPre(
      globalState& gs, state& s, ptracer& t, scheduler& sched);
  static void handleDetPost(
      globalState& gs, state& s, ptracer& t, scheduler& sched);

  const int syscallNumber = SYS_chmod;
  const string syscallName = "chmod";
};
// =======================================================================================

/**
 *
 * int clock_gettime(clockid_t clk_id, struct timespec *tp);
 *
 */
class clock_gettimeSystemCall {
public:
  static bool handleDetPre(
      globalState& gs, state& s, ptracer& t, scheduler& sched);
  static void handleDetPost(
      globalState& gs, state& s, ptracer& t, scheduler& sched);

  const int syscallNumber = SYS_clock_gettime;
  const string syscallName = "clock_gettime";
};
// =======================================================================================
/**
 *
 * int close(int fd);
 *
 */
class closeSystemCall {
public:
  static bool handleDetPre(
      globalState& gs, state& s, ptracer& t, scheduler& sched);
  static void handleDetPost(
      globalState& gs, state& s, ptracer& t, scheduler& sched);

  const int syscallNumber = SYS_close;
  const string syscallName = "close";
};
// =======================================================================================
/**
 *
 * int connect(int sockfd, const struct sockaddr *addr, socklen_t
 * addrlen);
 *
 * The connect() system call connects the socket referred to by the file
 * descriptor sockfd to the address specified by addr. The addrlen argument
 * specifies the size of addr. The format of the address in addr is determined
 * by the address space of the socket sockfd.
 * TODO
 *
 */
class connectSystemCall {
public:
  static bool handleDetPre(
      globalState& gs, state& s, ptracer& t, scheduler& sched);
  static void handleDetPost(
      globalState& gs, state& s, ptracer& t, scheduler& sched);

  const int syscallNumber = SYS_connect;
  const string syscallName = "connect";
};
// =======================================================================================
/**
 *
 * int creat(const char *pathname, mode_t mode);
 *
 * A call to creat() is equivalent to calling open() with flags equal to
 * O_CREAT|O_WRONLY|O_TRUNC.
 */
class creatSystemCall {
public:
  static bool handleDetPre(
      globalState& gs, state& s, ptracer& t, scheduler& sched);
  static void handleDetPost(
      globalState& gs, state& s, ptracer& t, scheduler& sched);

  const int syscallNumber = SYS_creat;
  const string syscallName = "creat";
};
// =======================================================================================
class dupSystemCall {
public:
  static bool handleDetPre(
      globalState& gs, state& s, ptracer& t, scheduler& sched);
  static void handleDetPost(
      globalState& gs, state& s, ptracer& t, scheduler& sched);

  const int syscallNumber = SYS_dup;
  const string syscallName = "dup";
};

// =======================================================================================
class dup2SystemCall {
public:
  static bool handleDetPre(
      globalState& gs, state& s, ptracer& t, scheduler& sched);
  static void handleDetPost(
      globalState& gs, state& s, ptracer& t, scheduler& sched);

  const int syscallNumber = SYS_dup2;
  const string syscallName = "dup2";
};
// =======================================================================================
class exit_groupSystemCall {
public:
  static bool handleDetPre(
      globalState& gs, state& s, ptracer& t, scheduler& sched);
  static void handleDetPost(
      globalState& gs, state& s, ptracer& t, scheduler& sched);

  const int syscallNumber = SYS_exit_group;
  const string syscallName = "exit_group";
};
// =======================================================================================
class epoll_waitSystemCall {
public:
  static bool handleDetPre(
      globalState& gs, state& s, ptracer& t, scheduler& sched);
  static void handleDetPost(
      globalState& gs, state& s, ptracer& t, scheduler& sched);

  const int syscallNumber = SYS_epoll_wait;
  const string syscallName = "epoll_wait";
};
// =======================================================================================
class epoll_pwaitSystemCall {
public:
  static bool handleDetPre(
      globalState& gs, state& s, ptracer& t, scheduler& sched);
  static void handleDetPost(
      globalState& gs, state& s, ptracer& t, scheduler& sched);

  const int syscallNumber = SYS_epoll_pwait;
  const string syscallName = "epoll_pwait";
};
// =======================================================================================
/**
 * int faccessat(int dirfd, const char *pathname, int mode, int flags);
 *
 * Variant of access with f and at. See access.
 */
class faccessatSystemCall {
public:
  static bool handleDetPre(
      globalState& gs, state& s, ptracer& t, scheduler& sched);
  static void handleDetPost(
      globalState& gs, state& s, ptracer& t, scheduler& sched);

  const int syscallNumber = SYS_faccessat;
  const string syscallName = "faccessat";
};
// =======================================================================================

/**
 * ssize_t fgetxattr(int fd, const char *name, static void *value, size_t size);
 *
 * Get extended attribute for file for value.
 */
class fgetxattrSystemCall {
public:
  static bool handleDetPre(
      globalState& gs, state& s, ptracer& t, scheduler& sched);
  static void handleDetPost(
      globalState& gs, state& s, ptracer& t, scheduler& sched);

  const int syscallNumber = SYS_fgetxattr;
  const string syscallName = "fgetxattr";
};

// =======================================================================================
/**
 * ssize_t flistxattr(int fd, char *list, size_t size);
 *
 * List exted attributes for file descriptor.
 */
class flistxattrSystemCall {
public:
  static bool handleDetPre(
      globalState& gs, state& s, ptracer& t, scheduler& sched);
  static void handleDetPost(
      globalState& gs, state& s, ptracer& t, scheduler& sched);

  const int syscallNumber = SYS_flistxattr;
  const string syscallName = "flistxattr";
};
// =======================================================================================
/**
 * int fstat(int fd, struct stat *statbuf);
 *
 * These functions return information about a file, in the buffer pointed to by
 statbuf.
 * No permissions are required on the file itself, but—in the case of stat(),
 fstatat(),
 * and  lstat()—execute  (search)  permission  is  required on all of the
 directories in
 * pathname that lead to the file.

 * fstat() is identical to stat(), except that the file about which information
 is to be
 * retrieved is specified by the file descriptor fd.
 *
 * int fstat(int fd, struct stat *statbuf);
 *
 * TODO
 * FILESYSTEM RELATED.
 * Notice we do the exact same thing for lstat, stat, and fstat.
 */
class fstatSystemCall {
public:
  static bool handleDetPre(
      globalState& gs, state& s, ptracer& t, scheduler& sched);
  static void handleDetPost(
      globalState& gs, state& s, ptracer& t, scheduler& sched);

  const int syscallNumber = SYS_fstat;
  const string syscallName = "fstat";
};
// =======================================================================================
/**
 * int fchownat(int dirfd, const char *pathname, uid_t owner, gid_t group, int
 * flags);
 *
 * change owner of file with f and at variant. Deterministic thanks to light
 * weight container.
 *
 */
class fchownatSystemCall {
public:
  static bool handleDetPre(
      globalState& gs, state& s, ptracer& t, scheduler& sched);
  static void handleDetPost(
      globalState& gs, state& s, ptracer& t, scheduler& sched);

  const int syscallNumber = SYS_fchownat;
  const string syscallName = "fchownat";
};

// =======================================================================================
class fchownSystemCall {
public:
  static bool handleDetPre(
      globalState& gs, state& s, ptracer& t, scheduler& sched);
  static void handleDetPost(
      globalState& gs, state& s, ptracer& t, scheduler& sched);

  const int syscallNumber = SYS_fchown;
  const string syscallName = "fchown";
};
// =======================================================================================
class chownSystemCall {
public:
  static bool handleDetPre(
      globalState& gs, state& s, ptracer& t, scheduler& sched);
  static void handleDetPost(
      globalState& gs, state& s, ptracer& t, scheduler& sched);

  const int syscallNumber = SYS_chown;
  const string syscallName = "chown";
};
// =======================================================================================
class lchownSystemCall {
public:
  static bool handleDetPre(
      globalState& gs, state& s, ptracer& t, scheduler& sched);
  static void handleDetPost(
      globalState& gs, state& s, ptracer& t, scheduler& sched);

  const int syscallNumber = SYS_lchown;
  const string syscallName = "lchown";
};
// =======================================================================================
/**
 * fcntl - manipulate file descriptor
 *
 * int fcntl(int fd, int cmd, ... arg );

 * Needed to check if user changed status of file descriptor from blocking to
 non-blocking.
 */
class fcntlSystemCall {
public:
  static bool handleDetPre(
      globalState& gs, state& s, ptracer& t, scheduler& sched);
  static void handleDetPost(
      globalState& gs, state& s, ptracer& t, scheduler& sched);

  const int syscallNumber = SYS_fcntl;
  const string syscallName = "fcntl";
};
// =======================================================================================
/**
 * int fstatfs(int fd, struct statfs *buf);
 *
 * The statfs() system call returns information about a mounted filesystem. path
 * is the pathname of any file within the mounted filesystem.
 *
 * Very similar to statfs, except it takes a file descriptor instead of a file
 * path.
 */
class fstatfsSystemCall {
public:
  static bool handleDetPre(
      globalState& gs, state& s, ptracer& t, scheduler& sched);
  static void handleDetPost(
      globalState& gs, state& s, ptracer& t, scheduler& sched);

  const int syscallNumber = SYS_fstatfs;
  const string syscallName = "fstatfs";
};
// =======================================================================================
/**
 *    int futex(int *uaddr, int futex_op, int val, const struct timespec
 * *timeout, int *uaddr2, int val3);
 *
 * Fast mutex.
 * TODO: Understand what these guys even do.
 */
class futexSystemCall {
public:
  static bool handleDetPre(
      globalState& gs, state& s, ptracer& t, scheduler& sched);
  static void handleDetPost(
      globalState& gs, state& s, ptracer& t, scheduler& sched);

  const int syscallNumber = SYS_futex;
  const string syscallName = "futex";
};
// =======================================================================================
/**
 *
 * char* getcwd(char *buf, size_t size);
 *
 * Deterministic. We print the path for debugging purposes here.
 *
 */
class getcwdSystemCall {
public:
  static bool handleDetPre(
      globalState& gs, state& s, ptracer& t, scheduler& sched);
  static void handleDetPost(
      globalState& gs, state& s, ptracer& t, scheduler& sched);

  const int syscallNumber = SYS_getcwd;
  const string syscallName = "getcwd";
};
// =======================================================================================
/**
 *
 * int getdents(unsigned int fd, struct linux_dirent *dirp, unsigned int count);
 *
 * Reads several linux_dirent structures from the directory referred to by the
 * open file descriptor fd into the buffer pointed to by  dirp. Reads files in
 * directory.
 *
 * TODO: Contains linux_dirent struct with inode that we could virtualize.
 */
class getdentsSystemCall {
public:
  static bool handleDetPre(
      globalState& gs, state& s, ptracer& t, scheduler& sched);
  static void handleDetPost(
      globalState& gs, state& s, ptracer& t, scheduler& sched);

  const int syscallNumber = SYS_getdents;
  const string syscallName = "getdents";
};
// =======================================================================================

/**
 *
 * int getdents64(unsigned int fd, struct linux_dirent64 *dirp, unsigned int
 * count);
 *
 * Reads several linux_dirent structures from the directory referred to by the
 * open file descriptor fd into the buffer pointed to by  dirp. Reads files in
 * directory.
 *
 * TODO: Contains linux_dirent struct with inode that we could virtualize.
 */
class getdents64SystemCall {
public:
  static bool handleDetPre(
      globalState& gs, state& s, ptracer& t, scheduler& sched);
  static void handleDetPost(
      globalState& gs, state& s, ptracer& t, scheduler& sched);

  const int syscallNumber = SYS_getdents64;
  const string syscallName = "getdents64";
};
// =======================================================================================
/**
 *
 * int getpeername(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
 *
 * getpeername()  returns the address of the peer connected to the socket
 * sockfd, in the buffer pointed to by addr.
 *
 * We allow this system call to go through in the case where we it returns a
 * non-zero this happens on non-interactive bash mode. We might come back later
 * if needed.
 *
 */
class getpeernameSystemCall {
public:
  static bool handleDetPre(
      globalState& gs, state& s, ptracer& t, scheduler& sched);
  static void handleDetPost(
      globalState& gs, state& s, ptracer& t, scheduler& sched);

  const int syscallNumber = SYS_getpeername;
  const string syscallName = "getpeername";
};
// =======================================================================================
/**
 *
 * ssize_t getrandom(void *buf, size_t buflen, unsigned int flags);
 *
 *
 * Nondeterministic. We fill the buffer with n deterministic bytes for the user
 * :)
 *
 */
class getrandomSystemCall {
public:
  static bool handleDetPre(
      globalState& gs, state& s, ptracer& t, scheduler& sched);
  static void handleDetPost(
      globalState& gs, state& s, ptracer& t, scheduler& sched);

  const int syscallNumber = SYS_getrandom;
  const string syscallName = "getrandom";
};
// =======================================================================================
/**
 * int getrlimit(int resource, struct rlimit *rlim);
 *
 *        The getrlimit() and setrlimit() system calls get and set resource
 *        limits respectively.  Each resource has an associated soft and hard
 *        limit, as defined by the rlimit structure.
 *
 */
class getrlimitSystemCall {
public:
  static bool handleDetPre(
      globalState& gs, state& s, ptracer& t, scheduler& sched);
  static void handleDetPost(
      globalState& gs, state& s, ptracer& t, scheduler& sched);

  const int syscallNumber = SYS_getrlimit;
  const string syscallName = "getrlimit";
};
// =======================================================================================
/**
 *
 * int getrusage(int who, struct rusage *usage);
 *
 * returns resource usage measures for who.
 *
 */
class getrusageSystemCall {
public:
  static bool handleDetPre(
      globalState& gs, state& s, ptracer& t, scheduler& sched);
  static void handleDetPost(
      globalState& gs, state& s, ptracer& t, scheduler& sched);

  const int syscallNumber = SYS_getrusage;
  const string syscallName = "getrusage";
};
// =======================================================================================
/**
 *
 * pid_t getsid(pid_t pid);
 *
 * returns a session ID
 *
 */
class getsidSystemCall {
public:
  static bool handleDetPre(
      globalState& gs, state& s, ptracer& t, scheduler& sched);
  static void handleDetPost(
      globalState& gs, state& s, ptracer& t, scheduler& sched);

  const int syscallNumber = SYS_getsid;
  const string syscallName = "getsid";
};
// =======================================================================================
/**
 *
 * int gettimeofday(struct timeval *tv, struct timezone *tz);
 *
 * gives the number of seconds and microseconds since the Epoch
 *
 */
class gettimeofdaySystemCall {
public:
  static bool handleDetPre(
      globalState& gs, state& s, ptracer& t, scheduler& sched);
  static void handleDetPost(
      globalState& gs, state& s, ptracer& t, scheduler& sched);

  const int syscallNumber = SYS_gettimeofday;
  const string syscallName = "gettimeofday";
};
// =======================================================================================
/**
 *
 * int ioctl(int fd, unsigned long request, ...);
 *
 * The  ioctl()  function manipulates the underlying device parameters of
 * special files. Kitchen sink system call to talk to various devices or
 * pseudo-devices through /dev/
 *
 * Definitely not deterministic but I don't think there is much we can do about
 * it.
 *
 */
class ioctlSystemCall {
public:
  static bool handleDetPre(
      globalState& gs, state& s, ptracer& t, scheduler& sched);
  static void handleDetPost(
      globalState& gs, state& s, ptracer& t, scheduler& sched);

  const int syscallNumber = SYS_ioctl;
  const string syscallName = "ioctl";
};
// =======================================================================================
/*
 * ssize_t llistxattr(const char *path, char *list, size_t size);
 *
 * Extended attributes are name:value pairs associated with inodes (files,
 * directories, symbolic links, etc.). They are extensions to the normal
 * attributes which are associated with all inodes in the system.
 * TODO
 */
class llistxattrSystemCall {
public:
  static bool handleDetPre(
      globalState& gs, state& s, ptracer& t, scheduler& sched);
  static void handleDetPost(
      globalState& gs, state& s, ptracer& t, scheduler& sched);

  const int syscallNumber = SYS_llistxattr;
  const string syscallName = "llistxattr";
};
// =======================================================================================
/*
 * ssize_t lgetxattr(const char *path, const char *name, void *value, size_t
 * size);
 *
 * Extended attributes are name:value pairs associated with inodes (files,
 * directories, symbolic links, etc.). They are extensions to the normal
 * attributes which are associated with all inodes in the system.
 * TODO
 */
class lgetxattrSystemCall {
public:
  static bool handleDetPre(
      globalState& gs, state& s, ptracer& t, scheduler& sched);
  static void handleDetPost(
      globalState& gs, state& s, ptracer& t, scheduler& sched);

  const int syscallNumber = SYS_lgetxattr;
  const string syscallName = "lgetxattr";
};

// =======================================================================================
/*
 * void* mmap(void* addr, size_t length, int prot, int flags, int fd, off_t
 * offset);
 *
 * TODO: This is currently implemented to handle injected calls only
 */
class mmapSystemCall {
public:
  static bool handleDetPre(
      globalState& gs, state& s, ptracer& t, scheduler& sched);
  static void handleDetPost(
      globalState& gs, state& s, ptracer& t, scheduler& sched);

  const int syscallNumber = SYS_mmap;
  const string syscallName = "mmap";
};

// =======================================================================================
/**
 * int fstatat(int dirfd, const char *pathname, struct stat *statbuf, int
 * flags);
 *
 * The fstatat() system call operates in exactly the same way as stat(), except
 * for if the pathname given in pathname is relative, then it is interpreted
 * relative to the directory referred to by the file descriptor dirfd (rather
 * than relative to the  cur‐ rent  working  directory  of the calling process,
 * as is done by stat() for a relative pathname).
 *
 * Actual name of underlying system call is newfstatat.
 */
class newfstatatSystemCall {
public:
  static bool handleDetPre(
      globalState& gs, state& s, ptracer& t, scheduler& sched);
  static void handleDetPost(
      globalState& gs, state& s, ptracer& t, scheduler& sched);

  const int syscallNumber = SYS_newfstatat;
  const string syscallName = "newfstatat";
};
// =======================================================================================
/**
 * int nanosleep(const struct timespec *req, struct timespec *rem);
 *
 * nanosleep()  suspends  the  execution of the calling thread until either at
 least the
 * time specified in *req has elapsed. rem is populated with the time left if
 this system
 * call was interrupted by a signal.

 * Surprisingly, I think this sytem was is deterministic for our purposes if we
 have a
 * handle on signals.
 */
class nanosleepSystemCall {
public:
  static bool handleDetPre(
      globalState& gs, state& s, ptracer& t, scheduler& sched);
  static void handleDetPost(
      globalState& gs, state& s, ptracer& t, scheduler& sched);

  const int syscallNumber = SYS_nanosleep;
  const string syscallName = "nanosleep";
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
class mkdirSystemCall {
public:
  static bool handleDetPre(
      globalState& gs, state& s, ptracer& t, scheduler& sched);
  static void handleDetPost(
      globalState& gs, state& s, ptracer& t, scheduler& sched);

  const int syscallNumber = SYS_mkdir;
  const string syscallName = "mkdir";
};
// =======================================================================================
/**
 * int mkdirat(int dirfd, const char *pathname, mode_t mode);
 *
 * "" variat of mkdir. Same things apply.
 */
class mkdiratSystemCall {
public:
  static bool handleDetPre(
      globalState& gs, state& s, ptracer& t, scheduler& sched);
  static void handleDetPost(
      globalState& gs, state& s, ptracer& t, scheduler& sched);

  const int syscallNumber = SYS_mkdirat;
  const string syscallName = "mkdirat";
};
// =======================================================================================
/**
 * int lstat(const char *pathname, struct stat *statbuf);
 *
 * lstat()  is  identical to stat(), except that if pathname is a symbolic link,
 * then it returns information about the link itself, not the file that it
 * refers to.
 *
 * FILESYSTEM RELATED.
 * Notice we do the exact same thing for lstat, stat, and fstat.
 */
class lstatSystemCall {
public:
  static bool handleDetPre(
      globalState& gs, state& s, ptracer& t, scheduler& sched);
  static void handleDetPost(
      globalState& gs, state& s, ptracer& t, scheduler& sched);

  const int syscallNumber = SYS_lstat;
  const string syscallName = "lstat";
};
// =======================================================================================
/**
 * int link(const char *oldpath, const char *newpath);
 *
 * Creates hardlink.
 */
class linkSystemCall {
public:
  static bool handleDetPre(
      globalState& gs, state& s, ptracer& t, scheduler& sched);
  static void handleDetPost(
      globalState& gs, state& s, ptracer& t, scheduler& sched);

  const int syscallNumber = SYS_link;
  const string syscallName = "link";
};
// =======================================================================================
/**
 * int linkat(int olddirfd, const char *oldpath,
 *            int newdirfd, const char *newpath, int flags);
 *
 * Creates hardlink.
 */
class linkatSystemCall {
public:
  static bool handleDetPre(
      globalState& gs, state& s, ptracer& t, scheduler& sched);
  static void handleDetPost(
      globalState& gs, state& s, ptracer& t, scheduler& sched);

  const int syscallNumber = SYS_linkat;
  const string syscallName = "linkat";
};
// =======================================================================================
/**
 * int open(const char *pathname, int flags);
 *
 * Given  a  pathname for a file, open() returns a file descriptor, a small,
 * nonnegative integer for use in subsequent system calls (read(2),  write(2),
 * lseek(2),  fcntl(2), etc.).  The file descriptor returned by a successful
 * call will be the lowest-numbered file descriptor not currently open for the
 * process.
 *
 */
class openSystemCall {
public:
  static bool handleDetPre(
      globalState& gs, state& s, ptracer& t, scheduler& sched);
  static void handleDetPost(
      globalState& gs, state& s, ptracer& t, scheduler& sched);

  const int syscallNumber = SYS_open;
  const string syscallName = "open";
};
// =======================================================================================
/**
 * int openat(int dirfd, const char *pathname, int flags);
 * int openat(int dirfd, const char *pathname, int flags, mode_t mode);
 *
 * The openat() system call operates in exactly the same way as open(), except
 * for  the differences described here.
 *
 * If the pathname given in pathname is relative, then it is interpreted
 * relative to the directory referred to by the file descriptor dirfd (rather
 * than  rela‐ tive  to  the  current working directory of the calling process,
 * as is done by open() for a relative pathname).
 *
 * If pathname is relative and dirfd is the special value AT_FDCWD, then
 * pathname is  interpreted  relative  to  the  current  working  directory of
 * the calling process (like open()).
 *
 * If pathname is absolute, then dirfd is ignored.
 */
class openatSystemCall {
public:
  static bool handleDetPre(
      globalState& gs, state& s, ptracer& t, scheduler& sched);
  static void handleDetPost(
      globalState& gs, state& s, ptracer& t, scheduler& sched);

  const int syscallNumber = SYS_openat;
  const string syscallName = "openat";
};
// =======================================================================================
/**
 * int pause(void);
 *
 * pause() causes the calling process (or thread) to sleep until a signal is
 * delivered that either terminates the process or causes the invocation of a
 * signal-catching function.
 */
class pauseSystemCall {
public:
  static bool handleDetPre(
      globalState& gs, state& s, ptracer& t, scheduler& sched);
  static void handleDetPost(
      globalState& gs, state& s, ptracer& t, scheduler& sched);

  const int syscallNumber = SYS_pause;
  const string syscallName = "pause";
};
// =======================================================================================
/**
 * int pipe(int pipefd[2]);
 *
 * Create a pipe communication channel.
 */
class pipeSystemCall {
public:
  static bool handleDetPre(
      globalState& gs, state& s, ptracer& t, scheduler& sched);
  static void handleDetPost(
      globalState& gs, state& s, ptracer& t, scheduler& sched);

  const int syscallNumber = SYS_pipe;
  const string syscallName = "pipe";
};
// =======================================================================================
/**
 * int pipe2(int pipefd[2], int flags);
 */
class pipe2SystemCall {
public:
  static bool handleDetPre(
      globalState& gs, state& s, ptracer& t, scheduler& sched);
  static void handleDetPost(
      globalState& gs, state& s, ptracer& t, scheduler& sched);

  const int syscallNumber = SYS_pipe2;
  const string syscallName = "pipe2";
};
// =======================================================================================
/**
 * int arch_prctl(int code, unsigned long addr);
 * arch-specific thread state - currently we use this for establishing a SIGSEGV
 * on CPUID
 */
class arch_prctlSystemCall {
public:
  static bool handleDetPre(
      globalState& gs, state& s, ptracer& t, scheduler& sched);
  static void handleDetPost(
      globalState& gs, state& s, ptracer& t, scheduler& sched);

  const int syscallNumber = SYS_arch_prctl;
  const string syscallName = "arch_prctl";
};

// =======================================================================================
/**
 * The  Linux  pselect6() system call modifies its timeout argument.  However,
 the glibc
 * wrapper function hides this behavior by using a local variable for the
 timeout  argu‐
 * ment  that is passed to the system call.  Thus, the glibc pselect() function
 does not
 * modify its timeout argument; this is the behavior required by POSIX.1-2001.
 *
 * The final argument of the pselect6() system call is not a sigset_t * pointer,
 but  is
 * instead a structure of the form:

 * struct {
 *   const kernel_sigset_t *ss;   Pointer to signal set
 *   size_t ss_len;               Size (in bytes) of object pointed to by 'ss'
 * };

 * This  allows the system call to obtain both a pointer to the signal set and
 its size,
 * while allowing for the fact that most architectures support a maximum of 6
 arguments
 * to  a system call.  See sigprocmask(2) for a discussion of the difference
 between the
 * kernel and libc notion of the signal set.
 *
 * Create a pipe communication channel.
 * TODO
 */
class pselect6SystemCall {
public:
  static bool handleDetPre(
      globalState& gs, state& s, ptracer& t, scheduler& sched);
  static void handleDetPost(
      globalState& gs, state& s, ptracer& t, scheduler& sched);

  const int syscallNumber = SYS_pselect6;
  const string syscallName = "pselect6";
};
// =======================================================================================
/**
 * int poll(struct pollfd *fds, nfds_t nfds, int timeout);*
 *
 * Wait for one of a set of fds to become ready to perform I/O
 *
 * We use a general approach for all blocking IO system calls:
 * Turn it into a non blocking IO. Check if "it would have" blocked. If so, we
 * preempt the current running process and let another process run in it's
 * place. Later we come back to this process.
 *
 */
class pollSystemCall {
public:
  static bool handleDetPre(
      globalState& gs, state& s, ptracer& t, scheduler& sched);
  static void handleDetPost(
      globalState& gs, state& s, ptracer& t, scheduler& sched);

  const int syscallNumber = SYS_poll;
  const string syscallName = "poll";
};
// =======================================================================================
/**
 * int prlimit64(pid_t pid, int resource, const struct rlimit *new_limit,
                   struct rlimit *old_limit);
 *
 * get/set different types of process resource limits to new values. These
 resources
 * include, nice values, max memory size, core file size, etc.

 *
 * Definitely nondeterminism if used for get but realistically we need this. It
 also
 * probably won't cause too much issues.
 * The pid has to be converted from a vpid -> pid, except for the 0 case which
 means
 * *this* process. So we merely check if non zero and fail. (TODO: This may
 change later
 * if this becomes an issue).
 *
 */
class prlimit64SystemCall {
public:
  static bool handleDetPre(
      globalState& gs, state& s, ptracer& t, scheduler& sched);
  static void handleDetPost(
      globalState& gs, state& s, ptracer& t, scheduler& sched);

  const int syscallNumber = SYS_prlimit64;
  const string syscallName = "prlimit64";
};
// =======================================================================================
/**
 * ssize_t read(int fd, void *buf, size_t count);
 *
 * TODO
 * FILESYSTEM RELATED.
 */
class readSystemCall {
public:
  static bool handleDetPre(
      globalState& gs, state& s, ptracer& t, scheduler& sched);
  static void handleDetPost(
      globalState& gs, state& s, ptracer& t, scheduler& sched);

  const int syscallNumber = SYS_read;
  const string syscallName = "read";
};
// =======================================================================================
/**
 * ssize_t readv(int fd, const struct iovec *iov, int iovcnt);
 *
 * read or write data into multiple buffers
 * Would be non determinitic based on number of bytes read is less than number
 * of bytes asked for.
 *
 * TODO
 */
class readvSystemCall {
public:
  static bool handleDetPre(
      globalState& gs, state& s, ptracer& t, scheduler& sched);
  static void handleDetPost(
      globalState& gs, state& s, ptracer& t, scheduler& sched);

  const int syscallNumber = SYS_readv;
  const string syscallName = "readv";
};
// =======================================================================================
/**
 * ssize_t readlink(const char *pathname, char *buf, size_t bufsiz);
 *
 * readlink, readlinkat - read value of a symbolic link
 * Deterministic thanks to our jail. Intercepted merely for debugging purposes.
 *
 */
class readlinkSystemCall {
public:
  static bool handleDetPre(
      globalState& gs, state& s, ptracer& t, scheduler& sched);
  static void handleDetPost(
      globalState& gs, state& s, ptracer& t, scheduler& sched);

  const int syscallNumber = SYS_readlink;
  const string syscallName = "readlink";
};
// =======================================================================================
/**
 * ssize_t readlinkat(int dirfd, const char *pathname, char *buf, size_t
 * bufsiz);
 *
 * readlinkat - read value of a symbolic link
 * Deterministic thanks to our jail. Intercepted merely for debugging purposes.
 *
 */
class readlinkatSystemCall {
public:
  static bool handleDetPre(
      globalState& gs, state& s, ptracer& t, scheduler& sched);
  static void handleDetPost(
      globalState& gs, state& s, ptracer& t, scheduler& sched);

  const int syscallNumber = SYS_readlinkat;
  const string syscallName = "readlinkat";
};
// =======================================================================================
/**
 * ssize_t recvmsg(int sockfd, struct msghdr *msg, int flags);
 *
 * recvmsg() call is used to receive messages from a socket and amy be used to
 * receive data on a socket whether or not it is connection-oriented.
 */
class recvmsgSystemCall {
public:
  static bool handleDetPre(
      globalState& gs, state& s, ptracer& t, scheduler& sched);
  static void handleDetPost(
      globalState& gs, state& s, ptracer& t, scheduler& sched);

  const int syscallNumber = SYS_recvmsg;
  const string syscallName = "recvmsg";
};
// =======================================================================================
/**
 * int rename(const char *oldpath, const char *newpath);
 *
 * Must be intercepted as this changes the inode for newpath if newpath exists.
 */
class renameSystemCall {
public:
  static bool handleDetPre(
      globalState& gs, state& s, ptracer& t, scheduler& sched);
  static void handleDetPost(
      globalState& gs, state& s, ptracer& t, scheduler& sched);

  const int syscallNumber = SYS_rename;
  const string syscallName = "rename";
};
// =======================================================================================
/**
 *  int renameat(int olddirfd, const char *oldpath, int newdirfd, const char
 * *newpath);
 */
class renameatSystemCall {
public:
  static bool handleDetPre(
      globalState& gs, state& s, ptracer& t, scheduler& sched);
  static void handleDetPost(
      globalState& gs, state& s, ptracer& t, scheduler& sched);

  const int syscallNumber = SYS_renameat;
  const string syscallName = "renameat";
};
// =======================================================================================
/**
 *  int renameat2(int olddirfd, const char *oldpath, int newdirfd,
 *                 const char *newpath, unsigned int flags);
 */
class renameat2SystemCall {
public:
  static bool handleDetPre(
      globalState& gs, state& s, ptracer& t, scheduler& sched);
  static void handleDetPost(
      globalState& gs, state& s, ptracer& t, scheduler& sched);

  const int syscallNumber = SYS_renameat2;
  const string syscallName = "renameat2";
};
// =======================================================================================
/**
 * int rmdir(const char *pathname);
 */
class rmdirSystemCall {
public:
  static bool handleDetPre(
      globalState& gs, state& s, ptracer& t, scheduler& sched);
  static void handleDetPost(
      globalState& gs, state& s, ptracer& t, scheduler& sched);

  const int syscallNumber = SYS_rmdir;
  const string syscallName = "rmdir";
};
// =======================================================================================
/**
 *  ssize_t sendto(int sockfd, const void *buf, size_t len, int flags,
 *                 const struct sockaddr *dest_addr, socklen_t addrlen);
 *
 * If sendto() is used on a connection-mode (SOCK_STREAM, SOCK_SEQPACKET)
 * socket, the arguments dest_addr and addrlen are ignored (and the error
 * EISCONN may be returned when they are not NULL and 0), and the error ENOTCONN
 * is returned when the socket was not actually connected. Otherwise, the
 * address of the target is given by dest_addr with addrlen specifying its size.
 * For sendmsg(), the address of the target is given by msg.msg_name, with
 * msg.msg_namelen specifying its size.
 *
 */
class sendtoSystemCall {
public:
  static bool handleDetPre(
      globalState& gs, state& s, ptracer& t, scheduler& sched);
  static void handleDetPost(
      globalState& gs, state& s, ptracer& t, scheduler& sched);

  const int syscallNumber = SYS_sendto;
  const string syscallName = "sendto";
};
// =======================================================================================
/**
 *  ssize_t sendmsg(int sockfd, const struct msghdr* msg, int flags);
 *
 * If sendmsg() is used on a connection-mode (SOCK_STREAM, SOCK_SEQPACKET)
 * socket, the arguments dest_addr and addrlen are ignored (and the error
 * EISCONN may be returned when they are not NULL and 0), and the error ENOTCONN
 * is returned when the socket was not actually connected. Otherwise, the
 * address of the target is given by dest_addr with addrlen specifying its size.
 * For sendmsg(), the address of the target is given by msg.msg_name, with
 * msg.msg_namelen specifying its size.
 *
 */
class sendmsgSystemCall {
public:
  static bool handleDetPre(
      globalState& gs, state& s, ptracer& t, scheduler& sched);
  static void handleDetPost(
      globalState& gs, state& s, ptracer& t, scheduler& sched);

  const int syscallNumber = SYS_sendmsg;
  const string syscallName = "sendmsg";
};

// =======================================================================================
/**
 *  int sendmsg(int sockfd, struct mmsghdr* msgvec, unsigned int vlen,
                int flags);
 *
 * The  sendmmsg()  system  call  is an extension of sendmsg(2) that allows
 * the caller to transmit multiple messages on a socket using a single system
 * call.  (This has performance benefits for some applications.)
 */
class sendmmsgSystemCall {
public:
  static bool handleDetPre(
      globalState& gs, state& s, ptracer& t, scheduler& sched);
  static void handleDetPost(
      globalState& gs, state& s, ptracer& t, scheduler& sched);

  const int syscallNumber = SYS_sendmmsg;
  const string syscallName = "sendmmsg";
};

// =======================================================================================
/**
 *  ssize_t recvfrom(int sockfd, void* buf, size_t len, int flags,
                     struct sockaddr* src_addr, socklen_t* addrlen);
 *
 * The  recv(),  recvfrom(),  and recvmsg() calls are used to receive messages
 * from a socket. They may be used to receive data on both connectionless and
 * connection-oriented sockets.  This page first describes common features of
 * all three system calls, and then describes the  differences between the
 calls.
 */
class recvfromSystemCall {
public:
  static bool handleDetPre(
      globalState& gs, state& s, ptracer& t, scheduler& sched);
  static void handleDetPost(
      globalState& gs, state& s, ptracer& t, scheduler& sched);

  const int syscallNumber = SYS_recvfrom;
  const string syscallName = "recvfrom";
};

// =======================================================================================
/**
 * int select(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds,
 *            struct timeval *timeout);
 *
 * select()  and pselect() allow a program to monitor multiple file descriptors,
 * waiting until one or more of the file descriptors become "ready" for some
 * class of I/O opera‐ tion (e.g., input possible).
 *
 * TODO! Super non deterministic, the most non-deterministic of them all!
 */
class selectSystemCall {
public:
  static bool handleDetPre(
      globalState& gs, state& s, ptracer& t, scheduler& sched);
  static void handleDetPost(
      globalState& gs, state& s, ptracer& t, scheduler& sched);

  const int syscallNumber = SYS_select;
  const string syscallName = "select";
};
// =======================================================================================
/**
 */
class set_robust_listSystemCall {
public:
  static bool handleDetPre(
      globalState& gs, state& s, ptracer& t, scheduler& sched);
  static void handleDetPost(
      globalState& gs, state& s, ptracer& t, scheduler& sched);

  const int syscallNumber = SYS_set_robust_list;
  const string syscallName = "set_robust_list";
};
// =======================================================================================
/**
 * int rt_sigprocmask(int how, const sigset_t* set, const sigset_t* oldset,
 * size_t sigsetsize);
 *
 * change signal mask for calling thread.
 */
class rt_sigprocmaskSystemCall {
public:
  static bool handleDetPre(
      globalState& gs, state& s, ptracer& t, scheduler& sched);
  static void handleDetPost(
      globalState& gs, state& s, ptracer& t, scheduler& sched);

  const int syscallNumber = SYS_rt_sigprocmask;
  const string syscallName = "rt_sigprocmask";
};
// =======================================================================================
/**
 * int sigaction(int signum, const struct sigaction *act, struct sigaction
 * *oldact);
 *
 * Setup a signal handler. Currently only used for determinizing alarm()
 */
class rt_sigactionSystemCall {
public:
  static bool handleDetPre(
      globalState& gs, state& s, ptracer& t, scheduler& sched);
  static void handleDetPost(
      globalState& gs, state& s, ptracer& t, scheduler& sched);

  const int syscallNumber = SYS_rt_sigaction;
  const string syscallName = "rt_sigaction";
};
// =======================================================================================
/**
 * int sigaction(int signum, const struct sigaction *act, struct sigaction
 * *oldact);
 *
 * Setup a signal handler. Currently only used for determinizing alarm()
 */
class rt_sigtimedwaitSystemCall {
public:
  static bool handleDetPre(
      globalState& gs, state& s, ptracer& t, scheduler& sched);
  static void handleDetPost(
      globalState& gs, state& s, ptracer& t, scheduler& sched);

  const int syscallNumber = SYS_rt_sigtimedwait;
  const string syscallName = "rt_sigtimedwait";
};

// =======================================================================================
/**
 * int sigaction(int signum, const struct sigaction *act, struct sigaction
 * *oldact);
 *
 * Setup a signal handler. Currently only used for determinizing alarm()
 */
class rt_sigsuspendSystemCall {
public:
  static bool handleDetPre(
      globalState& gs, state& s, ptracer& t, scheduler& sched);
  static void handleDetPost(
      globalState& gs, state& s, ptracer& t, scheduler& sched);

  const int syscallNumber = SYS_rt_sigsuspend;
  const string syscallName = "rt_sigsuspend";
};
// =======================================================================================
/**
 * int sigaction(int signum, const struct sigaction *act, struct sigaction
 * *oldact);
 *
 * Setup a signal handler. Currently only used for determinizing alarm()
 */
class rt_sigpendingSystemCall {
public:
  static bool handleDetPre(
      globalState& gs, state& s, ptracer& t, scheduler& sched);
  static void handleDetPost(
      globalState& gs, state& s, ptracer& t, scheduler& sched);

  const int syscallNumber = SYS_rt_sigpending;
  const string syscallName = "rt_sigpending";
};
// =======================================================================================
/**
 * int stat(const char *pathname, struct stat *statbuf);
 *
 * stat() and retrieve information about the file pointed to by pathname.
 *
 * FILESYSTEM RELATED.
 * TODO: Figure out semantics of all fields in struct stat* statbuf.
 * Notice we do the exact same thing for lstat, stat, and fstat.
 */
class statSystemCall {
public:
  static bool handleDetPre(
      globalState& gs, state& s, ptracer& t, scheduler& sched);
  static void handleDetPost(
      globalState& gs, state& s, ptracer& t, scheduler& sched);

  const int syscallNumber = SYS_stat;
  const string syscallName = "stat";
};
// =======================================================================================
/**
 * int statfs(const char *path, struct statfs *buf);
 * Implement various fields.
 * FILESYSTEM RELATED.
 */
class statfsSystemCall {
public:
  static bool handleDetPre(
      globalState& gs, state& s, ptracer& t, scheduler& sched);
  static void handleDetPost(
      globalState& gs, state& s, ptracer& t, scheduler& sched);

  const int syscallNumber = SYS_statfs;
  const string syscallName = "statfs";
};
// =======================================================================================
/**
 * int symlink(const char *target, const char *linkpath);
 *
 * symlink() creates a symbolic link named linkpath which contains the string
 * target.
 *
 * Although this function is deterministic, we track it to keep track of files
 * created.
 */
class symlinkSystemCall {
public:
  static bool handleDetPre(
      globalState& gs, state& s, ptracer& t, scheduler& sched);
  static void handleDetPost(
      globalState& gs, state& s, ptracer& t, scheduler& sched);

  const int syscallNumber = SYS_symlink;
  const string syscallName = "symlink";
};
// =======================================================================================
/**
 * int symlinkat(const char *target, int newdirfd, const char *linkpath);
 * Although this function is deterministic, we track it to keep track of files
 * created.
 */
class symlinkatSystemCall {
public:
  static bool handleDetPre(
      globalState& gs, state& s, ptracer& t, scheduler& sched);
  static void handleDetPost(
      globalState& gs, state& s, ptracer& t, scheduler& sched);

  const int syscallNumber = SYS_symlinkat;
  const string syscallName = "symlinkat";
};
// =======================================================================================
/**
 * int mknod(const char *pathname, mode_t mode, dev_t dev);
 * Create a new special file.
 * Although this function is deterministic, we track it to keep track of files
 * created.
 */
class mknodSystemCall {
public:
  static bool handleDetPre(
      globalState& gs, state& s, ptracer& t, scheduler& sched);
  static void handleDetPost(
      globalState& gs, state& s, ptracer& t, scheduler& sched);

  const int syscallNumber = SYS_mknod;
  const string syscallName = "mknod";
};
// =======================================================================================
/**
 * int mknodat(int dirfd, const char *pathname, mode_t mode, dev_t dev);
 * Create a new special file.
 * Although this function is deterministic, we track it to keep track of files
 * created.
 */
class mknodatSystemCall {
public:
  static bool handleDetPre(
      globalState& gs, state& s, ptracer& t, scheduler& sched);
  static void handleDetPost(
      globalState& gs, state& s, ptracer& t, scheduler& sched);

  const int syscallNumber = SYS_mknodat;
  const string syscallName = "mknodat";
};
// =======================================================================================
/**
 * int sysinfo(struct sysinfo *info);
 *
 * sysinfo()  returns  certain  statistics on memory and swap usage, as well as
 * the load average.
 *
 */
class sysinfoSystemCall {
public:
  static bool handleDetPre(
      globalState& gs, state& s, ptracer& t, scheduler& sched);
  static void handleDetPost(
      globalState& gs, state& s, ptracer& t, scheduler& sched);

  const int syscallNumber = SYS_sysinfo;
  const string syscallName = "sysinfo";
};
// =======================================================================================
/**
 * int tgkill(int tgid, int tid, int sig);
 *
 * SIGNAL RELATED
 *
 * Should be deterministic in the sense that our pid namespace separates us from
 * other processes. So only processes in our tree can use it. However, if a
 * process delivers a signal to another process, how can we make that
 * determinitic? Maybe we don't care about those programs? If a signal was to be
 * delivered from P1 -> P2, P2 has no guarantee of when the signal will arrive,
 * unless they do a wait*(), so maybe only deliver the signal if P2 is waiting?
 * Otherwise never deliver it since the signal may take arbitrarily long to be
 * delivered.
 * TODO
 */
class tgkillSystemCall {
public:
  static bool handleDetPre(
      globalState& gs, state& s, ptracer& t, scheduler& sched);
  static void handleDetPost(
      globalState& gs, state& s, ptracer& t, scheduler& sched);

  const int syscallNumber = SYS_tgkill;
  const string syscallName = "tgkill";
};
// =======================================================================================
/**
 * time_t time(time_t *tloc);
 *
 * TODO: Document and verify implementation.
 * TODO: Add logical clock for rt_sigprocmask.
 * Return results from our logical clock.
 */
class timeSystemCall {
public:
  static bool handleDetPre(
      globalState& gs, state& s, ptracer& t, scheduler& sched);
  static void handleDetPost(
      globalState& gs, state& s, ptracer& t, scheduler& sched);

  const int syscallNumber = SYS_time;
  const string syscallName = "time";
};
// =======================================================================================
/**
 * int timer_create(clockid_t clockid, struct sigevent *sevp, timer_t *timerid);
 */
class timer_createSystemCall {
public:
  static bool handleDetPre(
      globalState& gs, state& s, ptracer& t, scheduler& sched);
  static void handleDetPost(
      globalState& gs, state& s, ptracer& t, scheduler& sched);

  const int syscallNumber = SYS_timer_create;
  const string syscallName = "timer_create";
};
// =======================================================================================
/**
 * int timer_delete(timer_t timerid);
 */
class timer_deleteSystemCall {
public:
  static bool handleDetPre(
      globalState& gs, state& s, ptracer& t, scheduler& sched);
  static void handleDetPost(
      globalState& gs, state& s, ptracer& t, scheduler& sched);

  const int syscallNumber = SYS_timer_delete;
  const string syscallName = "timer_delete";
};
// =======================================================================================
/**
 * int timer_getoverrun(timer_t timerid);
 */
class timer_getoverrunSystemCall {
public:
  static bool handleDetPre(
      globalState& gs, state& s, ptracer& t, scheduler& sched);
  static void handleDetPost(
      globalState& gs, state& s, ptracer& t, scheduler& sched);

  const int syscallNumber = SYS_timer_getoverrun;
  const string syscallName = "timer_getoverrun";
};
// =======================================================================================
/**
 * int timer_gettime(timer_t timerid, struct itimerspec *curr_value);
 */
class timer_gettimeSystemCall {
public:
  static bool handleDetPre(
      globalState& gs, state& s, ptracer& t, scheduler& sched);
  static void handleDetPost(
      globalState& gs, state& s, ptracer& t, scheduler& sched);

  const int syscallNumber = SYS_timer_gettime;
  const string syscallName = "timer_gettime";
};
// =======================================================================================
/**
 * int timer_settime(timer_t timerid, int flags, const struct itimerspec
 * *new_value, struct itimerspec *old_value);
 */
class timer_settimeSystemCall {
public:
  static bool handleDetPre(
      globalState& gs, state& s, ptracer& t, scheduler& sched);
  static void handleDetPost(
      globalState& gs, state& s, ptracer& t, scheduler& sched);

  const int syscallNumber = SYS_timer_settime;
  const string syscallName = "timer_settime";
};
// =======================================================================================
/**
 * int getitimer(int which, struct itimerval *curr_value);
 */
class getitimerSystemCall {
public:
  static bool handleDetPre(
      globalState& gs, state& s, ptracer& t, scheduler& sched);
  static void handleDetPost(
      globalState& gs, state& s, ptracer& t, scheduler& sched);

  const int syscallNumber = SYS_getitimer;
  const string syscallName = "getitimer";
};
// =======================================================================================
/**
 * int setitimer(int which, const struct itimerval *new_value, struct itimerval
 * *old_value);
 */
class setitimerSystemCall {
public:
  static bool handleDetPre(
      globalState& gs, state& s, ptracer& t, scheduler& sched);
  static void handleDetPost(
      globalState& gs, state& s, ptracer& t, scheduler& sched);

  const int syscallNumber = SYS_setitimer;
  const string syscallName = "setitimer";
};

// =======================================================================================
/**
 * int timerfd_create(clockid_t clockid, int flags);
 */
class timerfd_createSystemCall {
public:
  static bool handleDetPre(
      globalState& gs, state& s, ptracer& t, scheduler& sched);
  static void handleDetPost(
      globalState& gs, state& s, ptracer& t, scheduler& sched);

  const int syscallNumber = SYS_timerfd_create;
  const string syscallName = "timerfd_create";
};

// =======================================================================================
/**
 * int timerfd_settime(clockid_t clockid, int flags,
                       const struct itimerspec* new_value,
                       struct itimerspec* old_value);
 */
class timerfd_settimeSystemCall {
public:
  static bool handleDetPre(
      globalState& gs, state& s, ptracer& t, scheduler& sched);
  static void handleDetPost(
      globalState& gs, state& s, ptracer& t, scheduler& sched);

  const int syscallNumber = SYS_timerfd_settime;
  const string syscallName = "timerfd_settime";
};

// =======================================================================================
/**
 * int timerfd_gettime(clockid_t clockid, struct itimerspec* curr_value);
 */
class timerfd_gettimeSystemCall {
public:
  static bool handleDetPre(
      globalState& gs, state& s, ptracer& t, scheduler& sched);
  static void handleDetPost(
      globalState& gs, state& s, ptracer& t, scheduler& sched);

  const int syscallNumber = SYS_timerfd_gettime;
  const string syscallName = "timerfd_gettime";
};

// =======================================================================================
/**
 * clock_t times(struct tms *buf);
 *
 * times()  stores the current process times in the struct tms that buf points
 * to.  The struct tms is as defined in <sys/times.h>:
 *
 *        struct tms {
 *             clock_t tms_utime;  // user time
 *             clock_t tms_stime;  // system time
 *             clock_t tms_cutime; // user time of children
 *             clock_t tms_cstime; // system time of children
 *         };
 *
 */
class timesSystemCall {
public:
  static bool handleDetPre(
      globalState& gs, state& s, ptracer& t, scheduler& sched);
  static void handleDetPost(
      globalState& gs, state& s, ptracer& t, scheduler& sched);

  const int syscallNumber = SYS_times;
  const string syscallName = "times";
};
// =======================================================================================
/**
 * int uname(struct utsname *buf);
 *
 * uname()  returns  system information in the structure pointed to by buf.
 * Definitely non deterministic.
 *
 *
 */
class unameSystemCall {
public:
  static bool handleDetPre(
      globalState& gs, state& s, ptracer& t, scheduler& sched);
  static void handleDetPost(
      globalState& gs, state& s, ptracer& t, scheduler& sched);

  const int syscallNumber = SYS_uname;
  const string syscallName = "uname";
};
// =======================================================================================
/**
 * int unlink(const char *pathname);
 *
 * unlink()  deletes  a  name  from the filesystem.  If that name was the last
 * link to a file and no processes have the file open, the file is deleted and
 * the  space  it  was using is made available for reuse.
 *
 * Similarly to other system calls, under deterministic threads and processes,
 * this should be deterministic. We keep it here to print it's path.
 */
class unlinkSystemCall {
public:
  static bool handleDetPre(
      globalState& gs, state& s, ptracer& t, scheduler& sched);
  static void handleDetPost(
      globalState& gs, state& s, ptracer& t, scheduler& sched);

  const int syscallNumber = SYS_unlink;
  const string syscallName = "unlink";
};
// =======================================================================================
/**
 * int unlinkat(int dirfd, const char *pathname, int flags);
 *
 * The unlinkat() system call operates in exactly the same way  as  either
 * unlink()  or rmdir(2)  (depending  on  whether or not flags includes the
 * AT_REMOVEDIR flag) except for the differences described here.
 *
 * If the pathname given in pathname is relative, then it is interpreted
 * relative to the directory  referred to by the file descriptor dirfd (rather
 * than relative to the cur‐ rent working directory of the calling process, as
 * is done by  unlink()  and  rmdir(2) for a relative pathname).
 *
 * If  the  pathname  given  in  pathname  is  relative  and  dirfd is the
 * special value AT_FDCWD, then pathname is interpreted relative to the current
 * working  directory  of the calling process (like unlink() and rmdir(2)).
 *
 * If the pathname given in pathname is absolute, then dirfd is ignored.
 *
 * Seems deterministic enough :)
 */
class unlinkatSystemCall {
public:
  static bool handleDetPre(
      globalState& gs, state& s, ptracer& t, scheduler& sched);
  static void handleDetPost(
      globalState& gs, state& s, ptracer& t, scheduler& sched);

  const int syscallNumber = SYS_unlinkat;
  const string syscallName = "unlinkat";
};
// =======================================================================================
/**
 * int utime(const char *filename, const struct utimbuf *times);
 *
 * The utime() system call changes the access and modification times of the
 * inode speci‐ fied by filename to the actime and modtime fields of times
 * respectively.
 *
 * The time the user uses should be determinitic. We only have to watch out for
 * the zero case when the user sets his own time.
 */
class utimeSystemCall {
public:
  static bool handleDetPre(
      globalState& gs, state& s, ptracer& t, scheduler& sched);
  static void handleDetPost(
      globalState& gs, state& s, ptracer& t, scheduler& sched);

  const int syscallNumber = SYS_utime;
  const string syscallName = "utime";
};
// =======================================================================================
/**
 * int utimes(const char *filename, const struct timeval times[2]);
 *
 * The utimes() system call changes the access and modification times of the
 * inode speci‐ fied by filename to the actime and modtime fields of times
 * respectively.
 *
 * The time the user uses should be determinitic. We only have to watch out for
 * the zero case when the user sets his own time.
 */
class utimesSystemCall {
public:
  static bool handleDetPre(
      globalState& gs, state& s, ptracer& t, scheduler& sched);
  static void handleDetPost(
      globalState& gs, state& s, ptracer& t, scheduler& sched);

  const int syscallNumber = SYS_utimes;
  const string syscallName = "utimes";
};
// =======================================================================================
/**
 * int utimensat(int dirfd, const char *pathname, const struct timespec
 * times[2], int flags);
 *
 * Updates the timestamps of a file with nanosecond precision.
 * TODO FILESYSTEM RELATED.
 *
 * Definitely not deterministic! We use our logical clock to set the file
 * timestamps. This is an issue for the case where both times entries are null.
 * From utimensat(2): > If times is NULL, then both timestamps are set to the
 * current time.
 */
class utimensatSystemCall {
public:
  static bool handleDetPre(
      globalState& gs, state& s, ptracer& t, scheduler& sched);
  static void handleDetPost(
      globalState& gs, state& s, ptracer& t, scheduler& sched);

  const int syscallNumber = SYS_utimensat;
  const string syscallName = "utimensat";
};
// =======================================================================================
/**
 * int futimesat(int dirfd, const char *pathname, const struct timespec
 * times[2]);
 *
 * Updates the timestamps of a file with nanosecond precision.
 * TODO FILESYSTEM RELATED.
 *
 * Definitely not deterministic! We use our logical clock to set the file
 * timestamps. This is an issue for the case where both times entries are null.
 * From utimensat(2): > If times is NULL, then both timestamps are set to the
 * current time.
 */
class futimesatSystemCall {
public:
  static bool handleDetPre(
      globalState& gs, state& s, ptracer& t, scheduler& sched);
  static void handleDetPost(
      globalState& gs, state& s, ptracer& t, scheduler& sched);

  const int syscallNumber = SYS_futimesat;
  const string syscallName = "futimesat";
};
// =======================================================================================
/**
 * Many threaded packages use epoll_*
 *
 */
class epoll_ctlSystemCall {
public:
  static bool handleDetPre(
      globalState& gs, state& s, ptracer& t, scheduler& sched);
  static void handleDetPost(
      globalState& gs, state& s, ptracer& t, scheduler& sched);

  const int syscallNumber = SYS_epoll_ctl;
  const string syscallName = "epoll_ctl";
};
// =======================================================================================
/**
 * We intercept exceve since we need to append our LD_PRELOAD enviornment to and
 * pass in, as the last argument.
 *
 */
class execveSystemCall {
public:
  static bool handleDetPre(
      globalState& gs, state& s, ptracer& t, scheduler& sched);
  static void handleDetPost(
      globalState& gs, state& s, ptracer& t, scheduler& sched);

  const int syscallNumber = SYS_execve;
  const string syscallName = "execve";
};

// =======================================================================================
/**
 * pid_t vfork(void);
 *
 * The vfork() function has the same effect as fork(2), except that the
 * behavior is undefined if the process created by  vfork()  either  modifies
 * any  data other  than  a variable of type pid_t used to store the return
 * value from vfork(), or returns from the function in which vfork() was called,
 * or calls  any  other  function before successfully calling _exit(2) or one of
 * the exec(3) family of functions.
 *
 * vfork() is a special case of clone(2).  It is used to create  new  processes
 * without copying  the page tables of the parent process.  It may be useful in
 * performance-sen‐ sitive applications where a  child  is  created  which  then
 * immediately  issues  an execve(2).
 *
 * This system call should be deterministic as long as we have the child run to
 * completion before letting the parent run, notice this is not the exact
 * behavior of vfork, as if the child execve's then the parent will no longer be
 * suspended.
 */
class vforkSystemCall {
public:
  static bool handleDetPre(
      globalState& gs, state& s, ptracer& t, scheduler& sched);
  static void handleDetPost(
      globalState& gs, state& s, ptracer& t, scheduler& sched);

  const int syscallNumber = SYS_vfork;
  const string syscallName = "vfork";
};
// =======================================================================================
class wait4SystemCall {
public:
  static bool handleDetPre(
      globalState& gs, state& s, ptracer& t, scheduler& sched);
  static void handleDetPost(
      globalState& gs, state& s, ptracer& t, scheduler& sched);

  const int syscallNumber = SYS_wait4;
  const string syscallName = "wait4";
};
// =======================================================================================
class waitidSystemCall {
public:
  static bool handleDetPre(
      globalState& gs, state& s, ptracer& t, scheduler& sched);
  static void handleDetPost(
      globalState& gs, state& s, ptracer& t, scheduler& sched);

  const int syscallNumber = SYS_waitid;
  const string syscallName = "waitid";
};
// =======================================================================================
/**
 * ssize_t writev(int fd, const struct iovec *iov, int iovcnt)
 *
 * The writev()  system call writes iovcnt buffers of data described by iov to
 * the file associated with the file descriptor fd ("gather output").
 *
 * Non deterministic!
 * Same problem as regular writes.
 *
 */
class writevSystemCall {
public:
  static bool handleDetPre(
      globalState& gs, state& s, ptracer& t, scheduler& sched);
  static void handleDetPost(
      globalState& gs, state& s, ptracer& t, scheduler& sched);

  const int syscallNumber = SYS_writev;
  const string syscallName = "writev";
};
// =======================================================================================
/**
 * ssize_t write(int fd, const void *buf, size_t count);
 *
 * write()  writes up to count bytes from the buffer pointed buf to the file
 * referred to by the file descriptor fd.
 *
 * TODO: Non deterministic due to errors being dependent on the underlying disk
 * space avaliable. This function can also fail due to many reasons, e.g. broken
 * pipe.
 *
 * TODO: Check number of bytes written, and continue writting until _count_
 * bytes are written. This may cause blocking issues in some cases.
 */
class writeSystemCall {
public:
  static bool handleDetPre(
      globalState& gs, state& s, ptracer& t, scheduler& sched);
  static void handleDetPost(
      globalState& gs, state& s, ptracer& t, scheduler& sched);

  const int syscallNumber = SYS_write;
  const string syscallName = "write";
};

// =======================================================================================
/**
 * int socket(int domain, int type, int protocol);
 *
 * socket()  creates  an endpoint for communication and returns a file
 * descriptor that refers to that endpoint.  The file descriptor returned by a
 * successful call will be the lowest-numbered file descriptor not currently
 * open for the process.
 */
class socketSystemCall {
public:
  static bool handleDetPre(
      globalState& gs, state& s, ptracer& t, scheduler& sched);
  static void handleDetPost(
      globalState& gs, state& s, ptracer& t, scheduler& sched);

  const int syscallNumber = SYS_socket;
  const string syscallName = "socket";
};

// =======================================================================================
/**
 * int listen(int sockfd, int backlog)
 *
 * listen()  marks the socket referred to by sockfd as a passive socket, that
 * is, as a socket that will be used to accept incoming connection requests
 * using accept(2).
 */
class listenSystemCall {
public:
  static bool handleDetPre(
      globalState& gs, state& s, ptracer& t, scheduler& sched);
  static void handleDetPost(
      globalState& gs, state& s, ptracer& t, scheduler& sched);

  const int syscallNumber = SYS_listen;
  const string syscallName = "listen";
};

// =======================================================================================
/**
 * int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
 */
class acceptSystemCall {
public:
  static bool handleDetPre(
      globalState& gs, state& s, ptracer& t, scheduler& sched);
  static void handleDetPost(
      globalState& gs, state& s, ptracer& t, scheduler& sched);

  const int syscallNumber = SYS_accept;
  const string syscallName = "accept";
};

// =======================================================================================
/**
 * int accept4(int sockfd, struct sockaddr *addr,
 *             socklen_t *addrlen, int flags);
 */
class accept4SystemCall {
public:
  static bool handleDetPre(
      globalState& gs, state& s, ptracer& t, scheduler& sched);
  static void handleDetPost(
      globalState& gs, state& s, ptracer& t, scheduler& sched);

  const int syscallNumber = SYS_accept4;
  const string syscallName = "accept4";
};

// =======================================================================================
/**
 * int shutdown(int sockfd, int how)
 */
class shutdownSystemCall {
public:
  static bool handleDetPre(
      globalState& gs, state& s, ptracer& t, scheduler& sched);
  static void handleDetPost(
      globalState& gs, state& s, ptracer& t, scheduler& sched);

  const int syscallNumber = SYS_shutdown;
  const string syscallName = "shutdown";
};

// =======================================================================================
// Iterate through our vector of entries, which represent the binary memory for
// linux_dirents or linux_dirent64. We virtualize the inodes and add entries to
// our inodeMap.
template <typename DirEntry>
void virtualizeEntries(
    vector<uint8_t>& entries, ValueMapper<ino_t, ino_t>& inodeMap) {
  // Variable size data, we cannot "iterate" over the entries in the array.
  uint8_t* position = entries.data();

  // Variable size data, we cannot "iterate" over the entries in the array.
  while (position < entries.data() + entries.size()) {
    DirEntry* currentEntry = (DirEntry*)position;
    size_t entrySize = currentEntry->d_reclen;

    // Offset values are only meaninful to the filesystem, programs should not
    // be using it.
    currentEntry->d_off = 0;

    // Virtualize our inode.
    ino64_t inode = currentEntry->d_ino;
    currentEntry->d_ino = !inodeMap.realValueExists(inode)
                              ? inodeMap.addRealValue(inode)
                              : inodeMap.getVirtualValue(inode);

    // Next entry...
    position += entrySize;
  }
}
// =======================================================================================
template <typename T>
void handleDents(globalState& gs, state& s, ptracer& t, scheduler& sched) {
  // Error, return system call to tracee.
  if (t.getReturnValue() < 0) {
    return;
  }

  // Use file descriptor to fetch correct entry in table.
  int fd = (int)t.arg1();
  traceePtr<uint8_t> traceeBuffer((uint8_t*)t.arg2());
  size_t traceeBufferSize = t.arg3();

  // We have never seen this entry before! This is a new getdents call, not a
  // replay by us.
  if (s.dirEntries.count(fd) == 0) {
    auto msg = "Tracee requested getdents for the first time for fd: %d.\n";
    gs.log.writeToLog(Importance::info, msg, fd);

    s.dirEntries.emplace(
        fd, directoryEntries<linux_dirent>{s.dirEntriesBytes, gs.log});
  }

  // We have read zero bytes. We're done!
  if (t.getReturnValue() == 0) {
    gs.log.writeToLog(Importance::info, "All bytes have been read.\n");
    gs.log.writeToLog(
        Importance::info, "Returning sorted entries to tracee.\n");

    // We want to fill up to traceeBufferSize which is the size the tracee
    // originally asked for.

    vector<uint8_t> filledVector =
        s.dirEntries.at(fd).getSortedEntries(traceeBufferSize);
    virtualizeEntries<T>(filledVector, gs.inodeMap);

    gs.log.writeToLog(
        Importance::info, "Returning %d bytes!\n", filledVector.size());

    // Write entry back to tracee!
    writeVmTraceeRaw(
        filledVector.data(), traceeBuffer, filledVector.size(), t.getPid());
    // Explicitly increase counter.
    t.readVmCalls++;

    // Set return register!
    t.setReturnRegister(filledVector.size());
  }
  // We read some bytes but there might be more to read.
  else {
    gs.log.writeToLog(Importance::info, "Reading directory entries...\n");

    // Read entries from tracee's buffer.
    // We only copy over the return value, which is how many bytes were actually
    // filled by the kernel into the tracee's buffer.
    size_t bytesToCopy = t.getReturnValue();
    uint8_t localBuffer[bytesToCopy];
    doWithCheck(
        readVmTraceeRaw(traceeBuffer, localBuffer, bytesToCopy, t.getPid()),
        "readVmTraceeRaw: Unable to read bytes for dirent into buffer.");
    // Explicitly increase counter.
    t.readVmCalls++;

    vector<uint8_t> newChunk{localBuffer, localBuffer + bytesToCopy};

    // Copy chunks over to our directory entry for this file descriptor.
    s.dirEntries.at(fd).addChunk(newChunk);

    gs.log.writeToLog(
        Importance::info, "Replaying system call to read more bytes...\n");
    replaySystemCall(gs, t, t.getSystemCallNumber());
  }
  return;
}
// =======================================================================================
#endif
