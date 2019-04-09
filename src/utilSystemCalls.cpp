#include "utilSystemCalls.hpp"

#include <sstream>
#include <fcntl.h>

// File local functions.

bool preemptIfBlocked(globalState& gs, state& s, ptracer& t, scheduler& sched,
                      int64_t errnoValue){
  if(- errnoValue == t.getReturnValue()){
    gs.log.writeToLog(Importance::info, "Syscall would have blocked!\n");

    sched.preemptAndScheduleNext(preemptOptions::runnable);
    return true;
  }else{
    // Disambiguiate. Otherwise it's impossible to tell the difference between a
    // maybeRunnable process that made no progress vs the case where we were on
    // maybeRunnable and we made progress, and eventually we hit another blocking
    // system call.
    return false;
  }
}

// =======================================================================================
bool replaySyscallIfBlocked(globalState& gs, state& s, ptracer& t, scheduler& sched,
                            int64_t errornoValue){
  if(- errornoValue == t.getReturnValue()){
    gs.log.writeToLog(Importance::info, "System call would have blocked!\n");

    gs.replayDueToBlocking++;
    sched.preemptAndScheduleNext(preemptOptions::markAsBlocked);
    replaySystemCall(gs, t, t.getSystemCallNumber());
    return true;
  }else{
    // Disambiguiate. Otherwise it's impossible to tell the difference between a
    // maybeRunnable process that made no progress vs the case where we were on
    // maybeRunnable and we made progress, and eventually we hit another blocking
    // system call.
    return false;
  }
}
// =======================================================================================
void replaySystemCall(globalState& gs, ptracer& t, uint64_t systemCall){
#ifdef EXTRANEOUS_TRACEE_READS
  uint16_t minus2 = t.readFromTracee(traceePtr<uint16_t>((uint16_t*) ((uint64_t) t.getRip().ptr - 2)), t.getPid());
  if (!(minus2 == 0x80CD || minus2 == 0x340F || minus2 == 0x050F)) {
    throw runtime_error("dettrace runtime exception: IP does not point to system call instruction!\n");
  }
#endif

  gs.totalReplays++;
  // Replay system call!
  t.changeSystemCall(systemCall);
  t.writeIp((uint64_t) t.getRip().ptr - 2);
}
// =======================================================================================
void zeroOutStatfs(struct statfs& stats){
  // Type of filesystem
  stats.f_type = 0xEF53;// EXT4_SUPER_MAGIC
  stats.f_bsize = 100;   /* Optimal transfer block size */
  stats.f_blocks = 1000;  /* Total data blocks in filesystem */
  stats.f_bfree = 10000;   /* Free blocks in filesystem */
  stats.f_bavail = 5000;  /* Free blocks available to
                             unprivileged user */
  stats.f_files = 1000;   /* Total file nodes in filesystem */
  stats.f_ffree = 1000;   /* Free file nodes in filesystem */
  stats.f_fsid.__val[0] = 0;
  stats.f_fsid.__val[1] = 0;
  stats.f_namelen = 200; /* Maximum length of filenames */
  stats.f_frsize = 20;  /* Fragment size (since Linux 2.6) */
  stats.f_flags = 1;   /* Mount flags of filesystem */
}
// =======================================================================================
void handleStatFamily(globalState& gs, state& s, ptracer& t, string syscallName){
  struct stat* statPtr;

  if(syscallName == "newfstatat"){
    statPtr = (struct stat*) t.arg3();
  }else{
    statPtr = (struct stat*) t.arg2();
  }

  if(statPtr == nullptr){
    gs.log.writeToLog(Importance::info, syscallName + ": statbuf null.\n");
    return;
  }

  int retVal = t.getReturnValue();
  if(retVal == 0){
    struct stat myStat = t.readFromTracee(traceePtr<struct stat>(statPtr), s.traceePid);
    ino_t inode = myStat.st_ino;
    gs.log.writeToLog(Importance::extra, "(device,inode) = (%lu,%lu)\n", myStat.st_dev, inode);
    // Use inode to check if we created this file during our run.
    time_t virtualMtime = gs.mtimeMap.realValueExists(inode) ?
      gs.mtimeMap.getVirtualValue(inode) :
      0; // This was an old file that has not been opened for modification.

    /* Time of last access */
    myStat.st_atim = timespec { .tv_sec =  0,
                                .tv_nsec = 0 };
    /* Time of last modification */
    myStat.st_mtim = timespec { .tv_sec =  virtualMtime,
                                .tv_nsec = 0 };
    /* Time of last status change */
    myStat.st_ctim = timespec { .tv_sec = 0,
                                .tv_nsec = 0 };

    // TODO: I'm surprised this doesn't break things. I guess so far, we have only used
    // single device filesystems.
    myStat.st_dev = 1;         /* ID of device containing file */

    myStat.st_ino = gs.inodeMap.realValueExists(inode) ?
      gs.inodeMap.getVirtualValue(inode) :
      gs.inodeMap.addRealValue(inode) ;

    // st_mode holds the permissions to the file. If we zero it out libc functions
    // will think we don't have access to this file. Hence we keep our permissions
    // as part of the stat.
    // mode_t    st_mode;        /* File type and mode */

    myStat.st_nlink = 1;       /* Number of hard links */

    // These should never be set! The container handles group and user id through
    // setting these will lead to inconistencies which will manifest themselves as
    // weird permission denied errors for some system calls.
    // myStat.st_uid = 65534;         /* User ID of owner */
    // myStat.st_gid = 1;         /* Group ID of owner */

    myStat.st_rdev = 1;        /* Device ID (if special file) */

    // Program will stall if we put some arbitrary value here: TODO.
    // myStat.st_size = 512;        /* Total size, in bytes */

    myStat.st_blksize = 512;     /* Block size for filesystem I/O */

    // TODO: could return actual value here?
    myStat.st_blocks = 1;      /* Number of 512B blocks allocated */

    // Write back result for child.
    t.writeToTracee(traceePtr<struct stat>(statPtr), myStat, s.traceePid);
  }
  return;
}
// =======================================================================================
void printInfoString(uint64_t addr, logger &log, pid_t traceePid, ptracer& t, string postFix){
  if((char*) addr != nullptr && log.getDebugLevel() > 0){
    string path = t.readTraceeCString(traceePtr<char>((char*) addr), traceePid);
    string msg = postFix + log.makeTextColored(Color::green, path) + "\n";
    log.writeToLog(Importance::info, msg);
  }
  return;
}
// =======================================================================================
void injectPause(globalState& gs, state& s, ptracer& t){
  gs.log.writeToLog(Importance::info, "Injecting pause call to tracee!\n");
  s.syscallInjected = true;
  gs.injectedSystemCalls++;

  replaySystemCall(gs, t, SYS_pause);
}
// =======================================================================================
void replaceSystemCallWithNoop(globalState& gs, state& s, ptracer& t){
  t.changeSystemCall(SYS_time);
  gs.log.writeToLog(Importance::info, "Turning this system call into a NOOP\n");
  s.noopSystemCall = true;
  return;
}
// =======================================================================================
pair<int,int> getPipeFds(globalState& gs, state& s, ptracer& t){
// Get values of both file descriptors.
  int* pipefdTracee = (int*) t.arg1();
  traceePtr<int> fdPtr1 = traceePtr<int>(& pipefdTracee[0]);
  traceePtr<int> fdPtr2 = traceePtr<int>(& pipefdTracee[1]);

  int fd1 = t.readFromTracee(fdPtr1, t.getPid());
  int fd2 = t.readFromTracee(fdPtr2, t.getPid());

  gs.log.writeToLog(Importance::info, "Got pipe fd1: " + to_string(fd1) + "\n");
  gs.log.writeToLog(Importance::info, "Got pipe fd2: " + to_string(fd2) + "\n");

  // Track this file descriptor:
  if(s.fdStatus.count(fd1) != 0){
    throw runtime_error("dettrace runtime exception: Value already in map (fdStatus).");
  }
  if(s.fdStatus.count(fd2) != 0){
    throw runtime_error("dettrace runtime exception: Value already in map (fdStatus).");
  }

  return make_pair(fd1, fd2);
}
// =======================================================================================
template <typename T, typename U> static inline traceePtr<T> plusRemotePtr(traceePtr<T> rptr, U off) {
  return traceePtr<T>((T*)((unsigned long)rptr.ptr + (long) off));
}

/* assume @remotePtr has enough space to store all of @s, '\0' included */
static void writeTraceeCString(ptracer& t, traceePtr<unsigned long>remotePtr, string& s)
{
  auto len = s.length();
  if (len == 0) return;
  unsigned long val;

  for (auto i = 0; i <= len; i += sizeof(long)) {
    val = 0;
    auto p = plusRemotePtr(remotePtr, i);
    for (int j = i; j < i + sizeof(long); j++) {
      if (j < len) {
	val |= ((unsigned long)s[j] & 0xffUL) << 8*(j-i);
      }
    }
    t.writeToTracee(p, val, t.getPid());
  }
}

static pair<string, string> parseEnv(string& env) {
  int i;
  for (i = 0; i < env.length(); i++) {
    if (env[i] == '=') {
      break;
    }
  }
  return make_pair(env.substr(0, i), env.substr(i+1));
}

static unordered_map<string, string> getTraceeEnv(ptracer& t) {
  unordered_map<string, string> envvars;

  unsigned long envpVal = (unsigned long)t.arg3();

  for (int i = 0; ; i++) {
    auto pp = traceePtr<unsigned long>((unsigned long*)(envpVal + i * sizeof(void*)));
    unsigned long envp = t.readFromTracee(pp, t.getPid());
    if (!envp) break;
    auto z = t.readTraceeCString(traceePtr<char>((char*)envp), t.getPid());
    if (z.empty()) {
      break;
    }

    envvars.insert(parseEnv(z));
  }

  return envvars;
}
// =======================================================================================
/* copy trace envs, caller to ensure @rptr has enough space */
static void copyTraceeEnv(ptracer& t, unordered_map<string, string>& envs, traceePtr<char*> rptr, traceePtr<char> strSection) {
  unsigned long newEnvpVal = (unsigned long)rptr.ptr;
  auto newCString = traceePtr<unsigned long>((unsigned long*)(strSection.ptr));
  int envpCount = 0;
  string env;

  for (auto it = envs.cbegin(); it != envs.cend(); ++it, ++envpCount) {
    auto newpp = traceePtr<unsigned long>((unsigned long*)(newEnvpVal + envpCount * sizeof(void*)));
    // update env string and pointer
    env = it->first + "=" + it->second;
    writeTraceeCString(t, newCString, env);
    t.writeToTracee(newpp, (unsigned long)newCString.ptr, t.getPid());
    newCString = plusRemotePtr(newCString, (1+env.length())); // point to next env string
  }
  // null terminate envp
  auto newpp = traceePtr<unsigned long>((unsigned long*)(newEnvpVal + envpCount * sizeof(void*)));
  t.writeToTracee(newpp, 0UL, t.getPid());
}

void appendEnvpLdPreload(globalState& gs, state& s, ptracer& t) {
  auto preloadedLibdet = true;
  auto envs = getTraceeEnv(t);

  if (!s.mmapMemory.doesExist) {
    for (auto it = envs.cbegin(); it != envs.cend(); ++it) {
      if (it->first == "LD_PRELOAD") {
	setenv("TRACEE_LDPRELOAD", it->second.c_str(), 1);
      }
    }
    return;
  }

  unsigned stroff = 0x1000;
  unsigned long newEnvpVal = (unsigned long)s.mmapMemory.getAddr().ptr;
  auto newCString = traceePtr<unsigned long>((unsigned long*)((unsigned long)newEnvpVal + stroff));

  string preloadKey("LD_PRELOAD");

  if (envs.find(preloadKey) == envs.end()) {  /* insert LD_PRELOAD if needed */
    envs[preloadKey] = secure_getenv("TRACEE_LDPRELOAD");
    preloadedLibdet = false;
  } else {
    auto preload = envs[preloadKey];
    string libdet(secure_getenv("TRACEE_LDPRELOAD"));
    /* LD_PRELOAD but no libdet.so */
    if (preload.find(libdet) == string::npos) {
      envs[preloadKey] = libdet + ":" + preload;
      preloadedLibdet = false;
    }
  }

  if (!preloadedLibdet) {
    string msg("append LD_PRELOAD=");
    gs.log.writeToLog(Importance::info, msg + secure_getenv("TRACEE_LDPRELOAD") + " to envp\n");
    copyTraceeEnv(t, envs, traceePtr<char*>((char**)newEnvpVal), traceePtr<char>((char*)newCString.ptr));
    t.writeArg3(newEnvpVal);
  }
}
// =======================================================================================
bool tracee_file_exists(string traceePath, pid_t traceePid, logger& log,
                   int traceeDirFd) {
  // Create full absolute path in the hostOS file system.
  string resolvedPath = resolve_tracee_path(traceePath, traceePid, log, traceeDirFd);

  resolvedPath.append("/");
  resolvedPath.append(traceePath);
  log.writeToLog(Importance::info, "fullpath: %s\n", resolvedPath.c_str());

   struct stat statbuf = {0};
  int res = stat(resolvedPath.c_str(), &statbuf);
  int err = errno;
  if (res == 0) {
    return true;
  } else if (err == ENOENT /*|| err == ENOTDIR might be needed later */) {
    return false;
  } else {
    throw runtime_error("dettrace runtime exception: "
                        "Unable to check for existance of file: " + to_string(errno));
  }
}
// =======================================================================================
ino_t inode_from_tracee(string traceePath, pid_t traceePid, logger& log,
                        int traceeDirFd) {
  // Create full absolute path in the hostOS file system.
  string resolvedPath = resolve_tracee_path(traceePath, traceePid, log, traceeDirFd);
  resolvedPath.append("/");
  resolvedPath.append(traceePath);
  log.writeToLog(Importance::info, "fullpath: %s\n", resolvedPath.c_str());

  struct stat statbuf = {0};
  // If this is a symbolic link, we want the actual symbolic links and not the file it
  // points to! So we lstat
  int res = lstat(resolvedPath.c_str(), &statbuf);
  if (res < 0) {
    throw runtime_error("dettrace runtime exception: Unable to stat file in "
                       "tracee from /proc/. errno: " + to_string(res));
  }

  if (S_ISLNK(statbuf.st_mode)) {
    log.writeToLog(Importance::info, "This file is a symbolic link\n");
  }

  log.writeToLog(Importance::info, "lstat(%s) returned inode!\n", resolvedPath.c_str());
  log.writeToLog(Importance::extra, "lstat(%s) returned inode: %d!\n", resolvedPath.c_str(),
                 statbuf.st_ino);

  return statbuf.st_ino;
}
// =======================================================================================
ino_t readInodeFor(logger& log, pid_t traceePid, int fd){
  std::ostringstream ss;
  // read from /proc/$pid/fd/$fd
  ss << "/proc/" << traceePid << "/fd/" << fd;
  string procPath = ss.str();
  log.writeToLog(Importance::info, "procPath: %s\n", procPath.c_str());
  struct stat statbuf = {0};
  int res = stat(procPath.c_str(), &statbuf);
  if (res < 0) {
    throw runtime_error("dettrace runtime exception: Unable to stat file in "
                       "tracee from /proc/. errno: " + to_string(res));
  }

  log.writeToLog(Importance::info, "stat(%s) returned inode!\n", procPath.c_str());
  log.writeToLog(Importance::extra, "stat(%s) returned inode: %d!\n", procPath.c_str(),
                    statbuf.st_ino);

  return statbuf.st_ino;
}
// =======================================================================================
bool sendTraceeSignalNow(int signum, globalState& gs,
                                state& s, ptracer& t, scheduler& sched) {
  enum sighandler_type sh = SIGHANDLER_DEFAULT;
  if (s.currentSignalHandlers.count(signum)) {
    sh = s.currentSignalHandlers[signum];
  }

  switch (sh) {

  case SIGHANDLER_CUSTOM_1SHOT: {
    gs.log.writeToLog(Importance::info, "tracee has a custom 1-shot signal "+to_string(signum)+" handler, sending signal to pid %u\n", t.getPid());

    // TODO: JLD is this a race? the tracee isn't technically paused yet
    t.changeSystemCall(SYS_pause);
    s.signalInjected = true;
    s.currentSignalHandlers[signum] = SIGHANDLER_DEFAULT; // go back to default next time
    int retVal = syscall(SYS_tgkill, t.getPid(), t.getPid(), signum);
    if (0 != retVal) {
      throw runtime_error("dettrace runtime exception: sending myself signal "+to_string(signum)+" failed, tgkill returned " + to_string(retVal));
    }
    return true; // run pause post-hook
  }

  case SIGHANDLER_CUSTOM: {
    gs.log.writeToLog(Importance::info, "tracee has a custom signal "+to_string(signum)+" handler, sending signal to pid %u\n", t.getPid());

    // TODO: JLD is this a race? the tracee isn't technically paused yet
    t.changeSystemCall(SYS_pause);
    s.signalInjected = true;
    int retVal = syscall(SYS_tgkill, t.getPid(), t.getPid(), signum);
    if (0 != retVal) {
      throw runtime_error("dettrace runtime exception: sending myself signal "+to_string(signum)+" failed, tgkill returned " + to_string(retVal));
    }
    return true; // run pause post-hook
  }

  case SIGHANDLER_DEFAULT: {
    if (SIGALRM != signum && SIGVTALRM != signum && SIGPROF != signum) {
      throw runtime_error("dettrace runtime exception: can't send myself a signal "+to_string(signum));
    }
    // for SIGALRM, SIGVTALRM, SIGPROF, default handler terminates the tracee
    gs.log.writeToLog(Importance::info, "tracee has default signal "+to_string(signum)+" handler, injecting exit() for pid %u\n", t.getPid());
    t.changeSystemCall(SYS_exit);
    t.writeArg1( 128 + signum ); // status reflects exit due to signal
    return false; // there shouldn't be a post-hook for exit
  }

  case SIGHANDLER_IGNORED: // don't do anything
    replaceSystemCallWithNoop(gs, s, t);
    gs.log.writeToLog(Importance::info, "tracee is ignoring signal "+to_string(signum)+", doing nothing\n");
    return true; // run noop (getpid) post-hook

  default:
    throw runtime_error("dettrace runtime exception: invalid handler "+to_string(sh)+
                        " for signal "+to_string(signum));
  }
}
// =======================================================================================
string resolve_tracee_path(string traceePath, pid_t traceePid, logger& log,
                        int traceeDirFd) {
  log.writeToLog(Importance::info, "Resolving path for: %s\n", traceePath.c_str());

  // Some system calls take empty path and use traceeDirFd exclusively to refer to a file
  // see O_PATH option in `man 2 open`. We do not support this right now...
  if (traceePath == "") {
    throw runtime_error("We do not support system calls with empty paths.");
  }

  if (traceeDirFd < -1 && traceeDirFd != AT_FDCWD) {
    throw runtime_error("Negative dirfd given to resolve_tracee_path.");
  }

  string prefixProcFd;
  // is absolute path:
  if (traceePath.rfind("/", 0) == 0) {
    // Absolute path, the user might have chrooted. Use their root.
    prefixProcFd = "/proc/" + to_string(traceePid) + "/root";
  } else {
    // Only on relative paths should we use traceeDirFd if avaliable, and it's not.
    // AT_FDCWD, just uses CWD which we do anyways, in the else branch.
    if (traceeDirFd != -1 && traceeDirFd != AT_FDCWD) {
      log.writeToLog(Importance::info, "Using user's dirfd for path resolution.\n");
      prefixProcFd = "/proc/" + to_string(traceePid) + "/fd/" + to_string(traceeDirFd);
    } else {
      // Use cwd to figure out path.
      prefixProcFd = "/proc/" + to_string(traceePid) + "/cwd";
    }
  }

  log.writeToLog(Importance::info, "prefixProcFd location: %s\n", prefixProcFd.c_str());
  char pathbuf[PATH_MAX + 1] = {0};
  int ret = readlink(prefixProcFd.c_str(), pathbuf, PATH_MAX);
  if (ret == -1) {
    throw runtime_error("Unable to read cwd from tracee: " + to_string(traceePid) +
                        " errno: " + to_string(errno));
  }

  return string { pathbuf };
}
// =======================================================================================
void handlePreOpens(globalState& gs, state& s, ptracer& t, int dirfd,
                traceePtr<char> charpath, int flags) {

  string path = t.readTraceeCString(charpath, s.traceePid);
  string coloredPath = gs.log.makeTextColored(Color::green, path);
  gs.log.writeToLog(Importance::info, "Path: %s\n", coloredPath.c_str());
  string flagsStr = "";
  if ((flags & O_RDONLY) == O_RDONLY) { flagsStr += "O_RDONLY "; }
  if ((flags & O_WRONLY) == O_WRONLY) { flagsStr += "O_WRONLY "; }
  if ((flags & O_RDWR) == O_RDWR) { flagsStr += "O_RDWR "; }
  if ((flags & O_APPEND) == O_APPEND) { flagsStr += "O_APPEND "; }
  if ((flags & O_ASYNC) == O_ASYNC) { flagsStr += "O_ASYNC "; }
  if ((flags & O_CLOEXEC) == O_CLOEXEC) { flagsStr += "O_CLOEXEC "; }
  if ((flags & O_CREAT) == O_CREAT) { flagsStr += "O_CREAT "; }
  if ((flags & O_DIRECT) == O_DIRECT) { flagsStr += "O_DIRECT "; }
  if ((flags & O_DIRECTORY) == O_DIRECTORY) { flagsStr += "O_DIRECTORY "; }
  if ((flags & O_DSYNC) == O_DSYNC) { flagsStr += "O_DSYNC "; }
  if ((flags & O_EXCL) == O_EXCL) { flagsStr += "O_EXCL "; }
  if ((flags & O_LARGEFILE) == O_LARGEFILE) { flagsStr += "O_LARGEFILE "; }
  if ((flags & O_NOATIME) == O_NOATIME) { flagsStr += "O_NOATIME "; }
  if ((flags & O_NOCTTY) == O_NOCTTY) { flagsStr += "O_NOCTTY "; }
  if ((flags & O_NOFOLLOW) == O_NOFOLLOW) { flagsStr += "O_NOFOLLOW "; }
  if ((flags & O_NONBLOCK) == O_NONBLOCK) { flagsStr += "O_NONBLOCK "; }
  if ((flags & O_NDELAY) == O_NDELAY) { flagsStr += "O_NDELAY "; }
  if ((flags & O_PATH) == O_PATH) { flagsStr += "O_PATH "; }
  if ((flags & O_SYNC) == O_SYNC) { flagsStr += "O_SYNC "; }
  if ((flags & O_TMPFILE) == O_TMPFILE) { flagsStr += "O_TMPFILE "; }
  if ((flags & O_TRUNC) == O_TRUNC) { flagsStr += "O_TRUNC "; }
  gs.log.writeToLog(Importance::info, "Flags: 0x%x "+flagsStr+"\n", flags);

  /*
  The O_TMPFILE is a superset of other flags and includes, bizarrely,
  O_DIRECTORY. So we always check for exact equivalence instead of a non-zero
  result after ANDing.

  see https://elixir.bootlin.com/linux/v4.1/source/include/uapi/asm-generic/fcntl.h#L92 for the Linux kernel definitions 
  glibc has the same property but different constants:
d@acghaswellcat16:dettrace-experiments$ gcc -Wall opentest.c -o opentest && ./opentest
O_DIRECTORY: 10000 O_TMPFILE: 410000
d@acghaswellcat16:dettrace-experiments$ uname -a
Linux acghaswellcat16 4.15.0-43-generic #46-Ubuntu SMP Thu Dec 6 14:45:28 UTC 2018 x86_64 x86_64 x86_64 GNU/Linux
  */
  if ((flags & O_TMPFILE) == O_TMPFILE) {
    // tmp file being created, no way it could already exist. Skip straight to post-hook.
    gs.log.writeToLog(Importance::info, "temporary file being created.\n");
    return;
  }

  if(path == "/dev/random"){
    gs.devRandomOpens++;
  }else if(path == "/dev/urandom"){
    gs.devUrandomOpens++;
  }

  // Flag should never be false in pre-hook.
  if (s.fileExisted != false) {
    throw runtime_error("fileExisted flag out of sync. It should have been set to false.");
  }

  // We only case we care about newly created files, later we might want to update
  // the mtime for other modification events like O_TRUNC or O_APPEND.
  if((flags & O_CREAT) == O_CREAT){
    gs.log.writeToLog(Importance::info, "Tracee included O_CREATE.\n");
    s.fileExisted = tracee_file_exists(path, s.traceePid, gs.log, dirfd);
    gs.log.writeToLog(Importance::info, "fileExisted? %s\n", s.fileExisted ? "true" : "false");
  }
}
// =======================================================================================
void handlePostOpens(globalState& gs, state& s, ptracer& t, int flags) {
  if(t.getReturnValue() > 0 &&
     // New regular file created through O_CREAT
     (((flags & O_CREAT) == O_CREAT && ! s.fileExisted) ||
      // Special case for O_TMPFILE
      ((flags & O_TMPFILE) == O_TMPFILE))
     ){
    gs.log.writeToLog(Importance::info, "A new file was created\n!");
    // Use fd to get inode.
    auto inode = readInodeFor(gs.log, s.traceePid, t.getReturnValue());
    gs.mtimeMap.addRealValue(inode);
    gs.inodeMap.addRealValue(inode);
  }
  s.fileExisted = false;
}
// =======================================================================================
