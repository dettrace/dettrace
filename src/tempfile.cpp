#include <sys/types.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/mount.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <limits.h>

#include <memory>
#include <tuple>
#include <fstream>
#include <string>

#include "util.hpp"
#include "tempfile.hpp"

#if defined _WIN32
  #define PATH_SEPERATOR  '\\';
#else
  #define PATH_SEPEARTOR  '/';
#endif

static std::string fd_file_path(int fd) {
  char procfd[32] = {0,};
  char pathname[1 + PATH_MAX] = {0,};

  snprintf(procfd, 32, "/proc/self/fd/%u", fd);
  if (readlink(procfd, pathname, PATH_MAX) < 0) {
    return "";
  }
  return std::string(pathname);
}

static std::pair<int, std::string> make_temp_file(const std::string& dir = "") {
  std::string path;
  
  if (dir.empty()) {
    path = P_tmpdir;
  } else {
    path = dir;
  }
    
  path += PATH_SEPEARTOR;
  path += "fileXXXXXX";
  int fd = mkostemp(strdupa(path.c_str()), O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC);
  assert(fd >= 0);
  path = fd_file_path(fd);
  return std::make_pair(fd, path);
}

static pid_t gettid(void) {
  return syscall(SYS_gettid);
}

TempDir::TempDir() {
  TempDir("", false);
}

TempDir::TempDir(const std::string& prefix, bool doMount) {
  owner_pid = gettid();
  std::string path(P_tmpdir);
  path += PATH_SEPEARTOR;
  path += prefix;
  path += "XXXXXX";
  name = mkdtemp(strdupa(path.c_str()));
  if (doMount) {
    if (mount("none", name.c_str(), "tmpfs", 0, NULL) < 0) {
      std::string errmsg("TempDir: failed to mount ");
      errmsg += name;
      errmsg += " as tmpfs";
      runtimeError(errmsg);
    }
    mounted = true;
  }
}

TempDir::~TempDir() {
  pid_t this_pid = gettid();
  if (this_pid == owner_pid) {
    if (this->mounted) {
      if(umount(this->name.c_str()) < 0) {
	std::string errmsg("TempDir: failed to umount ");
	errmsg += name;
	errmsg += ", error: ";
	errmsg += strerror(errno);
	runtimeError(errmsg);
      }
    }
    if (unlinkat(AT_FDCWD, this->name.c_str(), AT_REMOVEDIR) < 0) {
      std::string errmsg("TempDir: unable to remove temp dir: ");
      errmsg += name;
      errmsg += ", error: ";
      errmsg += strerror(errno);
      runtimeError(errmsg);
    }
  }
}

NamedTempFile::NamedTempFile() {
  int fd;
  std::string path;
  std::tie(fd, path) = make_temp_file();
  file = fdopen(fd, "wb");
  assert(file != NULL);
  name = std::move(path);
}

NamedTempFile::NamedTempFile(TempDir& dir) {
  int fd;
  std::string path;
  std::tie(fd, path) = make_temp_file(dir.path());
  file = fdopen(fd, "wb");
  assert(file != NULL);
  name = std::move(path);
}

NamedTempFile::NamedTempFile(const std::string& path) {
  name = path;
  file = fopen(path.c_str(), "wb");
}

TempFile::TempFile() {
  std::string path;
  int fd;

  std::tie(fd, path) = make_temp_file();
  file = fdopen(fd, "wb");
  assert(file != NULL);
  unlink(path.c_str());
}

TempFile::TempFile(TempDir& dir) {
  std::string path;
  int fd;

  std::tie(fd, path) = make_temp_file(dir.path());
  file = fdopen(fd, "wb");
  assert(file != NULL);
  unlink(path.c_str());
}

TempPath::TempPath() {
  std::string path;
  int fd;

  std::tie(fd, path) = make_temp_file();
  close(fd);

  name = std::move(path);
}

TempPath::TempPath(TempDir& dir) {
  std::string path;
  int fd;

  std::tie(fd, path) = make_temp_file(dir.path());
  close(fd);

  name = std::move(path);
}
