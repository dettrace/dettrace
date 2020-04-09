#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

#include <fstream>
#include <memory>
#include <string>
#include <tuple>

#include "tempfile.hpp"
#include "util.hpp"

#if defined _WIN32
#define PATH_SEPERATOR '\\';
#else
#define PATH_SEPEARTOR '/';
#endif

static std::string fd_file_path(int fd) {
  char procfd[32] = {
      0,
  };
  char pathname[1 + PATH_MAX] = {
      0,
  };

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
  int fd =
      mkostemp(strdupa(path.c_str()), O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC);
  if (fd < 0) {
    string errmsg("mkostemp ");
    errmsg += path;
    errmsg += " failed, error: ";
    errmsg += strerror(errno);
    runtimeError(errmsg);
  }

  path = fd_file_path(fd);
  return std::make_pair(fd, path);
}

// glibc only started providing this function in version 3.30, which is still
// pretty recent. Thus, we define this ourselves to support older systems.
namespace {
pid_t _gettid() __THROW { return syscall(SYS_gettid); }
} // namespace

TempDir::TempDir() { TempDir("", false); }

TempDir::TempDir(const std::string& prefix, bool doMount)
    : owner_pid(_gettid()), mounted(false) {
  std::string path(P_tmpdir);
  path += PATH_SEPEARTOR;
  path += prefix;
  path += "XXXXXX";
  name = mkdtemp(strdupa(path.c_str()));
  if (name.empty()) {
    runtimeError("TempDir mkdtemp failed.");
  }

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
  pid_t this_pid = _gettid();

  if (this_pid == owner_pid) {
    if (this->mounted) {
      umount(this->name.c_str());
    }
    unlinkat(AT_FDCWD, this->name.c_str(), AT_REMOVEDIR);
  }
}

NamedTempFile::NamedTempFile() {
  int fd;
  std::string path;
  std::tie(fd, path) = make_temp_file();
  file = fdopen(fd, "wb");
  VERIFY(file != NULL);
  name = std::move(path);
}

NamedTempFile::NamedTempFile(TempDir& dir) {
  int fd;
  std::string path;
  std::tie(fd, path) = make_temp_file(dir.path());
  file = fdopen(fd, "wb");
  VERIFY(file != NULL);
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
  VERIFY(file != NULL);
  unlink(path.c_str());
}

TempFile::TempFile(TempDir& dir) {
  std::string path;
  int fd;

  std::tie(fd, path) = make_temp_file(dir.path());
  file = fdopen(fd, "wb");
  VERIFY(file != NULL);
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

TempPath::TempPath(const string& scoped) { this->name = scoped; }
