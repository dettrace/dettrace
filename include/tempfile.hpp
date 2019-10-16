#ifndef _MY_TEMPFILE_H
#define _MY_TEMPFILE_H

#include <assert.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <fstream>
#include <memory>
#include <string>
#include <tuple>

#if defined _WIN32
#define PATH_SEPERATOR '\\';
#else
#define PATH_SEPEARTOR '/';
#endif

class TempDir {
private:
  std::string name;
  pid_t owner_pid;
  bool mounted;

public:
  TempDir();
  TempDir(const std::string& prefix = "", bool doMount = false);
  std::string path(void) const { return name; }
  virtual ~TempDir();
};

class NamedTempFile {
private:
  FILE* file;
  std::string name;

public:
  NamedTempFile();
  NamedTempFile(TempDir& dir);
  NamedTempFile(const std::string& path);
  std::string path(void) const { return name; }

  unsigned long seek(unsigned long offset) {
    fseek(file, (long)offset, SEEK_SET);
    return ftell(file);
  }

  template <typename T>
  size_t read(T& to) {
    return fread(to, sizeof(to), 1, file);
  }

  template <typename T>
  size_t read(T* to, size_t size, size_t nmemb) {
    return fread(to, size, nmemb, file);
  }

  template <typename T>
  size_t write(T& to) {
    return fwrite(to, sizeof(to), 1, file);
  }

  template <typename T>
  size_t write(const T* to, size_t size, size_t nmemb) {
    return fwrite(to, size, nmemb, file);
  }

  virtual ~NamedTempFile() {
    fclose(file);
    unlink(name.c_str());
    name = "";
  }
};

class TempFile {
private:
  FILE* file;

public:
  TempFile();
  TempFile(TempDir& dir);

  unsigned long seek(unsigned long offset) {
    fseek(file, (long)offset, SEEK_SET);
    return ftell(file);
  }

  template <typename T>
  size_t read(T& to) {
    return fread(to, sizeof(to), 1, file);
  }

  template <typename T>
  size_t read(T* to, size_t size, size_t nmemb) {
    return fread(to, size, nmemb, file);
  }

  template <typename T>
  size_t write(T& to) {
    return fwrite(to, sizeof(to), 1, file);
  }

  template <typename T>
  size_t write(const T* to, size_t size, size_t nmemb) {
    return fwrite(to, size, nmemb, file);
  }

  virtual ~TempFile() { fclose(file); }
};

class TempPath {
private:
  std::string name;

public:
  TempPath();
  TempPath(TempDir& dir);
  TempPath(const std::string& scoped_path);
  std::string path(void) const { return name; }

  virtual ~TempPath() { unlink(name.c_str()); }
};

#endif
