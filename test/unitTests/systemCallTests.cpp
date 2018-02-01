#include "catch.hpp"

#include <stdio.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdint.h>
#include <sys/user.h>
#include <sys/vfs.h>
#include <sys/ptrace.h>
#include <sys/reg.h>     /* For constants ORIG_EAX, etc */
#include <string.h>
#include <sys/wait.h>
#include <sys/syscall.h>    /* For SYS_write, etc */

#include <sys/time.h>
#include <sys/resource.h>

#include <tuple>
#include <unistd.h>
#include <sys/types.h>
#include <experimental/optional>
#include <climits>

using namespace std;
using namespace experimental;

/*
 * Do not run these tests directly from the executable! Use runTests.sh to run them!
 * Warning, please do not add tests "in the middle", only at the end, as the number
 * of ran tests determinies the value of our logical clock. Sorry about that.
 */

TEST_CASE("time system call", "time"){
  time_t tloc;
  syscall(SYS_time, &tloc);
  REQUIRE(64 == tloc);
}

TEST_CASE("statfs system call", "statfs"){
  struct statfs info;
  statfs("./", &info);

  REQUIRE(info.f_type == 0xEF53);
  REQUIRE(info.f_bsize == 100);
  REQUIRE(info.f_blocks == 1000);
  REQUIRE(info.f_bfree == 10000);
  REQUIRE(info.f_bavail == 5000);
  REQUIRE(info.f_files == 1000);
  REQUIRE(info.f_ffree == 1000);
  REQUIRE(info.f_fsid.__val[0] == 0);
  REQUIRE(info.f_fsid.__val[1] == 0);
  REQUIRE(info.f_namelen == 200);
  REQUIRE(info.f_frsize == 20);
  REQUIRE(info.f_flags == 1);
}

TEST_CASE("fstatfs system call", "statfs"){
  struct statfs info;
  int fd = open("./", O_RDONLY);
  fstatfs(fd, &info);

  REQUIRE(info.f_type == 0xEF53);
  REQUIRE(info.f_bsize == 100);
  REQUIRE(info.f_blocks == 1000);
  REQUIRE(info.f_bfree == 10000);
  REQUIRE(info.f_bavail == 5000);
  REQUIRE(info.f_files == 1000);
  REQUIRE(info.f_ffree == 1000);
  REQUIRE(info.f_fsid.__val[0] == 0);
  REQUIRE(info.f_fsid.__val[1] == 0);
  REQUIRE(info.f_namelen == 200);
  REQUIRE(info.f_frsize == 20);
  REQUIRE(info.f_flags == 1);
}

TEST_CASE("getpid simple case", "getpid"){
  pid_t p = getpid();
  REQUIRE(p == (pid_t) 1);
}

// Verify that starting program breakpoint is always deterministic.
TEST_CASE("starting program sbrk", "sbrk"){
  void* breakLocation = sbrk(0);
  // Hard to test, as this program grows, breakpoint moves.
  // REQUIRE(breakLocation == (void*)0x0000555555818000);
}

// FORK
// Catch does not support forking X(

TEST_CASE("getrusage", "getrusage"){
  struct rusage usage;
  getrusage(RUSAGE_SELF, &usage);

  REQUIRE(usage.ru_maxrss == LONG_MAX);
  REQUIRE(usage.ru_nsignals == LONG_MAX);
  REQUIRE(usage.ru_utime.tv_sec == 139);
}

TEST_CASE("getuid", "getuid"){
  uid_t uid = getuid();
  // Nobody
  REQUIRE(uid == 65534);
}

void statFamilyTests(struct stat statbuf){
  REQUIRE(statbuf.st_uid == 65534);
  REQUIRE(statbuf.st_dev == 1);
  REQUIRE(statbuf.st_blocks == 1);
  REQUIRE(statbuf.st_gid == 1);
}

TEST_CASE("stat", "stat"){
  struct stat statbuf;
  int ret = stat("./", &statbuf);
  statFamilyTests(statbuf);
  REQUIRE(statbuf.st_atim.tv_nsec == statbuf.st_atim.tv_sec);
  REQUIRE(statbuf.st_atim.tv_nsec == 169);
  REQUIRE(statbuf.st_atim.tv_sec == 169);
}


TEST_CASE("fstat", "fstat"){
  struct stat statbuf;
  int fd = open("./", O_RDONLY);
  int ret = fstat(fd, &statbuf);
  statFamilyTests(statbuf);
  REQUIRE(statbuf.st_atim.tv_nsec == statbuf.st_atim.tv_sec);
  REQUIRE(statbuf.st_atim.tv_nsec == 185);
  REQUIRE(statbuf.st_atim.tv_sec == 185);
}


TEST_CASE("lstat", "lstat"){
  struct stat statbuf;
  int ret = lstat("./", &statbuf);
  statFamilyTests(statbuf);
  REQUIRE(statbuf.st_atim.tv_nsec == statbuf.st_atim.tv_sec);
  REQUIRE(statbuf.st_atim.tv_nsec == 200);
  REQUIRE(statbuf.st_atim.tv_sec == 200);
}

 TEST_CASE("open", "/dev/urandom"){
   // TODO.
 }

TEST_CASE("prlimit64", "prlimit64"){
  // TODO
}

TEST_CASE("sysinfo", "sysinfo"){
  // TODO
}

TEST_CASE("utimensat", "utimensat"){
  // TODO
  // int fd = open("./test.txt", O_RDWR);
  // int dirfd = open("./", O_RDONLY);
  // const struct timespec times[2] = {timespec {}, {}};
  // utimensat(dirfd, "./test.txt", times, 0);
}
