#include "catch.hpp"
#include <sched.h>

#include <sys/utsname.h>
#include <sys/times.h>
#include <stdio.h>
#include <sys/types.h>
#include <utime.h>

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
#include <sys/sysinfo.h>
#include <sys/resource.h>

#include <iostream>
#include <tuple>
#include <unistd.h>
#include <sys/types.h>
#include <climits>

#include <linux/membarrier.h>

using namespace std;

/*
 * Do not run these tests directly from the executable! Use runTests.py to run them!
 * Warning, please do not add tests "in the middle", only at the end, as the number
 * of ran tests determinies the value of our logical clock. Sorry about that.
 */

TEST_CASE("time system call", "time"){
  time_t tloc;
  syscall(SYS_time, &tloc);
  REQUIRE(744847200 == tloc);
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
  REQUIRE(p == (pid_t) 2);
}

// Verify that starting program breakpoint is always deterministic.
TEST_CASE("starting program sbrk", "sbrk"){
  void* breakLocation = sbrk(0);
  // Hard to test, as this program grows, breakpoint moves.
  // REQUIRE(breakLocation == (void*)0x0000555555818000);
}

// FORK
// Catch does not support forking X(
// Instead we test fork through our ../samplePrograms

TEST_CASE("getrusage", "getrusage"){
  struct rusage usage;
  getrusage(RUSAGE_SELF, &usage);

  REQUIRE(usage.ru_maxrss == LONG_MAX);
  REQUIRE(usage.ru_nsignals == LONG_MAX);
  REQUIRE(usage.ru_utime.tv_usec == 12);
}

TEST_CASE("getuid", "getuid"){
  uid_t uid = getuid();
  // We're uid 0
  REQUIRE(uid == 0);
}

void statFamilyTests(struct stat statbuf){
  CHECK(statbuf.st_uid == 0);
  CHECK(statbuf.st_dev == 1);

  // FIXME: Definite portability problem
  CHECK(statbuf.st_ino >= 8); // 8 on Azure Devops [2020.02.19], e.g.:
                              // https://dev.azure.com/dettrace/dettrace/_build/results?buildId=459&view=logs&j=12f1170f-54f2-53f3-20dd-22fc7dff55f9&t=bd05475d-acb5-5619-3ccb-c46842dbc997
  CHECK(statbuf.st_ino <= 9); // 9 on ubuntu 18.04 local machine
  CHECK(statbuf.st_blksize == 512);
  CHECK(statbuf.st_blocks == 1);
  CHECK(statbuf.st_gid == 0);


  // CHECK(749999999 == statbuf.st_mtim.tv_nsec);
  // CHECK(749999999 == statbuf.st_mtim.tv_nsec);
  // CHECK(749999999 == statbuf.st_ctim.tv_nsec);
  // CHECK(749999999 == statbuf.st_ctim.tv_nsec);

  // CHECK(6917529027641081855 == statbuf.st_mtim.tv_sec);
  // CHECK(6917529027641081855 == statbuf.st_atim.tv_sec);
  // CHECK(6917529027641081855 == statbuf.st_ctim.tv_sec);
  // CHECK(6917529027641081855 == statbuf.st_atim.tv_sec);
}

TEST_CASE("stat", "stat"){
  struct stat statbuf;
  std::remove("test_temp.txt");
  // Create new file to verify it has the newest filestamp possible.
  system("touch test_temp.txt");

  int ret = stat("test_temp.txt", &statbuf);
  statFamilyTests(statbuf);
}


TEST_CASE("fstat", "fstat"){
  struct stat statbuf;

  int fd = open("test_temp.txt", O_RDONLY);
  int ret = fstat(fd, &statbuf);
  if(ret == -1){
    std::remove("test_temp.txt");
    REQUIRE(false);
  }

  statFamilyTests(statbuf);
}


TEST_CASE("lstat", "lstat"){
  struct stat statbuf;

  int ret = lstat("./test_temp.txt", &statbuf);
  statFamilyTests(statbuf);
  std::remove("test_temp.txt");
}

TEST_CASE("open", "/dev/urandom"){
   // TODO.
}

TEST_CASE("prlimit64", "prlimit64"){
  // joe: can't compile a prlimit test on acggrid, I get:
  // "error: 'SYS_prlimit' was not declared in this scope"

  // list of all resources per https://linux.die.net/man/2/prlimit
  const int RESOURCE[] = {
    RLIMIT_AS, RLIMIT_CORE, RLIMIT_CPU, RLIMIT_DATA,
    RLIMIT_FSIZE, RLIMIT_LOCKS, RLIMIT_MEMLOCK, RLIMIT_MSGQUEUE,
    RLIMIT_NICE, RLIMIT_NOFILE, RLIMIT_NPROC, RLIMIT_RSS,
    RLIMIT_RTPRIO, RLIMIT_RTTIME, RLIMIT_SIGPENDING, RLIMIT_STACK
  };
  struct rlimit limits;
  for (unsigned i = 0; i < sizeof(RESOURCE)/sizeof(RESOURCE[0]); i++) {
    syscall(SYS_prlimit64, 0, RESOURCE[i], nullptr, &limits);
    INFO("resource=" << RESOURCE[i] << " i=" << i << " &limits=" << &limits);

    // TODO
    // REQUIRE(RLIM_INFINITY == limits.rlim_cur);
    // REQUIRE(RLIM_INFINITY == limits.rlim_max);
  }
}

TEST_CASE("sysinfo", "sysinfo"){
  struct sysinfo info;
  sysinfo(&info);
  REQUIRE(info.uptime == 365LL * 24 * 3600);
  REQUIRE(info.totalram == 32ULL << 32);
  REQUIRE(info.freehigh == 0);
  REQUIRE(info.loads[2] == 65536);
  REQUIRE(info.sharedram == 1ULL << 30);
  REQUIRE(info.totalswap == 0);
  REQUIRE(info.procs == 256);
  REQUIRE(info.freeswap == 0);

}

TEST_CASE("utimensat", "utimensat"){
  // Huh, it's actually impossible to check if the timestamp is working
  // as a unit test since we cannot stat the timestamps!
  // int fd = open("./test.txt", O_RDWR);
  // futimens(fd, nullptr);
}

TEST_CASE("uname", "uname"){
  struct utsname buf;
  int ret = uname(&buf);
  REQUIRE(ret == 0);
  REQUIRE(strcmp(buf.sysname, "Linux") == 0);
  REQUIRE(strcmp(buf.nodename,"") == 0);
  REQUIRE(strcmp(buf.release, "4.0") == 0);
  REQUIRE(strcmp(buf.version, "#1") == 0);
  REQUIRE(strcmp(buf.machine, "x86_64") == 0);

#ifdef _GNU_SOURCE
  REQUIRE(strcmp(buf.domainname, "") == 0);
#endif
}

TEST_CASE("utime", "utime"){
  char* test = (char*)"utimeTestFile.txt";
  std::remove("utimeTestFile.txt");
  system("touch utimeTestFile.txt");
  if(-1 == utime(test, NULL)){
    REQUIRE(false);
  }

  // Verify timestamp is zero:
  struct stat myStat;
  if(-1 == stat(test, &myStat)){
    std::remove("utimeTestFile.txt");
    REQUIRE(false);
  }
  std::remove("utimeTestFile.txt");

  REQUIRE(myStat.st_atim.tv_sec == 744847200);
  REQUIRE(myStat.st_atim.tv_nsec == 0);
  REQUIRE(myStat.st_mtim.tv_sec == 744847200);
  REQUIRE(myStat.st_mtim.tv_nsec == 999);
}

TEST_CASE("uid/gid", "uid/gid"){
  // Nobody.
  REQUIRE(getegid() == 0);
  REQUIRE(getgid() == 0);
  REQUIRE(geteuid() == 0);
  REQUIRE(getpgrp() == 0);
}

TEST_CASE("times", "times"){
  struct tms buf;
  clock_t time = times(&buf);
  // Nobody.
  REQUIRE(time == 744847200000038);
  REQUIRE(buf.tms_utime == 0);
  REQUIRE(buf.tms_stime == 0);
  REQUIRE(buf.tms_cutime == 0);
  REQUIRE(buf.tms_cstime == 0);
}


static int membarrier(int cmd, int flags)
{
    return syscall(__NR_membarrier, cmd, flags);
}

TEST_CASE("membarrier", "membarrier"){
  int support = membarrier(MEMBARRIER_CMD_QUERY, 0);
  REQUIRE( support >= 0 );  
  REQUIRE( (support & MEMBARRIER_CMD_SHARED) == MEMBARRIER_CMD_SHARED);
  membarrier(MEMBARRIER_CMD_SHARED, 0);
    
  // CMD_GLOBAL is quite new and would require we increase our kernel lower bound:
  // REQUIRE( support & MEMBARRIER_CMD_GLOBAL == MEMBARRIER_CMD_GLOBAL);
  // membarrier(MEMBARRIER_CMD_GLOBAL, 0);  
}

