#include <assert.h>
#include <errno.h>
#include <inttypes.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/reg.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/syscall.h>
#include <sys/sysinfo.h>
#include <sys/time.h>
#include <sys/times.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include <utime.h>
#include <wait.h>

/*
This is a small ptrace implementation that validates that structs have the same
size from the point of view of the tracee and that of ptrace, i.e., that going
through libc does not change struct layout or contents.

We validate size by writing a unique pattern into the struct from the tracee,
and then validate that we see the expected pattern (across the size of the
struct) from ptrace.

Since we treat the struct as a bag of bytes, we don't know if here was some
size-preserving change of fields, e.g., the tracee sees two `uint32_t` fields
but the kernel sees one `uint64_t` field. Testing for the contents of each field
would be a lot more effort, and doesn't seem necessary.

We have added tests for all of the structs read/written by DetTrace. This
validates a discrepancy in the definition of `struct sigaction` - libc converts
the tracee representation into a very different one for the kernel.
*/


pid_t childPid;

int doWithCheck(int returnValue, char* errorMessage){
  char* whyError = strerror(errno);
  if (returnValue == -1){
    fprintf(stderr, "%s failed: %s\n", errorMessage, whyError);
  }
  return returnValue;
}

// fill the given memory region with increasing nibble values (1, 2, 3, ...)
void increasingNibbles(const bool write, void* start, const uint32_t length) {

  bool valid = true;
  uint8_t* p = (uint8_t*) start;
  uint8_t nibbleValue = 0x1;
  
  for (uint32_t i = 0; i < length; i++) {
    uint8_t value = (nibbleValue << 4);

    nibbleValue += 1;
    if (nibbleValue > 0x0f) {
      nibbleValue = 0x01;
    }
    value |= (nibbleValue & 0x0f);
    nibbleValue += 1;
    if (nibbleValue > 0x0f) {
      nibbleValue = 0x01;
    }

    if (write) {
      p[i] = value;
      
    } else {
      // NB: read from tracee
      long traceeWord = ptrace(PTRACE_PEEKDATA, childPid, &p[i], NULL);
      uint8_t traceeByte = traceeWord & 0x00FF;
      if (traceeByte != value) {
        valid = false;
      }
    }
  }

  if (!write) {
    if (valid) {
      printf("    passed validation!\n");
      
    } else {
      printf("VALIDATION FAILED: actual buffer contents: ");
      for (uint32_t i = 0; i < length; i++) {
        printf("%02x", p[i]);
      }
      printf("\n");
    }
  }
  
}

void dochild() {
  doWithCheck(ptrace(PTRACE_TRACEME, 0, NULL, NULL), "PTRACE_TRACEME");
  kill(getpid(), SIGSTOP);

  {
    struct sigaction sa = {0};
    increasingNibbles(true, &sa, sizeof(struct sigaction));
    //increasingNibbles(false, &sa, sizeof(struct sigaction));
    doWithCheck(sigaction(SIGALRM, &sa, NULL),"sigaction");
  }
  {
    struct itimerval itv = {0};
    increasingNibbles(true, &itv, sizeof(struct itimerval));
    doWithCheck(getitimer(ITIMER_REAL, &itv), "getitimer");
  }
  {
    timer_t timerid;
    struct sigevent se = {0};
    increasingNibbles(true, &se, sizeof(struct sigevent));
    int rv = timer_create(CLOCK_REALTIME, &se, &timerid);
    assert(-1 == rv && EINVAL == errno);
  }
  {
    timer_t timerid;
    struct sigevent se = {0};
    se.sigev_notify = SIGEV_NONE;
    int rv = timer_create(CLOCK_REALTIME, &se, &timerid);
    struct itimerspec its = {0};
    increasingNibbles(true, &its, sizeof(struct itimerspec));
    doWithCheck(timer_gettime(timerid, &its), "timer_gettime");
  }
  {
    struct stat st = {0};
    increasingNibbles(true, &st, sizeof(struct stat));
    doWithCheck(stat("/etc", &st), "stat");
  }
  {
    struct statfs st = {0};
    increasingNibbles(true, &st, sizeof(struct statfs));
    doWithCheck(statfs("/etc", &st), "statfs");
  } 
  {
    struct timespec ts = {0};
    increasingNibbles(true, &ts, sizeof(struct timespec));
    doWithCheck(clock_getres(CLOCK_REALTIME, &ts), "clock_getres");
  }
  {
    struct timeval tv = {0};
    increasingNibbles(true, &tv, sizeof(struct timeval));
    doWithCheck(settimeofday(&tv, NULL), "settimeofday");
  }
  {
    struct rusage ru = {0};
    increasingNibbles(true, &ru, sizeof(struct rusage));
    doWithCheck(getrusage(RUSAGE_SELF, &ru), "getrusage");
  }
  {
    struct sysinfo si = {0};
    increasingNibbles(true, &si, sizeof(struct sysinfo));
    doWithCheck(sysinfo(&si), "sysinfo");
  }
  {
    struct utsname uts = {0};
    increasingNibbles(true, &uts, sizeof(struct utsname));
    doWithCheck(uname(&uts), "uname");
  }
  {
    struct tms t = {0};
    increasingNibbles(true, &t, sizeof(struct tms));
    doWithCheck(times(&t), "times");
  }
  {
    struct utimbuf ut = {0};
    increasingNibbles(true, &ut, sizeof(struct utimbuf));
    doWithCheck(utime("/etc/mtab", &ut), "utime");
  }
  /*
  {
    struct ;
    increasingNibbles(true, &, sizeof(struct ));
    doWithCheck(, "");    
  }
*/
  /*
  {
    char buf[30];
    increasingNibbles(true, &buf, sizeof(buf));
    doWithCheck(read(0, buf, sizeof(buf)), "read");
  }

  {
    char buf[30];
    increasingNibbles(true, &buf, sizeof(buf));
    doWithCheck(write(1, buf, sizeof(buf)), "write");
  }
  */

}

/*
int wait_for_syscall(pid_t child) {
  int status;
  while (1) {
    ptrace(PTRACE_SYSCALL, child, 0, 0);
    waitpid(child, &status, 0);
    if (WIFSTOPPED(status) && WSTOPSIG(status) & 0x80)
      return 0;
    if (WIFEXITED(status))
      return 1;
  }
}
*/

int main() {

  childPid = fork();
  
  if (0 == childPid) {
    dochild();
    exit(0);
  }

  // parent code
  int wstatus, rv;

  doWithCheck(waitpid(childPid, &wstatus, 0), "initial waitpid");
  rv = ptrace(PTRACE_SETOPTIONS, childPid, NULL, (void*)
              (PTRACE_O_EXITKILL | // If Tracer exits. Send SIGKIll signal to all tracees.
               PTRACE_O_TRACECLONE | // enroll child of tracee when clone is called.
               // We don't really need to catch execves, but we get a spurious signal 5
               // from ptrace if we don't.
               PTRACE_O_TRACEEXEC |
               PTRACE_O_TRACEFORK |
               PTRACE_O_TRACEVFORK |
               // Stop tracee right as it is about to exit. This is needed as we cannot
               // assume WIFEXITED will work, see man ptrace 2.
               PTRACE_O_TRACEEXIT |
               PTRACE_O_TRACESYSGOOD) );
  doWithCheck(rv, "PTRACE_SETOPTIONS");

  bool syscallEnter = true;

  while (true) {

    /* if (wait_for_syscall(childPid) != 0) break; */

    /* doWithCheck(ptrace(PTRACE_GETREGS, childPid, NULL, &regs), "PTRACE_GETREGS"); */
    
    /* //long syscall = ptrace(PTRACE_PEEKUSER, childPid, sizeof(long)*ORIG_EAX); */
    /* printf("syscall(%ld) = ", regs.orig_rax); */

    /* if (wait_for_syscall(childPid) != 0) break; */

    /* //long retval = ptrace(PTRACE_PEEKUSER, childPid, sizeof(long)*EAX); */
    /* doWithCheck(ptrace(PTRACE_GETREGS, childPid, NULL, &regs), "PTRACE_GETREGS"); */
    /* printf("%ld\n", regs.rax); */

    doWithCheck(ptrace(PTRACE_SYSCALL, childPid, 0, 0), "PTRACE_SYSCALL");
    doWithCheck(waitpid(childPid, &wstatus, 0), "waitpid");
    
    if (WIFEXITED(wstatus)) {
      printf("tracee exited with status %d\n", WEXITSTATUS(wstatus));
      break;
    }
    if (WIFSIGNALED(wstatus)) {
      printf("tracee exited due to signal %d\n", WTERMSIG(wstatus));
      break;
    }
    
    struct user_regs_struct regs;
    doWithCheck(ptrace(PTRACE_GETREGS, childPid, NULL, &regs), "PTRACE_GETREGS");
    
    if (WIFSTOPPED(wstatus) && WSTOPSIG(wstatus) & 0x80) { // syscall
      
      if (!syscallEnter) {
        printf("    tracee syscall returning %lld\n", regs.rax);
        syscallEnter = !syscallEnter;
        continue;
      }
      syscallEnter = !syscallEnter;

      switch (regs.orig_rax) {
      case SYS_rt_sigaction:
        printf("tracee performing rt_sigaction\n");
        increasingNibbles(false, (void*)regs.rsi, sizeof(struct sigaction));
        break;
      case SYS_getitimer:
        printf("tracee performing getitimer\n");
        increasingNibbles(false, (void*)regs.rsi, sizeof(struct itimerval));
        break;
      case SYS_timer_create: {
        printf("tracee performing timer_create\n");
        // TODO: check sigev_notify == SIGEV_NONE, code below doesn't quite work
        long w = ptrace(PTRACE_PEEKDATA, childPid, (void*)regs.rsi, NULL);
        int i = (int) w;
        if (SIGEV_NONE == i) {
          printf("    allowing timer_create() through\n");
          continue;
        } else {
          increasingNibbles(false, (void*)regs.rsi, sizeof(struct sigevent));
        }
        break;
      }
      case SYS_timer_gettime:
        printf("tracee performing timer_gettime\n");
        increasingNibbles(false, (void*)regs.rsi, sizeof(struct itimerspec));
        break;
      case SYS_stat:
        printf("tracee performing stat\n");
        increasingNibbles(false, (void*)regs.rsi, sizeof(struct stat));
        break;
      case SYS_statfs:
        printf("tracee performing statfs\n");
        increasingNibbles(false, (void*)regs.rsi, sizeof(struct statfs));
        break;
      case SYS_clock_getres:
        printf("tracee performing clock_getres\n");
        increasingNibbles(false, (void*)regs.rsi, sizeof(struct timespec));
        break;
      case SYS_settimeofday:
        printf("tracee performing settimeofday\n");
        increasingNibbles(false, (void*)regs.rdi, sizeof(struct timeval));
        break;
      case SYS_getrusage:
        printf("tracee performing getrusage\n");
        increasingNibbles(false, (void*)regs.rsi, sizeof(struct rusage));
        break;
      case SYS_sysinfo:
        printf("tracee performing sysinfo\n");
        increasingNibbles(false, (void*)regs.rdi, sizeof(struct sysinfo));
        break;
      case SYS_uname:
        printf("tracee performing uname\n");
        increasingNibbles(false, (void*)regs.rdi, sizeof(struct utsname));
        break;
      case SYS_times:
        printf("tracee performing times\n");
        increasingNibbles(false, (void*)regs.rdi, sizeof(struct tms));
        break;
      case SYS_utime:
        printf("tracee performing utime\n");
        increasingNibbles(false, (void*)regs.rsi, sizeof(struct utimbuf));
        break;

        
        /*
      case SYS_read:
        printf("tracee performing read\n");
        increasingNibbles(false, (void*)regs.rsi, regs.rdx);
        // suppress the read call
        regs.rdx = 0;
        break;
      case SYS_write:
        printf("tracee performing write\n");
        increasingNibbles(false, (void*)regs.rsi, regs.rdx);
        // suppress the write call
        regs.rdx = 0;
        break;
        */

        // allow some system calls through
      case SYS_write:
      case SYS_brk:
      case SYS_exit_group:
        continue;
      default:
        printf("tracee performing unknown syscall %llu, letting it through\n", regs.orig_rax);
        continue;
      }

      // convert syscall to nop: getpid 
      regs.rax = SYS_getpid;
      //regs.rax = SYS_alarm;
      //regs.rdi = 0;
      doWithCheck(ptrace(PTRACE_SETREGS, childPid, NULL, &regs), "PTRACE_SETREGS");
    }
    
  } // end while

  
  return 0;
}
