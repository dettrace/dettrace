#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>

int main(int argc, char* argv[])
{
  pid_t pid;

  if (argc > 1) {
    pid = fork();

    if (pid > 0) {
      int status;
      waitpid(pid, &status, 0);
    } else if (pid < 0) {
      fprintf(stderr, "fork failed: %s\n", strerror(errno));
      exit(1);
    } else {
      const char* exe = argv[0];
      char* const argv[] = { (char*)exe, NULL };
      char* const env[]  = { "PATH=/bin:/usr/bin", NULL };
      int rc = execve(exe, argv, env);
      if (rc != 0) {
        fprintf(stderr, "execve failed: %s\n", strerror(errno));
        exit(1);
      }
    }
  } else {
    char template[] ="/tmp/XXXXXXXX";
    int fd = mkstemp(template);
    printf("creating %s.\n", template);
    close(fd);
    unlink(template);
  }
  return 0;
}
