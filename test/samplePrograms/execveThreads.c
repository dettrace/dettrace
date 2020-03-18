
#include <sched.h>
#include <errno.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <time.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <pthread.h>

#define STACK_SIZE (1024 * 1024)

const int bytesToRead = 100;
const int bytesToWrite = 100;
int pipefd[2];
// Process spawns thread with clone().
// Thread blocks trying to read from a pipe.
// Can the process still exit?
int thread_func(void *arg){
  printf("Thread wants to read from pipe.\n");
  char buf[bytesToRead];
  int bytes = read(pipefd[0], buf, bytesToRead);
  return 0;
}

int other_func(void *arg){
  printf("Special thread triggering execve.\n");
  char* args[] = {"ls", NULL};
  execvp("ls", args);
  printf("failed to execve! Reason: %s", strerror(errno));
  _exit(EXIT_SUCCESS);
}

int main(void){
  printf("Process - my pid is: %d\n", getpid());
  printf("Process - my ppid is: %d\n", getppid());

  int ret = pipe(pipefd);
  if(ret != 0){
    printf("Pipe errored.\n");
    exit(1);
  }

  pthread_t threads[10];
  int t[10];
  for(int i = 0; i < 9; i++){
    //void* child_stack = malloc(STACK_SIZE);
    //int thread_pid;
    printf("Creating new thread.\n");
    //thread_pid = clone(thread_func, child_stack+STACK_SIZE, CLONE_VM|CLONE_FS|CLONE_FILES|CLONE_SIGHAND|CLONE_THREAD|CLONE_SYSVSEM|CLONE_SETTLS|CLONE_PARENT_SETTID|CLONE_CHILD_CLEARTID, NULL);
    t[i] = pthread_create(&threads[i], NULL, thread_func, NULL);
  }

  //void* child_stack = malloc(STACK_SIZE);
  //int thread_pid;
  printf("Creating special thread.\n");
  //thread_pid = clone(other_func, child_stack+STACK_SIZE, CLONE_VM|CLONE_FS|CLONE_FILES|CLONE_SIGHAND|CLONE_THREAD|CLONE_SYSVSEM|CLONE_SETTLS|CLONE_PARENT_SETTID|CLONE_CHILD_CLEARTID, NULL);
  t[9] = pthread_create(&threads[9], NULL, other_func, NULL);
  
  for(int i = 0; i < 10; i++){
    pthread_join(threads[i], NULL);
  }
  exit(EXIT_SUCCESS);
}
