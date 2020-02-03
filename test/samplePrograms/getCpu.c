
#include <unistd.h>
#include <sys/syscall.h>
#include <stdio.h>

static inline int getcpu() {
    #ifdef SYS_getcpu
    int cpu, status;
    status = syscall(SYS_getcpu, &cpu, NULL, NULL);
    return (status == -1) ? status : cpu;
    #else
    return -1; // unavailable
    #endif
}

int main(){
  printf("Cpu %d\n", getcpu());
}
