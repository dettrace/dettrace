#ifndef STATE_H
#define STATE_H

#include <sys/ptrace.h>
#include <sys/reg.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/vfs.h>

#include "ptracer.hpp"
#include "valueMapper.hpp"

using namespace std;

/**
 * Class to hold all state that we will need to update in between system calls inside the
 * tracer so far this includes:
 * Inodes Mappings.
 * PID Mappings.
 * Logical Clocks.
 * Logger.
 */
class state{
public:
  state(logger& log, pid_t myPid);

  /**
   * Logical clock. Ticks for every event: system call, signal, etc.
   */
  size_t clock = 0;

  // The pid of the process represented by this state.
  pid_t traceePid;

  // Virtual parent's process ID number. This is needed for consistency when children
  // ask for their parent's VPID. TODO: Not really implemented yet.
  int vppid = 1;

  // Isomorphism between pids to pids and back. Uses two hash tables.
  valueMapper pidMap;
  // Isomorphism between inodes and vitual inodes.
  valueMapper inodeMap;
  logger log;

  bool doSystemcall;

  // It's our job to keep track whether we are on a system call pre or post.
  syscallState syscallStopState = syscallState::pre;
};

#endif
