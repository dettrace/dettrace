#ifndef GLOBAL_STATE_H
#define GLOBAL_STATE_H

#include <unordered_map>
#include <unordered_set>

#include "PRNG.hpp"
#include "ValueMapper.hpp"
#include "logicalclock.hpp"

/**
 * Mapping of inodes to modification times. When we observe the creation of an
 * inode, we add the current logical time to this map. We use this to keep track
 * of modification times for files in order to present a consistent view of
 * time.
 */
using ModTimeMap = std::unordered_map<ino_t, logical_clock::time_point>;

/**
 * Class to hold global state shared among all processes, this includes the
 * logger, inode mappings, modified time mappings.
 */
class globalState {
public:
  /**
   * Constructor.
   * @param log global program log
   * @param inodeMap map of inodes and virtual nodes
   * @param mtimeMap map of inode to modification times
   */
  globalState(
      logger& log,
      ValueMapper<ino_t, ino_t> inodeMap,
      ModTimeMap mtimeMap,
      bool kernelPre4_12,
      unsigned prngSeed,
      logical_clock::time_point epoch,
      bool allow_network = false);

  /**
   * Reference to our global program logger.
   */
  logger& log;

  /**
   * Isomorphism between inodes and virtual inodes.
   */
  ValueMapper<ino_t, ino_t> inodeMap;

  /**
   * Tracker of modification times.
   */
  ModTimeMap mtimeMap;

  /**
   * Using kernel version < 4.12 . 4.12 and above needed for CPUID.
   */
  bool kernelPre4_12;

  /**
   * A pseudorandom number generator to implement getrandom()
   */
  PRNG prng;

  /**
   * The number of microseconds since the Unix epoch. This is used as the
   * default value for file modification times if it doesn't exist in
   * `mtimeMap`.
   */
  logical_clock::time_point epoch;

  // Kept here as they're ticked up in the function hooks.
  /**
   * Counter for keeping track of total number of read retries.
   */
  uint32_t readRetryEvents = 0;

  /**
   * Counter for keeping track of total number of write retries.
   */
  uint32_t writeRetryEvents = 0;

  /**
   * Counter for keeping track of number of calls to getRandom.
   */
  uint32_t getRandomCalls = 0;

  /**
   * Counter for keeping track of number of open/openat to /dev/urandom
   * Not as interest as "reads" from open urandom, but this is the best we can
   * do. As we don't keep track of which fds map to which files.
   */
  uint32_t devUrandomOpens = 0;

  uint32_t devRandomOpens = 0;

  /**
   * Counter for keeping track of all time related calls
   */
  uint32_t timeCalls = 0;

  /**
   * Counter for keeping track of number of replays due to blocking events.
   */
  uint32_t replayDueToBlocking = 0;

  /**
   * Counter for keeping track of number of replays including replays due to
   * blocking.
   */
  uint32_t totalReplays = 0;

  /**
   * Counter for keeping track of injected system calls
   */
  uint32_t injectedSystemCalls = 0;

  /**
   * Keeps track of live threads in our program.
   */
  unordered_set<pid_t> liveThreads;

  /**
   * Keeps track of thread groups, each thread groups is composed of the threads
   * and the single parent process that belongs to that thread group. The
   * process will always be the last live member of a thread group as it cannot
   * exit until all it's threads and true process children have exited. When no
   * members are left, the threadGroup is deleted. The pid of the process is
   * used as the key into the multimap. Hence {(2, 2), (2, 3), (2, 4)} means for
   * thread group 2, process 2, thread 3, and thread 4 are members of this
   * thread group. (k, k) is always the process, and two different processes
   * cannot belong to the same thread group. Child processes of a process are
   * NOT included in the thread group, only threads are. A child process will
   * get it's own thread group.
   */
  unordered_multimap<pid_t, pid_t> threadGroups;

  /**
   * Map threadsGroups members back to their thread group.
   * Makes it easy to look up threads in threadGroups while only knowing their
   * tid/traceePid. Notice for processes their threadGroupNumber equals their
   * traceePid, we add them to the map anyways to avoid special cases for the
   * process owner vs threads.
   */
  unordered_map<pid_t, pid_t> threadGroupNumber;

  /**
   * Allow non-deterministic socket/networking
   */
  bool allow_network;

  /**
   * allow trap CPUID. this can be set to false
   * when arch_prctl(SET_CPUID) returned error
   * which can happen in old CPUs or in certain VM.
   */
  bool allow_trapCPUID;
};

#endif
