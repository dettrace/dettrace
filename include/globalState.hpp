#ifndef GLOBAL_STATE_H
#define GLOBAL_STATE_H

#include "ValueMapper.hpp"

/**
 * Class to hold global state shared among all processes, this includes the logger, inode
 * mappings, modified time mappings.
 */
class globalState{
public:
  /**
   * Constructor.
   * @param log global program log
   * @param inodeMap map of inodes and virtual nodes
   * @param mtimeMap map of inode to modification times
   */
  globalState(logger& log, ValueMapper<ino_t, ino_t> inodeMap,
              ValueMapper<ino_t, time_t> mtimeMap);

  /**
   * Isomorphism between inodes and virtual inodes.
   */
  ValueMapper<ino_t, ino_t> inodeMap;

  /**
   * Tracker of modification times.
   */
  ValueMapper<ino_t, time_t> mtimeMap;

  /**
   * Reference to our global program logger.
   */
  logger& log;


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
   * Not as interest as "reads" from open urandom, but this is the best we can do.
   * As we don't keep track of which fds map to which files.
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
   * Counter for keeping track of number of replays including replays due to blocking.
   */
  uint32_t totalReplays = 0;

  /**
   * Counter for keeping track of injected system calls
   */
  uint32_t injectedSystemCalls = 0;
};

#endif
