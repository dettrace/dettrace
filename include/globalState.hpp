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
};

#endif
