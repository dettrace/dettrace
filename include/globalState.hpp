#ifndef GLOBAL_STATE_H
#define GLOBAL_STATE_H

#include "ValueMapper.hpp"

/* Class to hold global state shared among all processes, this includes the logger, inode
 * mappings, modified time mappings.
 */
class globalState{
public:
  globalState(logger& log, ValueMapper<ino_t, ino_t> inodeMap,
              ValueMapper<ino_t, time_t> mtimeMap);

  /*
   * Isomorphism between inodes and vitual inodes.
   */
  ValueMapper<ino_t, ino_t> inodeMap;

  /*
   * Tracker of mtimes.
   */
  ValueMapper<ino_t, time_t> mtimeMap;

  /*
   * Reference to our global program logger.
   */
  logger& log;
};

#endif
