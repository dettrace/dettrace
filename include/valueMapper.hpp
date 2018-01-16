#ifndef VALUE_MAPPER_H
#define VALUE_MAPPER_H

#include <map>
#include "logger.hpp"
/**
 * Simple wrapper around std::map for virtualizing values like pids and inodes.
 * Ideally we would have a value parameter over the type but it seems int is good enough
 * for now, no template needed.
 */
class valueMapper{
private:
  // I would ideally like to type alias real values to virtual values from int and have
  // the compiler enforce them through type errors. But it seems like C++ doesn't support
  // that unless I use phantom types and wrapper classes...

  // Tables to keep track of mappings.
  std::map<int, int> virtualToRealValue;
  std::map<int, int> realToVirtualValue;
  int freshValue;
  logger& myLogger;
  const std::string mappingName;
public:
  /**
   * Given a value, add it to our mapping tables and map it to a fresh new virtual value.
   * @param realValue: realValue to add. Assumed to be unique.
   * @return virtualValue: a fresh new virtual value.
   */
  int addEntryValue(int realValue);

  /**
   * Get the real value of a process from our @valueMappingTable based on the virtual value.
   * OSNL: TODO The virtual value is assumed to exist?
   * @param virtualValue: virtial value of process.
   * @return realValue: real value. Returns -1 if it doesn't exist.
   */
  int getRealValue(int virtualValue);

  /**
   * Get the virtual value from the real value. This assumes the value has already been added
   * through @addEntryValue.
   * @param realValue: real value of process.
   * @return virtualValue: real value. Returns -1 if it doesn't exist.
   */
  int getVirtualValue(int realValue);

  /**
   * Contructor. Takes in logger for writing data and name of this mapping.
   * @myLogger: initialized logger to write data to.
   * @name: name of this mapping for debuging.
   */
  valueMapper(logger& myLogger, std::string name);

  /**
   * Check if key is already in map for real values.
   * @realValue: real value to check for.
   * @return bool: true if key already exists in @realToVirtualValue.
   */
  bool realKeyExists(int realValue);

  /**
   * Check if key is already in map for virtual values.
   * @realValue: virtual value to check for.
   * @return bool: true if key already exists in @virtualToRealValue.
   */
  bool virtualKeyExists(int virtualValue);
};

#endif
