#ifndef VALUE_MAPPER_H
#define VALUE_MAPPER_H

#include <map>
#include "logger.hpp"

/**
 * Simple wrapper around std::map for virtualizing values like inodes. 
 * Template parameter T must be an integral type.
 */
template <class T>
class ValueMapper {
private:
  // I would ideally like to type alias real values to virtual values from int and have
  // the compiler enforce them through type errors. But it seems like C++ doesn't support
  // that unless I use phantom types and wrapper classes...

  // Tables to keep track of mappings.
  std::map<T, T> virtualToRealValue;
  std::map<T, T> realToVirtualValue;
  T freshValue;
  logger& myLogger;
  const std::string mappingName;

public:
  /**
   * Constructor. Takes in logger for writing data and name of this mapping.
   * @myLogger: initialized logger to write data to.
   * @name: name of this mapping for debugging.
   */
  ValueMapper(logger& logr, std::string name) :
    myLogger(logr),
    mappingName(name) {
    freshValue = 1;
  }

  /**
   * Given a real value, add it to our mapping tables and map it to a fresh new virtual value.
   * @param realValue: realValue to add. Assumed to be unique.
   * @return virtualValue: a fresh new virtual value.
   */
  T addRealValue(T realValue) {
    myLogger.writeToLog(Importance::info, "%s: Added mapping %d -> %d\n",  mappingName.c_str(),
                        realValue, freshValue);
    
    T vValue = freshValue;
    realToVirtualValue[realValue] = vValue;
    virtualToRealValue[vValue] = realValue;
    freshValue++;
    return vValue;
  }

  /**
   * Get the real value of a process from our @valueMappingTable based on the virtual value.
   * OSNL: TODO The virtual value is assumed to exist?
   * @param virtualValue: virtual value of process.
   * @return realValue: real value. Throws if it doesn't exist.
   */
  T getRealValue(T virtualValue) {
    // does element exist?
    if (virtualToRealValue.find(virtualValue) != virtualToRealValue.end()) {
      T realValue = virtualToRealValue[virtualValue];
      myLogger.writeToLog(Importance::info, "%s: getRealValue(%d) = %d\n", mappingName.c_str(),
                          virtualValue, realValue);
      return realValue;
    }    
    throw runtime_error(mappingName + ": getRealValue(" +
                        to_string(virtualValue) + ") does not exist\n");
  }

  /**
   * Get the virtual value from the real value. This assumes the value has already been added
   * through @addEntryValue.
   * @param realValue: real value of process.
   * @return virtualValue: real value. Throws if it doesn't exist.
   */
  T getVirtualValue(T realValue) {
    if (realToVirtualValue.find(realValue) != realToVirtualValue.end()) {
      T virtValue = realToVirtualValue[realValue];
      myLogger.writeToLog(Importance::info, "%s: getVirtualValue(%d) = %d\n", mappingName.c_str(),
                          realValue, virtValue);
      return virtValue;
    }
    throw runtime_error(mappingName + ": getVirtualValue(" +
                        to_string(realValue) + ") does not exist\n");
  }

  /**
   * Check if real value is already in map for real values.
   * @realValue: real value to check for.
   * @return bool: true if real value already exists in @realToVirtualValue.
   */
  bool realValueExists(T realValue) {
    bool keyExists = realToVirtualValue.find(realValue) != realToVirtualValue.end();
    return keyExists;
  }
  
  /**
   * Check if virtual value is already in map for virtual values.
   * @realValue: virtual value to check for.
   * @return bool: true if virtual value already exists in @virtualToRealValue.
   */
  bool virtualValueExists(T virtualValue) {
    bool keyExists = virtualToRealValue.find(virtualValue) != virtualToRealValue.end();
    return keyExists;
  }
};

#endif
