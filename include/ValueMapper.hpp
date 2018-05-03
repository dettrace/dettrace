#ifndef VALUE_MAPPER_H
#define VALUE_MAPPER_H

#include <map>
#include "logger.hpp"

/**
 * Simple wrapper around std::map for virtualizing values like inodes.
 * Template parameter T must be an integral type.
 */
template <typename Real, typename Virtual>
class ValueMapper {
protected:
  // I would ideally like to type alias real values to virtual values from int and have
  // the compiler enforce them through type errors. But it seems like C++ doesn't support
  // that unless I use phantom types and wrapper classes...

  // Tables to keep track of mappings.
  std::map<Virtual, Real> virtualToRealValue;
  std::map<Real, Virtual> realToVirtualValue;
  Virtual freshValue;
  logger& myLogger;
  const std::string mappingName;

public:
  /**
   * Constructor. Takes in logger for writing data and name of this mapping.
   * @myLogger: initialized logger to write data to.
   * @name: name of this mapping for debugging.
   */
  ValueMapper(logger& logr, std::string name, Virtual startingValue) :
    myLogger(logr),
    mappingName(name) {
    freshValue = startingValue;
  }

  /**
   * Given a real value, add it to our mapping tables and map it to a fresh new virtual value.
   * @param realValue: realValue to add. Assumed to be unique.
   * @return virtualValue: a fresh new virtual value.
   */
  virtual Virtual addRealValue(Real realValue) {
    if(realToVirtualValue.find(realValue) != realToVirtualValue.end()){
      throw runtime_error("Attempting to add already existing key: " + to_string(realValue));
    }
    myLogger.writeToLog(Importance::info, mappingName + ": Added mapping: " +
                        to_string(realValue) + " -> " + to_string(freshValue));

    Virtual vValue = freshValue;
    realToVirtualValue[realValue] = vValue;
    virtualToRealValue[vValue] = realValue;
    freshValue++;
    return vValue;
  }

  /**
   * Get the real value of a process from our @valueMappingTable based on the virtual value.
   * @param virtualValue: virtual value of process.
   * @return realValue: real value. Throws if it doesn't exist.
   */
  Real getRealValue(Virtual virtualValue) {
    // does element exist?
    if (virtualToRealValue.find(virtualValue) != virtualToRealValue.end()) {
      Real realValue = virtualToRealValue[virtualValue];
      myLogger.writeToLog(Importance::info, mappingName + "getRealValue(" +
                          to_string(virtualValue) + ") = " + to_string(realValue) +
                          "\n");
      return realValue;
    }
    throw runtime_error(mappingName + ": getRealValue(" +
                        to_string(virtualValue) + ") does not exist\n");
  }

  /**
   * Get the virtual value from the real value. This assumes the value has already been added
   * through @addRealValue.
   * @param realValue: real value of process.
   * @return virtualValue: real value. Throws if it doesn't exist.
   */
  Virtual getVirtualValue(Real realValue) {
    if (realToVirtualValue.find(realValue) != realToVirtualValue.end()) {
      Virtual virtValue = realToVirtualValue[realValue];
      myLogger.writeToLog(Importance::info, mappingName + "getVirtualValue(" +
                          to_string(realValue) + ") = " + to_string(virtValue) +
                          "\n");
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
  bool realValueExists(Real realValue) {
    bool keyExists = realToVirtualValue.find(realValue) != realToVirtualValue.end();
    return keyExists;
  }

  /**
   * Check if virtual value is already in map for virtual values.
   * @realValue: virtual value to check for.
   * @return bool: true if virtual value already exists in @virtualToRealValue.
   */
  bool virtualValueExists(Virtual virtualValue) {
    bool keyExists = virtualToRealValue.find(virtualValue) != virtualToRealValue.end();
    return keyExists;
  }
};


#endif
