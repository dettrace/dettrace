#ifndef VALUE_MAPPER_H
#define VALUE_MAPPER_H

#include <unordered_map>
#include "logger.hpp"

using namespace std;

/**
 * Simple wrapper around std::map for virtualizing values like inodes.
 * Template parameter Virtual must be an integral type.
 */
template <typename Real, typename Virtual>
class ValueMapper {
protected:
  /**
   * I would ideally like to type alias real values to virtual values from int and have
   * the compiler enforce them through type errors. But it seems like C++ doesn't support
   * that unless I use phantom types and wrapper classes...
   */

  unordered_map<Virtual, Real> virtualToRealValue; /**< A mapping from Virtual to Real. */
  unordered_map<Real, Virtual> realToVirtualValue; /**< A mapping from Real to Virtual. */
  Virtual freshValue; /**< Next available Virtual value to be added to map. */
  logger& myLogger; /**< A logger. */
  const string mappingName; /**< String name of this map, useful for debugging. */

public:
  /**
   * Constructor.
   * Takes in logger for writing data, name of the mapping, and a starting virtual value.
   * @param logr initialized logger to write data to.
   * @param name string name of this mapping, useful for debugging.
   * @param startingValue initial Virtual value to start with.
   */
  ValueMapper(logger& logr, string name, Virtual startingValue) :
    myLogger(logr),
    mappingName(name) {
    freshValue = startingValue;
  }

  /**
   * Given a real value, add it to our mapping tables and map it to a fresh new virtual value.
   * Throws error if realValue already exists.
   * @param realValue: realValue to add. Assumed to be unique.
   * @return the mapped virtual value.
   */
  virtual Virtual addRealValue(Real realValue) {
    if(realToVirtualValue.find(realValue) != realToVirtualValue.end()){
      throw runtime_error("Attempting to add already existing key: " +
                          to_string(realValue) + "\n");
    }


    myLogger.writeToLog(Importance::info, mappingName + ": New virtual value added: " +
                        to_string(freshValue) + "\n");
    myLogger.writeToLog(Importance::extra,
                        "  (Real value was: " + to_string(realValue) + ")\n");

    Virtual vValue = freshValue;
    realToVirtualValue[realValue] = vValue;
    virtualToRealValue[vValue] = realValue;
    freshValue++;
    return vValue;
  }

  /**
   * Get the real value from the virtual value. 
   * Throws error if virtual value does not exist in map.
   * @param virtualValue virtual value of process.
   * @return real value that is mapped to the virtual one.
   */
  Real getRealValue(Virtual virtualValue) {
    // does element exist?
    if (virtualToRealValue.find(virtualValue) != virtualToRealValue.end()) {
      Real realValue = virtualToRealValue.at(virtualValue);
      myLogger.writeToLog(Importance::extra, mappingName + "getRealValue(" +
                          to_string(virtualValue) + ") = " + to_string(realValue) +
                          "\n");
      return realValue;
    }
    throw runtime_error(mappingName + ": getRealValue(" +
                        to_string(virtualValue) + ") does not exist\n");
  }

  /**
   * Get the virtual value from the real value.
   * Throws error if real value does not exist.
   * @param realValue real value of process.
   * @return virtual value that is mapped to the real one.
   */
  Virtual getVirtualValue(Real realValue) {
    if (realToVirtualValue.find(realValue) != realToVirtualValue.end()) {
      Virtual virtValue = realToVirtualValue.at(realValue);
      myLogger.writeToLog(Importance::info, mappingName + " fetched virtual value: " +
                          to_string(virtValue) + "\n");
      myLogger.writeToLog(Importance::extra, "  (Real value was: " +
                          to_string(realValue) +  ")\n");

      return virtValue;
    }
    throw runtime_error(mappingName + ": getVirtualValue(" +
                        to_string(realValue) + ") does not exist\n");
  }

  /**
   * Check if real value is already in map for real values.
   * @param realValue: real value to check for.
   * @return True if real value exists, otherwise False.
   */
  bool realValueExists(Real realValue) {
    bool keyExists = realToVirtualValue.find(realValue) != realToVirtualValue.end();
    myLogger.writeToLog(Importance::extra, mappingName + "realValueExists(" +
                        to_string(realValue) + ") = " + to_string(keyExists) + "\n");
    return keyExists;
  }

  /**
   * Check if virtual value is already in map for virtual values.
   * @param virtualValue virtual value to check for.
   * @return True if virtual value exists, otherwise False.
   */
  bool virtualValueExists(Virtual virtualValue) {
    bool keyExists = virtualToRealValue.find(virtualValue) != virtualToRealValue.end();
    myLogger.writeToLog(Importance::extra, mappingName + "realValueExists(" +
                        to_string(virtualValue) + ") = " + to_string(keyExists) + "\n");
    return keyExists;
  }

  /** 
   * Given a real value, erase the entry from the map.
   * Throws error if key does not exist in map.
   * @param key real value of the entry to be erased.
   */
  void eraseBasedOnKey(Real key){
    Virtual value;
    try{
      value = realToVirtualValue.at(key);
    }catch(...){
      throw runtime_error("Key does not exist in real to virtual map.\n");
    }

    // We know it's there. We just checked.
    realToVirtualValue.erase(key);
    auto res = virtualToRealValue.erase(value);
    if(res == 0){
      throw runtime_error("value does not exist in virtual to real map.\n");
    }
  }
};


#endif
