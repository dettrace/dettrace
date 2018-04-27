#ifndef MTIME_MAPPER_H
#define MTIME_MAPPER_H

#include <cstdint>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <limits.h>

#include <map>
#include <string>
#include <algorithm>
#include <memory>
#include <vector>
#include <time.h>

#include <map>
#include "logger.hpp"
#include "util.hpp"


using namespace std;


// This class implements deterministic, relative times. That is, given some real
// modified times: t1 < t2 < t3, we map these real modified times to deterministic
// times where we maintain the "less than" relation.

// This is done by using ordered hash tables. When give a real modified time t1, we use
// the range of integers to "squeeze" t1 between other previous timestamps.
class mtimeMapper{
private:
  // Tables to keep track of mappings.
  std::map<pair<time_t,time_t>, pair<time_t,time_t>> virtualToRealValue;
  std::map<pair<time_t,time_t>, pair<time_t,time_t>> realToVirtualValue;
  logger& myLogger;



public:
  mtimeMapper(logger& log):
    myLogger(log){
    // Add ranges for us to squeeze between.
    virtualToRealValue[make_pair(0, 0)] = make_pair(0, 0);
    // Current time.
    time_t currentTime = time(nullptr);

    auto currentTimeP = make_pair(currentTime, currentTime);
    auto virtualTimeP = make_pair(virtualNowTime, virtualNowTime);
    virtualToRealValue[virtualTimeP] = currentTimeP;
    realToVirtualValue[currentTimeP] = virtualTimeP;

    virtualToRealValue[make_pair(maxTime, maxNanoTime)] = make_pair(maxTime, maxNanoTime);
    realToVirtualValue[make_pair(maxTime, maxNanoTime)] = make_pair(maxTime, maxNanoTime);
  }

  string to_string(pair<time_t, time_t> p){
    return "(" + std::to_string(p.first) + "," + std::to_string(p.second) + ")";
  }

  pair<time_t, time_t> addRealValue(pair<time_t, time_t> realValue){
    myLogger.writeToLog(Importance::info, "In addRealValue!\n");
    if(realToVirtualValue.find(realValue) != realToVirtualValue.end()){
      throw runtime_error("Attempting to add already existing key: " +
                          to_string(realValue));
    }

    // No need to worry about this not being intialized, we added an entry of map(0) -> 0
    // to our map. So we are guaranteed to always iterate at least once.
    pair<time_t, time_t> prevVirt;

    // Iterate through ordered map to find where to "squeze in our value".
    for(auto entry : realToVirtualValue){
      pair<time_t, time_t> realTimes = entry.first;
      pair<time_t, time_t> virtualTimes = entry.second;

      time_t virtualSeconds = virtualTimes.first;
      time_t virtualNano = virtualTimes.second;

      // We have found the correct place to squeeze our value.
      if(realValue < realTimes){
        auto msg = "Squeezig((%ld, %ld), (%ld, %ld))\n";
        myLogger.writeToLog(Importance::info, msg, prevVirt.first, prevVirt.second,
                            virtualSeconds,  virtualNano);
        time_t newVirtSeconds = getSqueezedValue(prevVirt.first, virtualSeconds);
        time_t newVirtNano = getSqueezedValue(prevVirt.second, virtualNano);
        auto newVirt = make_pair(newVirtSeconds, newVirtNano);

        // We have ran out of numbers to squeeze. The integer division returns our bottom
        // number.
        if(newVirt == prevVirt){
          throw runtime_error("dettrace failure: we have ran out of mtimes to squeeze!");
        }

        realToVirtualValue[realValue] = newVirt;
        virtualToRealValue[newVirt] = realValue;
        myLogger.writeToLog(Importance::info, "%s: Added mapping %s -> %s\n",
                            "mtimeMapper", to_string(realValue).c_str(),
                            to_string(newVirt).c_str());
        return newVirt;
      }

      // Continue, but keep track of our previous.
      prevVirt = virtualTimes;
    }

    throw runtime_error("Reached the end of time (this should be impossible).");
  }

  /**
   * Get the real value of a process from our @valueMappingTable based on the virtual value.
   * OSNL: TODO The virtual value is assumed to exist?
   * @param virtualValue: virtual value of process.
   * @return realValue: real value. Throws if it doesn't exist.
   */
  pair<time_t, time_t>getRealValue(pair<time_t, time_t> virtualValue) {
    // does element exist?
    if (virtualToRealValue.find(virtualValue) != virtualToRealValue.end()) {
      pair<time_t, time_t>realValue = virtualToRealValue[virtualValue];
      myLogger.writeToLog(Importance::info, "mtimeMapper: getRealValue(%s) = %s\n",
                          to_string(virtualValue).c_str(),
                          to_string(realValue).c_str());
      return realValue;
    }
    throw runtime_error("mtimeMapper: getRealValue(" +
                        to_string(virtualValue) + ") does not exist\n");
  }

  // Find the middle of the two numbers that squeeze us.
  // Copied from the internet.
  time_t getSqueezedValue(long si_a, long si_b){
    if ((si_b > 0) && (si_a > (LONG_MAX - si_b)))
      {
        /* will overflow, so use difference method */
        /* both si_a and si_b > 0;
           we want difference also > 0
           so rounding works correctly */
        if (si_a >= si_b)
          return si_b + (si_a - si_b) / 2;
        else
          return si_a + (si_b - si_a) / 2;
      }
    else if ((si_b < 0) && (si_a < (LONG_MIN - si_b)))
      {
        /* will overflow, so use difference method */
        /* both si_a and si_b < 0;
           we want difference also < 0
           so rounding works correctly */
        if (si_a <= si_b)
          return si_b + (si_a - si_b) / 2;
        else
          return si_a + (si_b - si_a) / 2;
      }
    else
      {
        /* the addition will not overflow */
        return (si_a + si_b) / 2;
      }
  }

  /**
   * Get the virtual value from the real value. This assumes the value has already been added
   * through @addEntryValue.
   * @param realValue: real value of process.
   * @return virtualValue: real value. Throws if it doesn't exist.
   */
  pair<time_t, time_t>getVirtualValue(pair<time_t, time_t> realValue) {
    if (realToVirtualValue.find(realValue) != realToVirtualValue.end()) {
      pair<time_t, time_t>virtValue = realToVirtualValue[realValue];
      myLogger.writeToLog(Importance::info, "mtimeMapper: getVirtualValue(%s) = %s\n",
                          to_string(realValue).c_str(),
                          to_string(virtValue).c_str());
      return virtValue;
    }
    throw runtime_error("mtimeMapper: getVirtualValue(" +
                        to_string(realValue) + ") does not exist\n");
  }

  /**
   * Check if real value is already in map for real values.
   * @realValue: real value to check for.
   * @return bool: true if real value already exists in @realToVirtualValue.
   */
  bool realValueExists(pair<time_t, time_t>realValue) {
    bool keyExists = realToVirtualValue.find(realValue) != realToVirtualValue.end();
    return keyExists;
  }

  /**
   * Check if virtual value is already in map for virtual values.
   * @realValue: virtual value to check for.
   * @return bool: true if virtual value already exists in @virtualToRealValue.
   */
  bool virtualValueExists(pair<time_t, time_t>virtualValue) {
    bool keyExists = virtualToRealValue.find(virtualValue) != virtualToRealValue.end();
    return keyExists;
  }

};

#endif
