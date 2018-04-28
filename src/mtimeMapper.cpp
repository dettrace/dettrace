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
#include "mtimeMapper.hpp"

using namespace std;

mtimeMapper::mtimeMapper(logger& log):
  myLogger(log){
  time_t currentTime = time(nullptr);

  // Add ranges for us to squeeze real values between:
  // Bottom bound.
  auto zeroPair = make_pair(0, 0);
  virtualToRealValue[zeroPair] = zeroPair;
  realToVirtualValue[zeroPair] = zeroPair;

  // We want to avoid errros where existing files look newer than the time.
  // So we set the current time be our middile point.
  auto currentTimeP = make_pair(currentTime, maxNanoTime / 2);
  auto virtualTimeP = make_pair(maxTime / 2, maxNanoTime / 2);
  auto maxTimeP = make_pair(maxTime, maxNanoTime);

  // Seed middle time. All real times that already existed will go to the left
  // of maxTime / 2, else to the right.
  virtualToRealValue[virtualTimeP] = currentTimeP;
  realToVirtualValue[currentTimeP] = virtualTimeP;

  // Max ranges. In case we ever reach the end of time.
  virtualToRealValue[maxTimeP] = maxTimeP;
  realToVirtualValue[maxTimeP] = maxTimeP;
}

string mtimeMapper::to_string(pair<time_t, time_t> p){
  return "(" + std::to_string(p.first) + "," + std::to_string(p.second) + ")";
}

pair<time_t, time_t> mtimeMapper::addRealValue(pair<time_t, time_t> realValue){
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


pair<time_t, time_t> mtimeMapper::getRealValue(pair<time_t, time_t> virtualValue) {
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

time_t mtimeMapper::getSqueezedValue(long si_a, long si_b){
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


pair<time_t, time_t> mtimeMapper::getVirtualValue(pair<time_t, time_t> realValue) {
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


bool mtimeMapper::realValueExists(pair<time_t, time_t>realValue) {
  bool keyExists = realToVirtualValue.find(realValue) != realToVirtualValue.end();
  return keyExists;
}

bool mtimeMapper::virtualValueExists(pair<time_t, time_t>virtualValue) {
  bool keyExists = virtualToRealValue.find(virtualValue) != virtualToRealValue.end();
  return keyExists;
}
