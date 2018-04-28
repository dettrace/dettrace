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

  const long maxTime = LONG_MAX;
  // The biggest a nanosecond can be before reaching seconds.
  const long maxNanoTime = 999999999;

public:
  mtimeMapper(logger& log);

  string to_string(pair<time_t, time_t> p);

  pair<time_t, time_t> addRealValue(pair<time_t, time_t> realValue);

  /**
   * Get the real value of a process from our @valueMappingTable based on the virtual value.
   * OSNL: TODO The virtual value is assumed to exist?
   * @param virtualValue: virtual value of process.
   * @return realValue: real value. Throws if it doesn't exist.
   */
  pair<time_t, time_t> getRealValue(pair<time_t, time_t> virtualValue);

  // Find the middle of the two numbers that squeeze us.
  // Copied from the internet.
  time_t getSqueezedValue(long si_a, long si_b);

  /**
   * Get the virtual value from the real value. This assumes the value has already been added
   * through @addEntryValue.
   * @param realValue: real value of process.
   * @return virtualValue: real value. Throws if it doesn't exist.
   */
  pair<time_t, time_t> getVirtualValue(pair<time_t, time_t> realValue);

  /**
   * Check if real value is already in map for real values.
   * @realValue: real value to check for.
   * @return bool: true if real value already exists in @realToVirtualValue.
   */
  bool realValueExists(pair<time_t, time_t> realValue);

  /**
   * Check if virtual value is already in map for virtual values.
   * @realValue: virtual value to check for.
   * @return bool: true if virtual value already exists in @virtualToRealValue.
   */
  bool virtualValueExists(pair<time_t, time_t> virtualValue);

};

#endif
