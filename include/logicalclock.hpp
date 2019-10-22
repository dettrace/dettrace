#ifndef LOGICAL_CLOCK_H
#define LOGICAL_CLOCK_H

#include <sys/time.h> // for timeval
#include <chrono>
#include <ctime> // for time_t

/**
 * This represents our logical clock.
 */
struct logical_clock {
  using duration = std::chrono::microseconds;
  using rep = duration::rep;
  using period = duration::period;
  using time_point = std::chrono::time_point<logical_clock, duration>;

  static_assert(
      logical_clock::duration::min() < logical_clock::duration::zero(),
      "a clock's minimum duration cannot be less than its epoch");

  static constexpr bool is_steady = false;

  static time_point now() noexcept;

  // time_t conversions
  static std::time_t to_time_t(const time_point& t) noexcept;
  static time_point from_time_t(std::time_t t) noexcept;

  // timespec conversions
  static timespec to_timespec(const time_point& t) noexcept;
  static time_point from_timespec(const timespec& ts) noexcept;

  // timeval conversions
  static timeval to_timeval(const time_point& t) noexcept;
  static time_point from_timeval(const timeval& tv) noexcept;
};

#endif // LOGICAL_CLOCK_H
