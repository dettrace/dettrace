#include "logicalclock.hpp"

logical_clock::time_point logical_clock::now() noexcept {
  const auto t = std::chrono::system_clock::now();
  return std::chrono::time_point<logical_clock>(
      std::chrono::duration_cast<logical_clock::duration>(
          t.time_since_epoch()));
}

std::time_t logical_clock::to_time_t(const time_point& t) noexcept {
  return std::time_t(
      std::chrono::duration_cast<std::chrono::seconds>(t.time_since_epoch())
          .count());
}

logical_clock::time_point logical_clock::from_time_t(std::time_t t) noexcept {
  typedef std::chrono::time_point<logical_clock, std::chrono::seconds> from;
  return std::chrono::time_point_cast<logical_clock::duration>(
      from(std::chrono::seconds(t)));
}

timespec logical_clock::to_timespec(const time_point& t) noexcept {
  const auto secs = std::chrono::time_point_cast<std::chrono::seconds>(t);
  const auto ns = std::chrono::time_point_cast<std::chrono::nanoseconds>(t) -
                  std::chrono::time_point_cast<std::chrono::nanoseconds>(secs);

  return timespec{secs.time_since_epoch().count(), ns.count()};
}

logical_clock::time_point logical_clock::from_timespec(
    const timespec& ts) noexcept {
  const auto dur = std::chrono::duration_cast<duration>(
      std::chrono::seconds(ts.tv_sec) + std::chrono::nanoseconds(ts.tv_nsec));
  return time_point{dur};
}

timeval logical_clock::to_timeval(const time_point& t) noexcept {
  const auto secs = std::chrono::time_point_cast<std::chrono::seconds>(t);
  const auto usecs =
      std::chrono::time_point_cast<std::chrono::microseconds>(t) -
      std::chrono::time_point_cast<std::chrono::microseconds>(secs);

  return timeval{.tv_sec = secs.time_since_epoch().count(),
                 .tv_usec = usecs.count()};
}

logical_clock::time_point logical_clock::from_timeval(
    const timeval& tv) noexcept {
  const auto dur = std::chrono::duration_cast<duration>(
      std::chrono::seconds(tv.tv_sec) + std::chrono::microseconds(tv.tv_usec));
  return time_point{dur};
}
