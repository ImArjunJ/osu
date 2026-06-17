#pragma once
#include <cstdint>

#include <time.h>
namespace introspect::util {
inline double monotonic_seconds() {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return static_cast<double>(ts.tv_sec) + static_cast<double>(ts.tv_nsec) / 1e9;
}
inline std::uint64_t monotonic_ns() {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return static_cast<std::uint64_t>(ts.tv_sec) * 1'000'000'000ULL +
           static_cast<std::uint64_t>(ts.tv_nsec);
}
struct Timer {
    std::uint64_t start_ns;
    Timer() : start_ns(monotonic_ns()) {}
    double elapsed_ms() const { return static_cast<double>(monotonic_ns() - start_ns) / 1e6; }
};
}  // namespace introspect::util
