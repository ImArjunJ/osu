#pragma once
#include <string_view>
namespace introspect::core {
enum class OutputMode : int {
    Summary,
    Verbose,
};
enum class CaptureLevel : int {
    None,
    Hashes,
    Full,
};
struct Config {
    OutputMode mode = OutputMode::Summary;
    CaptureLevel capture = CaptureLevel::None;
    const char* log_path = nullptr;
    int log_fd = -1;
    static Config& instance();
    void load_from_env();
};
}  // namespace introspect::core
