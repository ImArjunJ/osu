#include "core/config.hpp"

#include <cstdlib>
#include <cstring>

#include <fcntl.h>
#include <unistd.h>
namespace introspect::core {
Config& Config::instance() {
    static Config cfg;
    return cfg;
}
void Config::load_from_env() {
    if (const char* mode_str = std::getenv("OSU_INTROSPECT_MODE")) {
        if (std::strcmp(mode_str, "verbose") == 0)
            mode = OutputMode::Verbose;
        else
            mode = OutputMode::Summary;
    }
    if (const char* cap_str = std::getenv("OSU_INTROSPECT_CAPTURE")) {
        if (std::strcmp(cap_str, "full") == 0)
            capture = CaptureLevel::Full;
        else if (std::strcmp(cap_str, "hashes") == 0)
            capture = CaptureLevel::Hashes;
        else
            capture = CaptureLevel::None;
    }
    log_path = std::getenv("OSU_INTROSPECT_LOG");
    if (log_path && log_path[0]) {
        log_fd = ::open(log_path, O_WRONLY | O_CREAT | O_APPEND, 0644);
    }
    if (log_fd < 0) {
        log_fd = STDERR_FILENO;
    }
}
}  // namespace introspect::core
