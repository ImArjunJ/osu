#include "core/logger.hpp"

#include <sys/syscall.h>
#include <unistd.h>

#include "core/config.hpp"
#include "util/time.hpp"
namespace introspect::core {
Logger& Logger::instance() {
    static Logger logger;
    return logger;
}
void Logger::init() {
    if (initialized_)
        return;
    auto& cfg = Config::instance();
    cfg.load_from_env();
    fd_ = cfg.log_fd;
    initialized_ = true;
}
void Logger::write_header(JsonWriter& w, Category cat) {
    w.begin_object();
    w.field("ts", util::monotonic_seconds());
    w.field("tid", static_cast<std::int64_t>(syscall(SYS_gettid)));
    w.field("cat", category_str(cat));
}
void Logger::emit_raw(const char* data, std::size_t len) {
    if (fd_ < 0)
        return;
    ::write(fd_, data, len);
}
void Logger::emit(Category cat, const char* json_body, std::size_t len) {
    (void)cat;
    emit_raw(json_body, len);
}
void Logger::shutdown() {
    if (fd_ > STDERR_FILENO) {
        ::close(fd_);
        fd_ = -1;
    }
}
}  // namespace introspect::core
