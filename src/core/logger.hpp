#pragma once
#include <cstdint>
#include <string_view>

#include "core/event.hpp"
#include "core/json.hpp"
namespace introspect::core {
class Logger {
public:
    static Logger& instance();
    void init();
    void emit(Category cat, const char* json_body, std::size_t len);
    template <typename BuildFn>
    void log(Category cat, BuildFn&& build) {
        thread_local char buf[4096];
        JsonWriter w{buf, sizeof(buf)};
        write_header(w, cat);
        build(w);
        w.end_object();
        w.newline();
        emit_raw(w.data(), w.size());
    }
    void shutdown();

private:
    void write_header(JsonWriter& w, Category cat);
    void emit_raw(const char* data, std::size_t len);
    int fd_ = -1;
    bool initialized_ = false;
};
}  // namespace introspect::core
