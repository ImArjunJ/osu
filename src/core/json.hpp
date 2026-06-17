#pragma once
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string_view>
namespace introspect::core {
class JsonWriter {
public:
    explicit JsonWriter(char* buf, std::size_t capacity)
        : buf_(buf), capacity_(capacity), pos_(0) {}
    JsonWriter& begin_object() {
        put('{');
        first_field_ = true;
        return *this;
    }
    JsonWriter& end_object() {
        put('}');
        return *this;
    }
    JsonWriter& key(std::string_view k) {
        if (!first_field_)
            put(',');
        first_field_ = false;
        put('"');
        write_raw(k);
        put('"');
        put(':');
        return *this;
    }
    JsonWriter& value_string(std::string_view v) {
        put('"');
        write_escaped(v);
        put('"');
        return *this;
    }
    JsonWriter& value_null() {
        write_raw("null");
        return *this;
    }
    JsonWriter& value_bool(bool v) {
        write_raw(v ? "true" : "false");
        return *this;
    }
    JsonWriter& value_int(std::int64_t v) {
        char tmp[24];
        int n = std::snprintf(tmp, sizeof(tmp), "%ld", static_cast<long>(v));
        write_raw(std::string_view{tmp, static_cast<std::size_t>(n)});
        return *this;
    }
    JsonWriter& value_uint(std::uint64_t v) {
        char tmp[24];
        int n = std::snprintf(tmp, sizeof(tmp), "%lu", static_cast<unsigned long>(v));
        write_raw(std::string_view{tmp, static_cast<std::size_t>(n)});
        return *this;
    }
    JsonWriter& value_double(double v, int precision = 6) {
        char tmp[32];
        int n = std::snprintf(tmp, sizeof(tmp), "%.*f", precision, v);
        write_raw(std::string_view{tmp, static_cast<std::size_t>(n)});
        return *this;
    }
    JsonWriter& value_hex(std::uintptr_t v) {
        char tmp[24];
        int n = std::snprintf(tmp, sizeof(tmp), "\"0x%lx\"", static_cast<unsigned long>(v));
        write_raw(std::string_view{tmp, static_cast<std::size_t>(n)});
        return *this;
    }
    JsonWriter& field(std::string_view k, std::string_view v) { return key(k).value_string(v); }
    JsonWriter& field(std::string_view k, const char* v) {
        if (v)
            return key(k).value_string(v);
        return key(k).value_null();
    }
    JsonWriter& field(std::string_view k, std::int64_t v) { return key(k).value_int(v); }
    JsonWriter& field(std::string_view k, std::uint64_t v) { return key(k).value_uint(v); }
    JsonWriter& field(std::string_view k, int v) { return key(k).value_int(v); }
    JsonWriter& field(std::string_view k, unsigned v) { return key(k).value_uint(v); }
    JsonWriter& field(std::string_view k, double v) { return key(k).value_double(v); }
    JsonWriter& field(std::string_view k, bool v) { return key(k).value_bool(v); }
    JsonWriter& field_hex(std::string_view k, std::uintptr_t v) { return key(k).value_hex(v); }
    void newline() { put('\n'); }
    std::string_view view() const { return {buf_, pos_}; }
    std::size_t size() const { return pos_; }
    const char* data() const { return buf_; }

private:
    void put(char c) {
        if (pos_ < capacity_ - 1)
            buf_[pos_++] = c;
    }
    void write_raw(std::string_view s) {
        std::size_t n = s.size();
        if (pos_ + n > capacity_ - 1)
            n = capacity_ - 1 - pos_;
        std::memcpy(buf_ + pos_, s.data(), n);
        pos_ += n;
    }
    void write_escaped(std::string_view s) {
        for (char c : s) {
            auto uc = static_cast<unsigned char>(c);
            if (c == '"' || c == '\\') {
                put('\\');
                put(c);
            } else if (c == '\n') {
                put('\\');
                put('n');
            } else if (c == '\r') {
                put('\\');
                put('r');
            } else if (c == '\t') {
                put('\\');
                put('t');
            } else if (uc < 0x20) {
                char tmp[8];
                std::snprintf(tmp, sizeof(tmp), "\\u%04x", uc);
                write_raw(std::string_view{tmp, 6});
            } else {
                put(c);
            }
        }
    }
    char* buf_;
    std::size_t capacity_;
    std::size_t pos_;
    bool first_field_ = true;
};
}  // namespace introspect::core
