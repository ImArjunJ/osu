#pragma once
#include <atomic>
#include <cstddef>
#include <cstdint>
namespace introspect::ac {
class ModuleTracker {
public:
    static ModuleTracker& instance();
    void detect_from_linkmap();
    void on_dlopen(const char* path, void* handle);
    void on_dlclose(void* handle);
    bool is_loaded() const { return base_.load(std::memory_order_acquire) != 0; }
    std::uintptr_t base() const { return base_.load(std::memory_order_acquire); }
    std::size_t size() const { return size_; }
    void* handle() const { return handle_; }
    bool is_from_module(void* addr) const;
    std::uintptr_t offset_of(void* addr) const;
    void format_caller(void* addr, char* buf, std::size_t bufsz) const;

private:
    std::atomic<std::uintptr_t> base_{0};
    std::size_t size_ = 0;
    void* handle_ = nullptr;
    bool exports_hooked_ = false;
};
}  // namespace introspect::ac
