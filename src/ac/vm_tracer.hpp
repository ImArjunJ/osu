#pragma once
#include <atomic>
#include <cstdint>
namespace introspect::ac {
struct VmTracer {
    static VmTracer& instance();
    void install(std::uintptr_t module_base);
    bool is_installed() const { return installed_.load(std::memory_order_acquire); }

private:
    std::atomic<bool> installed_{false};
    std::uintptr_t base_ = 0;
};
void flush_vm_traces();
}  // namespace introspect::ac
