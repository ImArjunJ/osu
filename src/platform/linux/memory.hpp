#pragma once
#include <cstddef>
#include <cstdint>
namespace introspect::platform::linux {
struct MemoryOps {
    static bool make_writable(void* addr, std::size_t len);
    static bool make_rx(void* addr, std::size_t len);
    static bool patch_pointer(std::uintptr_t slot_addr, void* new_value, void** old_value);
};
}  // namespace introspect::platform::linux
