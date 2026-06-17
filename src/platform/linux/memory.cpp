#include "platform/linux/memory.hpp"

#include <sys/mman.h>
namespace introspect::platform::linux {
bool MemoryOps::make_writable(void* addr, std::size_t len) {
    auto page = reinterpret_cast<std::uintptr_t>(addr) & ~0xFFFUL;
    return mprotect(reinterpret_cast<void*>(page), len + 4096,
                    PROT_READ | PROT_WRITE | PROT_EXEC) == 0;
}
bool MemoryOps::make_rx(void* addr, std::size_t len) {
    auto page = reinterpret_cast<std::uintptr_t>(addr) & ~0xFFFUL;
    return mprotect(reinterpret_cast<void*>(page), len + 4096, PROT_READ | PROT_EXEC) == 0;
}
bool MemoryOps::patch_pointer(std::uintptr_t slot_addr, void* new_value, void** old_value) {
    auto* slot = reinterpret_cast<void**>(slot_addr);
    if (!make_writable(slot, sizeof(void*)))
        return false;
    *old_value = *slot;
    *slot = new_value;
    make_rx(slot, sizeof(void*));
    return true;
}
}  // namespace introspect::platform::linux
