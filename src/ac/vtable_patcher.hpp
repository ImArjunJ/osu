#pragma once
#include <cstdint>
namespace introspect::ac {
using StateCbFn = void (*)(void* capture, std::uint32_t* prev, std::uint32_t* curr);
class VtablePatcher {
public:
    static VtablePatcher& instance();
    void try_patch();
    bool is_patched() const { return patched_; }
    StateCbFn real_callback = nullptr;

private:
    bool patched_ = false;
};
}  // namespace introspect::ac
