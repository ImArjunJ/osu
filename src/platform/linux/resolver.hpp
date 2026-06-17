#pragma once
#include <dlfcn.h>
namespace introspect::platform::linux {
class Resolver {
public:
    void* resolve(const char* name);
    void* resolve_versioned(const char* name, const char* version);
    static Resolver& instance();
    void* real_dlsym() const { return real_dlsym_; }
    bool is_bootstrapped() const { return real_dlsym_ != nullptr; }
    void bootstrap();

private:
    void* real_dlsym_ = nullptr;
};
}  // namespace introspect::platform::linux
