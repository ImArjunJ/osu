#define _GNU_SOURCE
#include "platform/linux/resolver.hpp"

#include <dlfcn.h>
namespace introspect::platform::linux {
Resolver& Resolver::instance() {
    static Resolver r;
    return r;
}
void Resolver::bootstrap() {
    if (real_dlsym_)
        return;
    real_dlsym_ = dlvsym(RTLD_NEXT, "dlsym", "GLIBC_2.34");
    if (!real_dlsym_)
        real_dlsym_ = dlvsym(RTLD_NEXT, "dlsym", "GLIBC_2.2.5");
}
void* Resolver::resolve(const char* name) {
    if (!real_dlsym_)
        bootstrap();
    using dlsym_fn = void* (*)(void*, const char*);
    return reinterpret_cast<dlsym_fn>(real_dlsym_)(RTLD_NEXT, name);
}
void* Resolver::resolve_versioned(const char* name, const char* version) {
    return dlvsym(RTLD_NEXT, name, version);
}
}  // namespace introspect::platform::linux
