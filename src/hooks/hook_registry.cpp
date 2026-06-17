#include "hooks/hook_registry.hpp"

#include "platform/linux/resolver.hpp"
namespace introspect::hooks {
HookRegistry& HookRegistry::instance() {
    static HookRegistry reg;
    return reg;
}
void HookRegistry::resolve_all() {
    if (resolved_.load(std::memory_order_acquire))
        return;
    if (resolving_)
        return;
    resolving_ = true;
    auto& resolver = platform::linux::Resolver::instance();
    resolver.bootstrap();
    real.open = reinterpret_cast<decltype(real.open)>(resolver.resolve("open"));
    real.fopen = reinterpret_cast<decltype(real.fopen)>(resolver.resolve("fopen"));
    real.readlink = reinterpret_cast<decltype(real.readlink)>(resolver.resolve("readlink"));
    real.popen = reinterpret_cast<decltype(real.popen)>(resolver.resolve("popen"));
    real.getenv = reinterpret_cast<decltype(real.getenv)>(resolver.resolve("getenv"));
    real.syscall = reinterpret_cast<decltype(real.syscall)>(resolver.resolve("syscall"));
    real.dlopen = reinterpret_cast<decltype(real.dlopen)>(resolver.resolve("dlopen"));
    real.dlclose = reinterpret_cast<decltype(real.dlclose)>(resolver.resolve("dlclose"));
    real.dl_iterate_phdr =
        reinterpret_cast<decltype(real.dl_iterate_phdr)>(resolver.resolve("dl_iterate_phdr"));
    real.pthread_create =
        reinterpret_cast<decltype(real.pthread_create)>(resolver.resolve("pthread_create"));
    real.dlsym = reinterpret_cast<decltype(real.dlsym)>(resolver.real_dlsym());
    resolved_.store(true, std::memory_order_release);
    resolving_ = false;
}
}  // namespace introspect::hooks
