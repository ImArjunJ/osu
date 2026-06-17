#include "ac/module_tracker.hpp"

#include <cstdio>
#include <cstring>

#include <dlfcn.h>
#include <link.h>

#include "ac/offsets.hpp"
#include "core/logger.hpp"
#include "hooks/hook_registry.hpp"
namespace introspect::ac {
ModuleTracker& ModuleTracker::instance() {
    static ModuleTracker mt;
    return mt;
}
void ModuleTracker::detect_from_linkmap() {
    if (is_loaded())
        return;
    auto& reg = hooks::HookRegistry::instance();
    void* self = reg.real.dlopen(nullptr, RTLD_LAZY | RTLD_NOLOAD);
    if (!self)
        return;
    struct link_map* lm = nullptr;
    if (dlinfo(self, RTLD_DI_LINKMAP, &lm) != 0) {
        reg.real.dlclose(self);
        return;
    }
    while (lm) {
        if (lm->l_name && std::strstr(lm->l_name, "AuthNative")) {
            base_.store(reinterpret_cast<std::uintptr_t>(lm->l_addr), std::memory_order_release);
            size_ = offsets::Table::module_size;
            handle_ = reg.real.dlopen(lm->l_name, RTLD_LAZY | RTLD_NOLOAD);
            core::Logger::instance().log(core::Category::Module, [&](core::JsonWriter& w) {
                w.field("event", "detected");
                w.field_hex("base", base());
                w.field("path", lm->l_name);
            });
            break;
        }
        lm = lm->l_next;
    }
    reg.real.dlclose(self);
}
void ModuleTracker::on_dlopen(const char* path, void* handle) {
    if (!path || !handle)
        return;
    if (!std::strstr(path, "AuthNative"))
        return;
    struct link_map* lm = nullptr;
    if (dlinfo(handle, RTLD_DI_LINKMAP, &lm) == 0 && lm) {
        base_.store(reinterpret_cast<std::uintptr_t>(lm->l_addr), std::memory_order_release);
        size_ = offsets::Table::module_size;
        handle_ = handle;
        core::Logger::instance().log(core::Category::Module, [&](core::JsonWriter& w) {
            w.field("event", "loaded");
            w.field_hex("base", base());
            w.field("path", path);
        });
    }
}
void ModuleTracker::on_dlclose(void* handle) {
    if (handle == handle_ && handle_) {
        core::Logger::instance().log(core::Category::Module,
                                     [&](core::JsonWriter& w) { w.field("event", "unloading"); });
        base_.store(0, std::memory_order_release);
        handle_ = nullptr;
    }
}
bool ModuleTracker::is_from_module(void* addr) const {
    auto b = base();
    if (!b || !addr)
        return false;
    auto a = reinterpret_cast<std::uintptr_t>(addr);
    return a >= b && a < b + size_;
}
std::uintptr_t ModuleTracker::offset_of(void* addr) const {
    return reinterpret_cast<std::uintptr_t>(addr) - base();
}
void ModuleTracker::format_caller(void* addr, char* buf, std::size_t bufsz) const {
    if (is_from_module(addr)) {
        auto off = offset_of(addr);
        auto annotation = offsets::annotate(off);
        if (!annotation.empty())
            std::snprintf(buf, bufsz, "AuthNative+0x%lx[%.*s]", static_cast<unsigned long>(off),
                          static_cast<int>(annotation.size()), annotation.data());
        else
            std::snprintf(buf, bufsz, "AuthNative+0x%lx", static_cast<unsigned long>(off));
    } else {
        Dl_info dli;
        if (dladdr(addr, &dli) && dli.dli_fname) {
            const char* base_name = std::strrchr(dli.dli_fname, '/');
            base_name = base_name ? base_name + 1 : dli.dli_fname;
            std::snprintf(
                buf, bufsz, "%s+0x%lx", base_name,
                static_cast<unsigned long>(reinterpret_cast<std::uintptr_t>(addr) -
                                           reinterpret_cast<std::uintptr_t>(dli.dli_fbase)));
        } else {
            std::snprintf(buf, bufsz, "0x%lx",
                          static_cast<unsigned long>(reinterpret_cast<std::uintptr_t>(addr)));
        }
    }
}
}  // namespace introspect::ac
