#include "hooks/libc_hooks.hpp"

#include <cstring>

#include <dlfcn.h>

#include "ac/crypto_hooks.hpp"
#include "ac/export_interceptor.hpp"
#include "ac/module_tracker.hpp"
#include "ac/vm_tracer.hpp"
#include "ac/vtable_patcher.hpp"
namespace introspect::hooks::libc {
void try_lazy_detect(void* return_addr) {
    auto& mt = ac::ModuleTracker::instance();
    if (mt.is_loaded()) {
        if (!ac::ExportInterceptor::instance().is_hooked()) {
            ac::ExportInterceptor::instance().try_hook_exports();
            ac::VtablePatcher::instance().try_patch();
            ac::VmTracer::instance().install(mt.base());
            ac::CryptoHooks::instance().install(mt.base());
        }
        return;
    }
    Dl_info dli{};
    if (return_addr && dladdr(return_addr, &dli) && dli.dli_fname &&
        std::strstr(dli.dli_fname, "AuthNative")) {
        mt.detect_from_linkmap();
        ac::ExportInterceptor::instance().try_hook_exports();
        ac::VtablePatcher::instance().try_patch();
        ac::VmTracer::instance().install(mt.base());
        ac::CryptoHooks::instance().install(mt.base());
    }
}
}  // namespace introspect::hooks::libc
