#include "ac/crypto_hooks.hpp"

#include <atomic>
#include <cstdlib>
#include <cstring>

#include <sys/mman.h>

#include "ac/module_tracker.hpp"
#include "ac/offsets.hpp"
#include "core/logger.hpp"
#include "platform/linux/memory.hpp"
namespace introspect::ac {
static constexpr std::uintptr_t SHA1_TRANSFORM = 0x70C6A1;
static constexpr std::uintptr_t TRAMPOLINE_AREA = 0x114C00;
static std::uintptr_t g_module_base = 0;
static void* g_sha1_trampoline = nullptr;
static std::atomic<uint64_t> g_sha1_call_count{0};
static void sha1_transform_hook(void* state) {
    uint64_t count = g_sha1_call_count.fetch_add(1, std::memory_order_relaxed);
    if (count % 64 == 0) {
        void* ra = __builtin_return_address(0);
        auto& mt = ModuleTracker::instance();
        char caller[64];
        mt.format_caller(ra, caller, sizeof(caller));
        core::Logger::instance().log(core::Category::AcCrypto, [&](core::JsonWriter& w) {
            w.field("func", "SHA1::Transform");
            w.field("block_num", static_cast<std::int64_t>(count));
            w.field("caller", caller);
        });
    }
    using transform_fn = void (*)(void*);
    reinterpret_cast<transform_fn>(g_sha1_trampoline)(state);
}
static bool install_inline_hook(std::uintptr_t target_va, void* hook_fn, void** trampoline_out) {
    auto* target = reinterpret_cast<std::uint8_t*>(g_module_base + target_va);
    static std::uintptr_t tramp_cursor = 0;
    if (tramp_cursor == 0)
        tramp_cursor = g_module_base + TRAMPOLINE_AREA;
    auto* tramp = reinterpret_cast<std::uint8_t*>(tramp_cursor);
    std::memcpy(tramp, target, 14);
    tramp[14] = 0xFF;
    tramp[15] = 0x25;
    tramp[16] = tramp[17] = tramp[18] = tramp[19] = 0x00;
    *reinterpret_cast<std::uintptr_t*>(tramp + 20) = reinterpret_cast<std::uintptr_t>(target + 14);
    *trampoline_out = tramp;
    tramp_cursor += 32;
    target[0] = 0xFF;
    target[1] = 0x25;
    target[2] = target[3] = target[4] = target[5] = 0x00;
    *reinterpret_cast<std::uintptr_t*>(target + 6) = reinterpret_cast<std::uintptr_t>(hook_fn);
    return true;
}
CryptoHooks& CryptoHooks::instance() {
    static CryptoHooks ch;
    return ch;
}
void CryptoHooks::install(std::uintptr_t module_base) {
    if (installed_)
        return;
    const char* env = std::getenv("OSU_INTROSPECT_DEVIRT");
    if (!env || env[0] != '1')
        return;
    g_module_base = module_base;
    if (install_inline_hook(SHA1_TRANSFORM, reinterpret_cast<void*>(sha1_transform_hook),
                            &g_sha1_trampoline)) {
        core::Logger::instance().log(core::Category::System, [](core::JsonWriter& w) {
            w.field("event", "crypto_hook_installed");
            w.field("target", "SHA1::Transform");
            w.field_hex("offset", SHA1_TRANSFORM);
        });
        installed_ = true;
    }
}
}  // namespace introspect::ac
