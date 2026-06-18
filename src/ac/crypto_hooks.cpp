#include "ac/crypto_hooks.hpp"

#include <atomic>
#include <cstdlib>
#include <cstring>

#include "ac/module_tracker.hpp"
#include "core/logger.hpp"
namespace introspect::ac {
static constexpr std::uintptr_t DISPATCH_TABLE_BASE = 0x7B9F78;
static constexpr std::uintptr_t FINALIZE_INVOKE_PTR = 0x7BA018;
static constexpr std::uintptr_t FINALIZE_INDEXED_PTR = 0x7BA020;
static constexpr std::uintptr_t GET_COUNT_PTR = 0x7B9FD0;
static std::uintptr_t g_module_base = 0;
static void* g_real_finalize_invoke = nullptr;
static void* g_real_finalize_indexed = nullptr;
static void* g_real_get_count = nullptr;
static std::atomic<uint64_t> g_invoke_count{0};
using generic_fn = void* (*)(void*, void*, void*, void*, void*, void*);
static void* hook_finalize_invoke(void* a1, void* a2, void* a3, void* a4, void* a5, void* a6) {
    uint64_t n = g_invoke_count.fetch_add(1, std::memory_order_relaxed);
    void* ra = __builtin_return_address(0);
    auto& mt = ModuleTracker::instance();
    char caller[64];
    mt.format_caller(ra, caller, sizeof(caller));
    auto* result = reinterpret_cast<generic_fn>(g_real_finalize_invoke)(a1, a2, a3, a4, a5, a6);
    core::Logger::instance().log(core::Category::AcCrypto, [&](core::JsonWriter& w) {
        w.field("func", "finalize_invoke");
        w.field("n", static_cast<std::int64_t>(n));
        w.field("at", caller);
        w.field_hex("a1", reinterpret_cast<std::uintptr_t>(a1));
        w.field_hex("a2", reinterpret_cast<std::uintptr_t>(a2));
        w.field_hex("a3", reinterpret_cast<std::uintptr_t>(a3));
        w.field_hex("a4", reinterpret_cast<std::uintptr_t>(a4));
        w.field_hex("ret", reinterpret_cast<std::uintptr_t>(result));
    });
    return result;
}
static void* hook_finalize_indexed(void* a1, void* a2, void* a3, void* a4, void* a5, void* a6) {
    void* ra = __builtin_return_address(0);
    auto& mt = ModuleTracker::instance();
    char caller[64];
    mt.format_caller(ra, caller, sizeof(caller));
    auto* result = reinterpret_cast<generic_fn>(g_real_finalize_indexed)(a1, a2, a3, a4, a5, a6);
    core::Logger::instance().log(core::Category::AcCrypto, [&](core::JsonWriter& w) {
        w.field("func", "finalize_indexed");
        w.field("at", caller);
        w.field_hex("a1", reinterpret_cast<std::uintptr_t>(a1));
        w.field_hex("a2", reinterpret_cast<std::uintptr_t>(a2));
        w.field_hex("a3", reinterpret_cast<std::uintptr_t>(a3));
        w.field_hex("a4", reinterpret_cast<std::uintptr_t>(a4));
        w.field_hex("ret", reinterpret_cast<std::uintptr_t>(result));
    });
    return result;
}
static void* hook_get_count(void* a1, void* a2, void* a3, void* a4, void* a5, void* a6) {
    void* ra = __builtin_return_address(0);
    auto& mt = ModuleTracker::instance();
    char caller[64];
    mt.format_caller(ra, caller, sizeof(caller));
    auto* result = reinterpret_cast<generic_fn>(g_real_get_count)(a1, a2, a3, a4, a5, a6);
    core::Logger::instance().log(core::Category::AcCrypto, [&](core::JsonWriter& w) {
        w.field("func", "get_count");
        w.field("at", caller);
        w.field_hex("ret", reinterpret_cast<std::uintptr_t>(result));
    });
    return result;
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
    if (g_module_base == 0)
        g_module_base = module_base;
    auto* invoke_ptr = reinterpret_cast<void**>(module_base + FINALIZE_INVOKE_PTR);
    auto* indexed_ptr = reinterpret_cast<void**>(module_base + FINALIZE_INDEXED_PTR);
    auto* count_ptr = reinterpret_cast<void**>(module_base + GET_COUNT_PTR);
    if (*invoke_ptr == nullptr) {
        return;
    }
    g_real_finalize_invoke = *invoke_ptr;
    g_real_finalize_indexed = *indexed_ptr;
    g_real_get_count = *count_ptr;
    *invoke_ptr = reinterpret_cast<void*>(hook_finalize_invoke);
    *indexed_ptr = reinterpret_cast<void*>(hook_finalize_indexed);
    *count_ptr = reinterpret_cast<void*>(hook_get_count);
    core::Logger::instance().log(core::Category::System, [](core::JsonWriter& w) {
        w.field("event", "dispatch_table_hooked");
        w.field("target", "finalize_invoke + finalize_indexed + get_count");
    });
    installed_ = true;
}
}  // namespace introspect::ac
