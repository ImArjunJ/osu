#include "ac/export_interceptor.hpp"

#include <cstdint>
#include <cstring>

#include "ac/module_tracker.hpp"
#include "ac/vm_tracer.hpp"
#include "ac/vtable_patcher.hpp"
#include "core/logger.hpp"
#include "hooks/hook_registry.hpp"
#include "util/time.hpp"
namespace introspect::ac {
__attribute__((noinline)) static void log_enter(const char* fn) {
    core::Logger::instance().log(core::Category::AcCall, [fn](core::JsonWriter& w) {
        w.field("func", fn);
        w.field("event", "enter");
    });
}
__attribute__((noinline)) static void log_exit(const char* fn) {
    core::Logger::instance().log(core::Category::AcCall, [fn](core::JsonWriter& w) {
        w.field("func", fn);
        w.field("event", "exit");
    });
}
__attribute__((noinline)) static void post_initialize() {
    VtablePatcher::instance().try_patch();
    flush_vm_traces();
}
__attribute__((noinline)) static void post_sign() {
    flush_vm_traces();
}
static void log_init_pre() {
    log_enter("Initialize");
}
static void log_init_post() {
    log_exit("Initialize");
    post_initialize();
}
static void log_sign_pre() {
    log_enter("Sign");
}
static void log_sign_post() {
    log_exit("Sign");
    post_sign();
}
static void log_unload_pre() {
    log_enter("Unload");
}
static void log_unload_post() {
    log_exit("Unload");
}
void* g_real_initialize = nullptr;
void* g_real_sign = nullptr;
void* g_real_unload = nullptr;
static void hook_initialize(long a1, long a2, long a3, long a4, long a5, long a6, long a7, long a8,
                            long a9, long a10, long a11, long a12) {
    log_init_pre();
    auto fn = reinterpret_cast<void (*)(long, long, long, long, long, long, long, long, long, long,
                                        long, long)>(g_real_initialize);
    fn(a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11, a12);
    log_init_post();
}
static void hook_sign(long a1, long a2, long a3, long a4, long a5, long a6, long a7, long a8,
                      long a9, long a10, long a11, long a12) {
    log_sign_pre();
    auto fn = reinterpret_cast<void (*)(long, long, long, long, long, long, long, long, long, long,
                                        long, long)>(g_real_sign);
    fn(a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11, a12);
    log_sign_post();
}
static void hook_unload() {
    log_unload_pre();
    auto fn = reinterpret_cast<void (*)()>(g_real_unload);
    fn();
    log_unload_post();
}
static std::uintptr_t g_trampoline_cursor = 0;
static std::uintptr_t write_abs_trampoline(std::uintptr_t base, void* target) {
    if (g_trampoline_cursor == 0)
        g_trampoline_cursor = base + 0x114B00;
    auto* tramp = reinterpret_cast<std::uint8_t*>(g_trampoline_cursor);
    tramp[0] = 0xFF;
    tramp[1] = 0x25;
    tramp[2] = tramp[3] = tramp[4] = tramp[5] = 0x00;
    *reinterpret_cast<std::uintptr_t*>(tramp + 6) = reinterpret_cast<std::uintptr_t>(target);
    auto result = g_trampoline_cursor;
    g_trampoline_cursor += 14;
    return result;
}
static void patch_jmp_thunk(std::uintptr_t thunk_addr, std::uintptr_t base, void* hook,
                            void** real) {
    auto* code = reinterpret_cast<std::uint8_t*>(thunk_addr);
    if (code[0] != 0xE9)
        return;
    std::int32_t orig_rel = *reinterpret_cast<std::int32_t*>(code + 1);
    *real = reinterpret_cast<void*>(thunk_addr + 5 + orig_rel);
    auto tramp_addr = write_abs_trampoline(base, hook);
    std::int32_t new_rel = static_cast<std::int32_t>(static_cast<std::int64_t>(tramp_addr) -
                                                     static_cast<std::int64_t>(thunk_addr + 5));
    *reinterpret_cast<std::int32_t*>(code + 1) = new_rel;
}
ExportInterceptor& ExportInterceptor::instance() {
    static ExportInterceptor ei;
    return ei;
}
void ExportInterceptor::try_hook_exports() {
    if (hooked_)
        return;
    auto& mt = ModuleTracker::instance();
    if (!mt.is_loaded())
        return;
    auto& log = core::Logger::instance();
    auto base = mt.base();
    constexpr std::uintptr_t INIT_THUNK = 0x114A90;
    constexpr std::uintptr_t SIGN_THUNK = 0x114AA0;
    constexpr std::uintptr_t UNLOAD_THUNK = 0x114A20;
    log.log(core::Category::Module, [base](core::JsonWriter& w) {
        w.field("event", "exports_identified");
        w.field_hex("Initialize", base + INIT_THUNK);
        w.field_hex("Sign", base + SIGN_THUNK);
        w.field_hex("Unload", base + UNLOAD_THUNK);
        w.field("note", "VM-protected; observed via side effects");
    });
    hooked_ = true;
}
void* ExportInterceptor::intercept_dlsym_result(const char* symbol, void* real_result) {
    if (!real_result || !symbol)
        return real_result;
    return real_result;
}
}  // namespace introspect::ac
