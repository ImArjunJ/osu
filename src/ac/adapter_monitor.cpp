#include "ac/adapter_monitor.hpp"

#include <atomic>
#include <cstdint>
#include <cstring>

#include "ac/module_tracker.hpp"
#include "core/logger.hpp"
#include "platform/linux/memory.hpp"
namespace introspect::ac {
static std::uintptr_t g_module_base = 0;
static std::atomic<bool> g_monitoring{false};
static void* g_anticheat_obj = nullptr;
void store_anticheat_object(void* obj) {
    g_anticheat_obj = obj;
}
void log_adapter_counts() {
    if (!g_anticheat_obj || !g_module_base)
        return;
    core::Logger::instance().log(core::Category::System, [](core::JsonWriter& w) {
        w.field("event", "adapter_monitor_tick");
        w.field_hex("anticheat_obj", reinterpret_cast<std::uintptr_t>(g_anticheat_obj));
    });
}
AdapterMonitor& AdapterMonitor::instance() {
    static AdapterMonitor am;
    return am;
}
void AdapterMonitor::install(std::uintptr_t module_base) {
    if (installed_)
        return;
    g_module_base = module_base;
    core::Logger::instance().log(core::Category::System, [](core::JsonWriter& w) {
        w.field("event", "adapter_monitor_ready");
        w.field("note", "Will log counts from state callback context");
    });
    installed_ = true;
}
}  // namespace introspect::ac
