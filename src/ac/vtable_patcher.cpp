#include "ac/vtable_patcher.hpp"

#include <cstring>

#include "ac/module_tracker.hpp"
#include "ac/offsets.hpp"
#include "ac/vm_tracer.hpp"
#include "core/logger.hpp"
#include "platform/linux/memory.hpp"
namespace introspect::ac {
static constexpr std::string_view state_name(std::uint32_t s) {
    switch (s) {
        case 0:
            return "NotPlaying";
        case 1:
            return "Break";
        case 2:
            return "Playing";
        default:
            return "Unknown";
    }
}
static void log_anticheat_context(void* capture) {
    auto& log = core::Logger::instance();
    auto& mt = ModuleTracker::instance();
    auto base = mt.base();
    auto capture_addr = reinterpret_cast<std::uintptr_t>(capture);
    auto* qwords = reinterpret_cast<std::uintptr_t*>(capture);
    log.log(core::Category::System, [&](core::JsonWriter& w) {
        w.field("event", "ac_context");
        w.field_hex("capture", capture_addr);
        for (int i = 0; i < 8; i++) {
            char key[8];
            std::snprintf(key, sizeof(key), "qw%d", i);
            w.field_hex(key, qwords[i]);
        }
    });
}
static void hook_state_transition(void* capture, std::uint32_t* prev, std::uint32_t* curr) {
    auto& vp = VtablePatcher::instance();
    auto& log = core::Logger::instance();
    std::uint32_t p = *prev, c = *curr;
    log.log(core::Category::AcState, [p, c](core::JsonWriter& w) {
        w.field("prev", state_name(p));
        w.field("curr", state_name(c));
        w.field("prev_raw", static_cast<std::uint64_t>(p));
        w.field("curr_raw", static_cast<std::uint64_t>(c));
    });
    log_anticheat_context(capture);
    vp.real_callback(capture, prev, curr);
    flush_vm_traces();
    log.log(core::Category::AcState, [p, c](core::JsonWriter& w) {
        w.field("event", "done");
        char transition[64];
        std::snprintf(transition, sizeof(transition), "%.*s->%.*s",
                      static_cast<int>(state_name(p).size()), state_name(p).data(),
                      static_cast<int>(state_name(c).size()), state_name(c).data());
        w.field("transition", transition);
    });
}
VtablePatcher& VtablePatcher::instance() {
    static VtablePatcher vp;
    return vp;
}
void VtablePatcher::try_patch() {
    if (patched_)
        return;
    auto& mt = ModuleTracker::instance();
    if (!mt.is_loaded())
        return;
    auto slot_addr = mt.base() + offsets::Table::state_cb_operator;
    auto* slot = reinterpret_cast<void**>(slot_addr);
    void* current = *slot;
    if (!current) {
        core::Logger::instance().log(core::Category::Module, [](core::JsonWriter& w) {
            w.field("event", "vtable_patch_skip");
            w.field("reason", "slot_empty");
        });
        return;
    }
    auto actual_offset = reinterpret_cast<std::uintptr_t>(current) - mt.base();
    if (actual_offset != offsets::Table::state_transition_cb) {
        core::Logger::instance().log(core::Category::Module, [actual_offset](core::JsonWriter& w) {
            w.field("event", "vtable_patch_skip");
            w.field("reason", "unexpected_offset");
            w.field_hex("found", actual_offset);
        });
        return;
    }
    void* old = nullptr;
    if (platform::linux::MemoryOps::patch_pointer(
            slot_addr, reinterpret_cast<void*>(hook_state_transition), &old)) {
        real_callback = reinterpret_cast<StateCbFn>(old);
        patched_ = true;
        core::Logger::instance().log(core::Category::Module, [old](core::JsonWriter& w) {
            w.field("event", "vtable_patched");
            w.field("target", "state_callback");
            w.field_hex("original", reinterpret_cast<std::uintptr_t>(old));
        });
    }
}
}  // namespace introspect::ac
