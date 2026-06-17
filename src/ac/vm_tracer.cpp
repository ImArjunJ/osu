#include "ac/vm_tracer.hpp"

#include <atomic>
#include <cstdio>
#include <cstdlib>
#include <cstring>

#include <dlfcn.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>

#include "ac/module_tracker.hpp"
#include "ac/offsets.hpp"
#include "core/config.hpp"
#include "core/logger.hpp"
namespace introspect::ac {
static constexpr std::size_t INIT_SLOT_STRIDE = 512;
static constexpr std::size_t SIGN_SLOT_STRIDE = 384;
static constexpr std::size_t MAX_SLOTS = 32;
static constexpr std::size_t RELOC_PTR_OFFSET = 215;
VmTracer& VmTracer::instance() {
    static VmTracer vt;
    return vt;
}
void VmTracer::install(std::uintptr_t module_base) {
    if (installed_.load(std::memory_order_acquire))
        return;
    const char* devirt = std::getenv("OSU_INTROSPECT_DEVIRT");
    if (!devirt || devirt[0] != '1') {
        core::Logger::instance().log(core::Category::System, [](core::JsonWriter& w) {
            w.field("event", "vm_tracer_skipped");
            w.field("reason", "set OSU_INTROSPECT_DEVIRT=1 to enable");
        });
        return;
    }
    base_ = module_base;
    core::Logger::instance().log(core::Category::System, [module_base](core::JsonWriter& w) {
        w.field("event", "vm_tracer_installed");
        w.field("strategy", "post_execution_dump");
        w.field_hex("module_base", module_base);
    });
    installed_.store(true, std::memory_order_release);
}
void flush_vm_traces() {
    auto& vt = VmTracer::instance();
    if (!vt.is_installed())
        return;
    auto& mt = ModuleTracker::instance();
    auto base = mt.base();
    if (!base)
        return;
    auto* code = reinterpret_cast<std::uint8_t*>(base);
    auto& log = core::Logger::instance();
    static int scan_count = 0;
    if (scan_count >= 5)
        return;
    scan_count++;
    struct ScanRegion {
        std::uintptr_t file_offset;
        std::size_t len;
        const char* name;
    };
    constexpr ScanRegion scan_regions[] = {
        {0x113000, 0x80000, "rwx_early"}, {0x193000, 0x80000, "rwx_mid1"},
        {0x213000, 0x80000, "rwx_mid2"},  {0x293000, 0x80000, "rwx_mid3"},
        {0x313000, 0x80000, "rwx_mid4"},  {0x393000, 0x80000, "rwx_mid5"},
    };
    FILE* binfile = fopen("/home/junie/.local/share/osu/AuthNative.so", "rb");
    if (!binfile) {
        log.log(core::Category::System, [](core::JsonWriter& w) {
            w.field("event", "vm_scan_failed");
            w.field("reason", "cannot open binary for comparison");
        });
        return;
    }
    for (const auto& region : scan_regions) {
        auto* runtime = reinterpret_cast<std::uint8_t*>(base + region.file_offset);
        auto* disk = static_cast<std::uint8_t*>(malloc(region.len));
        if (!disk)
            continue;
        fseek(binfile, region.file_offset, SEEK_SET);
        std::size_t read_n = fread(disk, 1, region.len, binfile);
        if (read_n < region.len) {
            free(disk);
            continue;
        }
        std::size_t count = region.len / sizeof(std::uintptr_t);
        std::size_t found = 0;
        for (std::size_t i = 0; i < count; i++) {
            auto runtime_val = *reinterpret_cast<std::uintptr_t*>(runtime + i * 8);
            auto disk_val = *reinterpret_cast<std::uintptr_t*>(disk + i * 8);
            if (runtime_val == disk_val)
                continue;
            if (runtime_val > base && runtime_val < base + mt.size()) {
                std::uintptr_t offset = runtime_val - base;
                if (offset >= 0x113000 && offset < 0x794000) {
                    found++;
                    if (found <= 100) {
                        log.log(core::Category::System, [&](core::JsonWriter& w) {
                            w.field("event", "vm_handler_found");
                            w.field("region", region.name);
                            w.field_hex("handler_offset", offset);
                            w.field_hex("slot_file_offset", region.file_offset + i * 8);
                            w.field_hex("disk_value", static_cast<std::uintptr_t>(disk_val));
                        });
                    }
                }
            }
        }
        if (found > 0) {
            log.log(core::Category::System, [&](core::JsonWriter& w) {
                w.field("event", "vm_scan_complete");
                w.field("region", region.name);
                w.field("handlers_found", static_cast<std::int64_t>(found));
            });
        }
        free(disk);
    }
    fclose(binfile);
}
}  // namespace introspect::ac
