#pragma once
#include <cstdint>
#include <string_view>
namespace introspect::ac::offsets {
struct Table {
    static constexpr std::uintptr_t state_cb_vtable = 0x79AE28;
    static constexpr std::uintptr_t state_cb_operator = 0x79AE58;
    static constexpr std::uintptr_t initialize_entry = 0x2EB7FB;
    static constexpr std::uintptr_t sign_entry = 0x2D3520;
    static constexpr std::uintptr_t unload_entry = 0x2CACD1;
    static constexpr std::uintptr_t state_transition_cb = 0x12F040;
    static constexpr std::uintptr_t antidebug_thread = 0x132D40;
    static constexpr std::uintptr_t antidebug_creator = 0x132C64;
    static constexpr std::uintptr_t file_reader = 0x74EB04;
    static constexpr std::uintptr_t crypto_rng = 0x74D606;
    static constexpr std::uintptr_t crypto_rng_alt = 0x720BC3;
    static constexpr std::uintptr_t exe_resolver = 0x411B4B;
    static constexpr std::uintptr_t hw_fingerprint = 0x310044;
    static constexpr std::uintptr_t nauth_logger = 0x2F4001;
    static constexpr std::size_t module_size = 0x7C2000;
};
constexpr std::string_view annotate(std::uintptr_t offset) {
    if (offset == Table::state_cb_vtable)
        return "state_callback_vtable";
    if (offset == Table::state_cb_operator)
        return "state_callback_operator()";
    if (offset == Table::initialize_entry)
        return "Initialize_protected_entry";
    if (offset == Table::sign_entry)
        return "Sign_protected_entry";
    if (offset == Table::unload_entry)
        return "Unload_protected_entry";
    if (offset == Table::state_transition_cb)
        return "anticheat_state_transition_callback";
    if (offset == Table::antidebug_thread)
        return "antidebug_poller_thread";
    if (offset == Table::antidebug_creator)
        return "antidebug_thread_creator";
    if (offset == Table::file_reader)
        return "file_reader_generic";
    if (offset == Table::crypto_rng)
        return "crypto_rng_seeder";
    if (offset == Table::crypto_rng_alt)
        return "crypto_rng_seeder_alt";
    if (offset == Table::exe_resolver)
        return "proc_self_exe_resolver";
    if (offset == Table::hw_fingerprint)
        return "hardware_fingerprint_popen";
    if (offset == Table::nauth_logger)
        return "nauth_log_writer";
    return "";
}
}  // namespace introspect::ac::offsets
