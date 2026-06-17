#pragma once
#include <cstdint>
#include <string_view>
namespace introspect::core {
enum class Category : std::uint8_t {
    AcState,
    AcIntegrity,
    AcFingerprint,
    AcAntidebug,
    AcCrypto,
    AcBridge,
    AcThread,
    AcCall,
    IoOpen,
    IoFopen,
    IoReadlink,
    Exec,
    Env,
    Syscall,
    DlOpen,
    DlSym,
    Module,
    MemoryMap,
    System,
};
constexpr std::string_view category_str(Category c) {
    switch (c) {
        case Category::AcState:
            return "ac.state";
        case Category::AcIntegrity:
            return "ac.integrity";
        case Category::AcFingerprint:
            return "ac.fingerprint";
        case Category::AcAntidebug:
            return "ac.antidebug";
        case Category::AcCrypto:
            return "ac.crypto";
        case Category::AcBridge:
            return "ac.bridge";
        case Category::AcThread:
            return "ac.thread";
        case Category::AcCall:
            return "ac.call";
        case Category::IoOpen:
            return "io.open";
        case Category::IoFopen:
            return "io.fopen";
        case Category::IoReadlink:
            return "io.readlink";
        case Category::Exec:
            return "exec";
        case Category::Env:
            return "env";
        case Category::Syscall:
            return "syscall";
        case Category::DlOpen:
            return "dl.open";
        case Category::DlSym:
            return "dl.sym";
        case Category::Module:
            return "module";
        case Category::MemoryMap:
            return "memory.map";
        case Category::System:
            return "system";
    }
    return "unknown";
}
}  // namespace introspect::core
