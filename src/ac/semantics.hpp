#pragma once
#include <cstdint>
#include <cstring>
#include <string_view>
namespace introspect::ac::semantics {
enum class FileIntent {
    AntiDebugCheck,
    IntegrityCheck,
    CryptoEntropy,
    LogOutput,
    StorageAccess,
    SelfLocation,
    Unknown,
};
constexpr std::string_view file_intent_str(FileIntent fi) {
    switch (fi) {
        case FileIntent::AntiDebugCheck:
            return "antidebug_check";
        case FileIntent::IntegrityCheck:
            return "integrity_check";
        case FileIntent::CryptoEntropy:
            return "crypto_entropy";
        case FileIntent::LogOutput:
            return "log_output";
        case FileIntent::StorageAccess:
            return "storage_access";
        case FileIntent::SelfLocation:
            return "self_location";
        case FileIntent::Unknown:
            return "unknown";
    }
    return "unknown";
}
inline FileIntent classify_file(std::string_view path, std::uintptr_t caller_offset) {
    if (path.find("/proc/self/status") != std::string_view::npos)
        return FileIntent::AntiDebugCheck;
    if (path.find("/proc/self/exe") != std::string_view::npos)
        return FileIntent::SelfLocation;
    if (path.find("/dev/urandom") != std::string_view::npos ||
        path.find("/dev/random") != std::string_view::npos)
        return FileIntent::CryptoEntropy;
    if (path.find(".dll") != std::string_view::npos)
        return FileIntent::IntegrityCheck;
    if (path.find(".nauth.log") != std::string_view::npos)
        return FileIntent::LogOutput;
    if (path.find("/files/") != std::string_view::npos)
        return FileIntent::StorageAccess;
    (void)caller_offset;
    return FileIntent::Unknown;
}
enum class PopenIntent {
    HwEnumerate,
    HwQuery,
    Unknown,
};
constexpr std::string_view popen_intent_str(PopenIntent pi) {
    switch (pi) {
        case PopenIntent::HwEnumerate:
            return "hw_enumerate";
        case PopenIntent::HwQuery:
            return "hw_query";
        case PopenIntent::Unknown:
            return "unknown";
    }
    return "unknown";
}
inline PopenIntent classify_popen(std::string_view cmd) {
    if (cmd.find("lsblk") != std::string_view::npos)
        return PopenIntent::HwEnumerate;
    if (cmd.find("udevadm") != std::string_view::npos)
        return PopenIntent::HwQuery;
    return PopenIntent::Unknown;
}
inline std::string_view extract_device_from_udevadm(std::string_view cmd) {
    auto pos = cmd.find("--name=");
    if (pos == std::string_view::npos)
        return {};
    return cmd.substr(pos + 7);
}
constexpr std::string_view state_name(std::uint32_t s) {
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
}  // namespace introspect::ac::semantics
