#pragma once
#include <cstdint>
namespace introspect::ac {
struct CryptoHooks {
    static CryptoHooks& instance();
    void install(std::uintptr_t module_base);
    bool is_installed() const { return installed_; }

private:
    bool installed_ = false;
};
}  // namespace introspect::ac
