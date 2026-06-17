#pragma once
#include <cstdint>
namespace introspect::ac {
using InitializeFn = void (*)(void*, void*, void*, void*, void*, void*);
using SignFn = void (*)(void*, void*, void*, void*, void*, void*, void*, void*);
using UnloadFn = void (*)();
struct ExportInterceptor {
    static ExportInterceptor& instance();
    void try_hook_exports();
    bool is_hooked() const { return hooked_; }
    void* intercept_dlsym_result(const char* symbol, void* real_result);
    InitializeFn real_initialize = nullptr;
    SignFn real_sign = nullptr;
    UnloadFn real_unload = nullptr;

private:
    bool hooked_ = false;
};
}  // namespace introspect::ac
