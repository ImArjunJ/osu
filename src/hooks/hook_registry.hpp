#pragma once
#include <atomic>
#include <cstdio>

#include <dlfcn.h>
#include <link.h>
#include <pthread.h>
#include <unistd.h>
namespace introspect::hooks {
struct RealFunctions {
    int (*open)(const char*, int, ...) = nullptr;
    FILE* (*fopen)(const char*, const char*) = nullptr;
    ssize_t (*readlink)(const char*, char*, size_t) = nullptr;
    FILE* (*popen)(const char*, const char*) = nullptr;
    char* (*getenv)(const char*) = nullptr;
    long (*syscall)(long, ...) = nullptr;
    void* (*dlopen)(const char*, int) = nullptr;
    void* (*dlsym)(void*, const char*) = nullptr;
    int (*dlclose)(void*) = nullptr;
    int (*dl_iterate_phdr)(int (*)(struct dl_phdr_info*, size_t, void*), void*) = nullptr;
    int (*pthread_create)(pthread_t*, const pthread_attr_t*, void* (*)(void*), void*) = nullptr;
};
class HookRegistry {
public:
    static HookRegistry& instance();
    void resolve_all();
    bool is_resolved() const { return resolved_.load(std::memory_order_acquire); }
    bool is_resolving() const { return resolving_; }
    void set_resolving(bool v) { resolving_ = v; }
    RealFunctions real;

private:
    std::atomic<bool> resolved_{false};
    volatile bool resolving_ = false;
};
}  // namespace introspect::hooks
