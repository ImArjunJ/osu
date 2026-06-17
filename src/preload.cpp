#define _GNU_SOURCE
#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <cstring>

#include <dlfcn.h>
#include <fcntl.h>
#include <link.h>
#include <pthread.h>
#include <sys/syscall.h>
#include <unistd.h>

#include "ac/export_interceptor.hpp"
#include "ac/module_tracker.hpp"
#include "ac/semantics.hpp"
#include "ac/vm_tracer.hpp"
#include "core/config.hpp"
#include "core/json.hpp"
#include "core/logger.hpp"
#include "hooks/hook_registry.hpp"
#include "hooks/libc_hooks.hpp"
#include "util/time.hpp"
using namespace introspect;
static inline hooks::HookRegistry& reg() {
    auto& r = hooks::HookRegistry::instance();
    if (!r.is_resolved()) [[unlikely]]
        r.resolve_all();
    return r;
}
static inline bool from_ac(void* ra) {
    return ac::ModuleTracker::instance().is_from_module(ra);
}
static void format_caller(void* ra, char* buf, std::size_t sz) {
    ac::ModuleTracker::instance().format_caller(ra, buf, sz);
}
extern "C" {
__attribute__((visibility("default"))) int open(const char* pathname, int flags, ...) {
    auto& r = reg();
    mode_t mode = 0;
    if (flags & O_CREAT) {
        va_list ap;
        va_start(ap, flags);
        mode = va_arg(ap, int);
        va_end(ap);
    }
    void* ra = __builtin_return_address(0);
    hooks::libc::try_lazy_detect(ra);
    bool is_ac = from_ac(ra);
    if (is_ac || (pathname &&
                  (std::strstr(pathname, "/proc/self") || std::strstr(pathname, "/dev/urandom") ||
                   std::strstr(pathname, "/dev/random") || std::strstr(pathname, "AuthNative") ||
                   std::strstr(pathname, ".auth_")))) {
        char caller[64];
        format_caller(ra, caller, sizeof(caller));
        auto intent = ac::semantics::classify_file(pathname ? pathname : "", 0);
        core::Logger::instance().log(core::Category::IoOpen, [&](core::JsonWriter& w) {
            w.field("path", pathname);
            w.field("flags", flags);
            w.field("ac", is_ac);
            w.field("at", caller);
            if (is_ac)
                w.field("intent", ac::semantics::file_intent_str(intent));
        });
    }
    if (flags & O_CREAT)
        return r.real.open(pathname, flags, mode);
    return r.real.open(pathname, flags);
}
__attribute__((visibility("default"))) FILE* fopen(const char* pathname, const char* mode) {
    auto& r = reg();
    void* ra = __builtin_return_address(0);
    hooks::libc::try_lazy_detect(ra);
    bool is_ac = from_ac(ra);
    if (is_ac || (pathname &&
                  (std::strstr(pathname, "/proc") || std::strstr(pathname, "/dev/random") ||
                   std::strstr(pathname, "/dev/urandom") || std::strstr(pathname, "AuthNative") ||
                   std::strstr(pathname, ".auth_") || std::strstr(pathname, ".dll")))) {
        char caller[64];
        format_caller(ra, caller, sizeof(caller));
        auto intent = ac::semantics::classify_file(pathname ? pathname : "", 0);
        core::Logger::instance().log(core::Category::IoFopen, [&](core::JsonWriter& w) {
            w.field("path", pathname);
            w.field("mode", mode);
            w.field("ac", is_ac);
            w.field("at", caller);
            if (is_ac)
                w.field("intent", ac::semantics::file_intent_str(intent));
        });
    }
    FILE* result = r.real.fopen(pathname, mode);
    if (is_ac && result && pathname && std::strstr(pathname, "/proc/self/status")) {
        static bool spoof_enabled = []() {
            const char* env = std::getenv("OSU_INTROSPECT_SPOOF_TRACER");
            return env && env[0] == '1';
        }();
        if (spoof_enabled) {
            char buf[4096];
            std::size_t n = fread(buf, 1, sizeof(buf) - 1, result);
            fclose(result);
            buf[n] = '\0';
            char* tracer = std::strstr(buf, "TracerPid:");
            if (tracer) {
                char* val_start = tracer + 10;
                while (*val_start == '\t' || *val_start == ' ')
                    val_start++;
                char* val_end = val_start;
                while (*val_end >= '0' && *val_end <= '9')
                    val_end++;
                *val_start = '0';
                for (char* p = val_start + 1; p < val_end; p++)
                    *p = ' ';
            }
            int pipefd[2];
            if (pipe(pipefd) == 0) {
                write(pipefd[1], buf, n);
                close(pipefd[1]);
                FILE* spoofed = fdopen(pipefd[0], "r");
                if (spoofed) {
                    core::Logger::instance().log(core::Category::AcAntidebug,
                                                 [](core::JsonWriter& w) {
                                                     w.field("check", "TracerPid");
                                                     w.field("spoofed", true);
                                                 });
                    return spoofed;
                }
                close(pipefd[0]);
            }
            return r.real.fopen(pathname, mode);
        }
        core::Logger::instance().log(core::Category::AcAntidebug,
                                     [](core::JsonWriter& w) { w.field("check", "TracerPid"); });
    }
    return result;
}
__attribute__((visibility("default"))) ssize_t readlink(const char* pathname, char* buf,
                                                        size_t bufsiz) {
    auto& r = reg();
    void* ra = __builtin_return_address(0);
    hooks::libc::try_lazy_detect(ra);
    ssize_t ret = r.real.readlink(pathname, buf, bufsiz);
    bool is_ac = from_ac(ra);
    if (is_ac || (pathname && std::strstr(pathname, "/proc/self"))) {
        char caller[64];
        format_caller(ra, caller, sizeof(caller));
        char result_str[1024];
        if (ret > 0) {
            std::size_t len = static_cast<std::size_t>(ret) < sizeof(result_str) - 1
                                  ? static_cast<std::size_t>(ret)
                                  : sizeof(result_str) - 1;
            std::memcpy(result_str, buf, len);
            result_str[len] = '\0';
        } else {
            result_str[0] = '\0';
        }
        core::Logger::instance().log(core::Category::IoReadlink, [&](core::JsonWriter& w) {
            w.field("path", pathname);
            if (ret > 0)
                w.field("result", result_str);
            else
                w.key("result").value_null();
            w.field("ac", is_ac);
            w.field("at", caller);
        });
    }
    return ret;
}
__attribute__((visibility("default"))) FILE* popen(const char* command, const char* type) {
    auto& r = reg();
    void* ra = __builtin_return_address(0);
    hooks::libc::try_lazy_detect(ra);
    bool is_ac = from_ac(ra);
    char caller[64];
    format_caller(ra, caller, sizeof(caller));
    auto intent = ac::semantics::classify_popen(command ? command : "");
    core::Logger::instance().log(core::Category::Exec, [&](core::JsonWriter& w) {
        w.field("cmd", command);
        w.field("ac", is_ac);
        w.field("at", caller);
        w.field("intent", ac::semantics::popen_intent_str(intent));
        if (intent == ac::semantics::PopenIntent::HwQuery) {
            auto dev = ac::semantics::extract_device_from_udevadm(command ? command : "");
            if (!dev.empty()) {
                char dev_buf[64]{};
                std::memcpy(dev_buf, dev.data(), dev.size() < 63 ? dev.size() : 63);
                w.field("device", dev_buf);
            }
        }
    });
    return r.real.popen(command, type);
}
__attribute__((visibility("default"))) char* getenv(const char* name) {
    auto& r = reg();
    void* ra = __builtin_return_address(0);
    char* result = r.real.getenv(name);
    if (from_ac(ra)) {
        char caller[64];
        format_caller(ra, caller, sizeof(caller));
        core::Logger::instance().log(core::Category::Env, [&](core::JsonWriter& w) {
            w.field("name", name);
            w.field("value", result);
            w.field("at", caller);
        });
    }
    return result;
}
__attribute__((visibility("default"))) long syscall(long number, ...) {
    auto& r = reg();
    va_list ap;
    va_start(ap, number);
    long a1 = va_arg(ap, long);
    long a2 = va_arg(ap, long);
    long a3 = va_arg(ap, long);
    long a4 = va_arg(ap, long);
    long a5 = va_arg(ap, long);
    long a6 = va_arg(ap, long);
    va_end(ap);
    long ret = r.real.syscall(number, a1, a2, a3, a4, a5, a6);
    void* ra = __builtin_return_address(0);
    if (from_ac(ra)) {
        char caller[64];
        format_caller(ra, caller, sizeof(caller));
        core::Logger::instance().log(core::Category::Syscall, [&](core::JsonWriter& w) {
            w.field("nr", number);
            w.field_hex("a1", static_cast<std::uintptr_t>(a1));
            w.field("ret", ret);
            w.field("at", caller);
        });
    }
    return ret;
}
__attribute__((visibility("default"))) void* dlopen(const char* filename, int flags) {
    auto& r = reg();
    void* ra = __builtin_return_address(0);
    void* handle = r.real.dlopen(filename, flags);
    if (filename && std::strstr(filename, "AuthNative")) {
        ac::ModuleTracker::instance().on_dlopen(filename, handle);
    } else if (from_ac(ra)) {
        char caller[64];
        format_caller(ra, caller, sizeof(caller));
        bool is_hostfxr = filename && std::strstr(filename, "hostfxr");
        auto cat = is_hostfxr ? core::Category::AcBridge : core::Category::DlOpen;
        core::Logger::instance().log(cat, [&](core::JsonWriter& w) {
            w.field("path", filename);
            w.field("flags", flags);
            w.field_hex("handle", reinterpret_cast<std::uintptr_t>(handle));
            w.field("at", caller);
        });
    }
    return handle;
}
__attribute__((visibility("default"))) void* dlsym(void* handle, const char* symbol) {
    auto& r = reg();
    if (r.is_resolving())
        return r.real.dlsym(handle, symbol);
    void* result = r.real.dlsym(handle, symbol);
    void* ra = __builtin_return_address(0);
    auto& mt = ac::ModuleTracker::instance();
    bool is_ac = from_ac(ra);
    bool is_ac_handle = (handle == mt.handle() && mt.handle() != nullptr);
    if (is_ac || is_ac_handle) {
        char caller[64];
        format_caller(ra, caller, sizeof(caller));
        bool is_hostfxr = symbol && std::strstr(symbol, "hostfxr");
        auto cat = is_hostfxr ? core::Category::AcBridge : core::Category::DlSym;
        core::Logger::instance().log(cat, [&](core::JsonWriter& w) {
            w.field("symbol", symbol);
            w.field_hex("result", reinterpret_cast<std::uintptr_t>(result));
            w.field("at", caller);
        });
    }
    if (is_ac_handle && result) {
        return ac::ExportInterceptor::instance().intercept_dlsym_result(symbol, result);
    }
    return result;
}
__attribute__((visibility("default"))) int dlclose(void* handle) {
    auto& r = reg();
    ac::ModuleTracker::instance().on_dlclose(handle);
    return r.real.dlclose(handle);
}
__attribute__((visibility("default"))) int dl_iterate_phdr(int (*callback)(struct dl_phdr_info*,
                                                                           size_t, void*),
                                                           void* data) {
    auto& r = reg();
    return r.real.dl_iterate_phdr(callback, data);
}
struct ThreadWrapCtx {
    void* (*real_start)(void*);
    void* real_arg;
    std::uintptr_t entry_offset;
};
static void* thread_wrapper(void* arg) {
    auto* ctx = static_cast<ThreadWrapCtx*>(arg);
    auto start = ctx->real_start;
    auto real_arg = ctx->real_arg;
    auto offset = ctx->entry_offset;
    delete ctx;
    core::Logger::instance().log(core::Category::AcThread, [offset](core::JsonWriter& w) {
        w.field("event", "started");
        w.field_hex("entry", offset);
    });
    void* ret = start(real_arg);
    core::Logger::instance().log(core::Category::AcThread, [offset](core::JsonWriter& w) {
        w.field("event", "exiting");
        w.field_hex("entry", offset);
    });
    return ret;
}
__attribute__((visibility("default"))) int pthread_create(pthread_t* thread,
                                                          const pthread_attr_t* attr,
                                                          void* (*start_routine)(void*),
                                                          void* arg) {
    auto& r = reg();
    void* ra = __builtin_return_address(0);
    if (from_ac(ra)) {
        auto& mt = ac::ModuleTracker::instance();
        auto offset = mt.offset_of(reinterpret_cast<void*>(start_routine));
        char caller[64];
        format_caller(ra, caller, sizeof(caller));
        core::Logger::instance().log(core::Category::AcThread, [&](core::JsonWriter& w) {
            w.field("event", "creating");
            w.field_hex("entry", offset);
            w.field("at", caller);
        });
        auto* ctx = new ThreadWrapCtx{start_routine, arg, offset};
        return r.real.pthread_create(thread, attr, thread_wrapper, ctx);
    }
    return r.real.pthread_create(thread, attr, start_routine, arg);
}
static void* maps_monitor(void*) {
    auto& r = hooks::HookRegistry::instance();
    for (int i = 0; i < 30; i++) {
        if (ac::ModuleTracker::instance().is_loaded())
            break;
        usleep(200'000);
    }
    if (!ac::ModuleTracker::instance().is_loaded())
        return nullptr;
    usleep(500'000);
    FILE* f = r.real.fopen("/proc/self/maps", "r");
    if (f) {
        char line[512];
        while (fgets(line, sizeof(line), f)) {
            if (std::strstr(line, "AuthNative")) {
                line[strcspn(line, "\n")] = '\0';
                core::Logger::instance().log(core::Category::MemoryMap,
                                             [&](core::JsonWriter& w) { w.field("line", line); });
            }
        }
        fclose(f);
    }
    return nullptr;
}
__attribute__((constructor, visibility("default"))) void introspect_init() {
    auto& r = hooks::HookRegistry::instance();
    r.resolve_all();
    core::Logger::instance().init();
    core::Logger::instance().log(core::Category::System, [](core::JsonWriter& w) {
        w.field("event", "loaded");
        w.field("pid", static_cast<std::int64_t>(getpid()));
        w.field("version", "2.0");
    });
    pthread_t mon;
    r.real.pthread_create(&mon, nullptr, maps_monitor, nullptr);
    pthread_detach(mon);
}
__attribute__((destructor, visibility("default"))) void introspect_fini() {
    core::Logger::instance().log(core::Category::System,
                                 [](core::JsonWriter& w) { w.field("event", "unloading"); });
    core::Logger::instance().shutdown();
}
}
