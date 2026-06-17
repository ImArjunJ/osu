#include <cerrno>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <dirent.h>
#include <fstream>
#include <linux/elf.h>
#include <signal.h>
#include <string>
#include <sys/ptrace.h>
#include <sys/uio.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>
#include <vector>

namespace offsets {
constexpr std::uintptr_t state_enter = 0x12CF10;
constexpr std::uintptr_t sign_thunk = 0x114AA0;
constexpr std::uintptr_t sign_entry = 0x2D3520;
constexpr std::uintptr_t module_size = 0x7C2000;
constexpr std::uintptr_t rwx_start = 0x113000;
constexpr std::uintptr_t rwx_end = 0x794000;
}  // namespace offsets

struct module_info {
    std::uintptr_t base = 0;
    std::string path;
};

module_info find_module(pid_t pid) {
    char maps[64];
    std::snprintf(maps, sizeof(maps), "/proc/%d/maps", pid);
    std::ifstream f(maps);
    std::string line;
    module_info m;
    while (std::getline(f, line)) {
        if (line.find("AuthNative") != std::string::npos) {
            std::sscanf(line.c_str(), "%lx", &m.base);
            auto p = line.find('/');
            if (p != std::string::npos) m.path = line.substr(p);
            break;
        }
    }
    return m;
}

std::vector<pid_t> get_threads(pid_t pid) {
    std::vector<pid_t> tids;
    char path[64];
    std::snprintf(path, sizeof(path), "/proc/%d/task", pid);
    DIR* dir = opendir(path);
    if (!dir) return tids;
    struct dirent* e;
    while ((e = readdir(dir)))
        if (e->d_name[0] != '.') tids.push_back(std::atoi(e->d_name));
    closedir(dir);
    return tids;
}

bool set_hwbp(pid_t tid, int idx, std::uintptr_t addr) {
    auto dr_off = offsetof(struct user, u_debugreg[0]) + idx * sizeof(unsigned long long);
    if (ptrace(PTRACE_POKEUSER, tid, dr_off, addr) < 0) return false;
    auto dr7_off = offsetof(struct user, u_debugreg[7]);
    errno = 0;
    long dr7 = ptrace(PTRACE_PEEKUSER, tid, dr7_off, nullptr);
    if (errno) return false;
    dr7 |= (1UL << (idx * 2));
    dr7 &= ~(0xFUL << (16 + idx * 4));
    return ptrace(PTRACE_POKEUSER, tid, dr7_off, dr7) == 0;
}

void clear_hwbp(pid_t tid, int idx) {
    auto dr7_off = offsetof(struct user, u_debugreg[7]);
    long dr7 = ptrace(PTRACE_PEEKUSER, tid, dr7_off, nullptr);
    dr7 &= ~(1UL << (idx * 2));
    ptrace(PTRACE_POKEUSER, tid, dr7_off, dr7);
}

std::uintptr_t get_rip(pid_t tid) {
    struct user_regs_struct regs;
    struct iovec iov = {&regs, sizeof(regs)};
    if (ptrace(PTRACE_GETREGSET, tid, NT_PRSTATUS, &iov) < 0) return 0;
    return regs.rip;
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::fprintf(stderr, "usage: %s <pid> [--trace-state|--trace-sign] [--max-steps N]\n", argv[0]);
        return 1;
    }

    pid_t pid = std::atoi(argv[1]);
    bool trace_sign = false;
    int max_steps = 5000;

    for (int i = 2; i < argc; i++) {
        if (std::strcmp(argv[i], "--trace-sign") == 0) trace_sign = true;
        if (std::strcmp(argv[i], "--max-steps") == 0 && i + 1 < argc) max_steps = std::atoi(argv[++i]);
    }

    auto mod = find_module(pid);
    if (!mod.base) {
        std::fprintf(stderr, "AuthNative.so not found in pid %d\n", pid);
        return 1;
    }
    std::fprintf(stderr, "AuthNative.so @ 0x%lx\n", mod.base);

    auto threads = get_threads(pid);
    std::vector<pid_t> attached;
    for (auto tid : threads) {
        if (ptrace(PTRACE_ATTACH, tid, nullptr, nullptr) == 0) {
            int st;
            waitpid(tid, &st, 0);
            attached.push_back(tid);
        }
    }
    std::fprintf(stderr, "attached %zu threads\n", attached.size());

    auto bp_offset = trace_sign ? offsets::sign_thunk : offsets::state_enter;
    auto bp_addr = mod.base + bp_offset;
    auto bp_addr2 = trace_sign ? mod.base + offsets::sign_entry : 0UL;

    for (auto tid : attached) {
        set_hwbp(tid, 0, bp_addr);
        if (bp_addr2) set_hwbp(tid, 1, bp_addr2);
        ptrace(PTRACE_SETOPTIONS, tid, nullptr, PTRACE_O_TRACECLONE);
    }

    for (auto tid : attached) ptrace(PTRACE_CONT, tid, nullptr, nullptr);
    std::fprintf(stderr, "waiting...\n");

    pid_t hit_tid = 0;
    while (true) {
        int status;
        pid_t stopped = waitpid(-1, &status, 0);
        if (stopped < 0) break;
        if (!WIFSTOPPED(status)) continue;

        int sig = WSTOPSIG(status);
        if (sig == SIGTRAP) {
            int event = (status >> 16) & 0xFF;
            if (event == PTRACE_EVENT_CLONE) {
                unsigned long new_tid = 0;
                ptrace(PTRACE_GETEVENTMSG, stopped, nullptr, &new_tid);
                if (new_tid > 0) {
                    int ns;
                    waitpid(new_tid, &ns, 0);
                    set_hwbp(new_tid, 0, bp_addr);
                    if (bp_addr2) set_hwbp(new_tid, 1, bp_addr2);
                    ptrace(PTRACE_SETOPTIONS, new_tid, nullptr, PTRACE_O_TRACECLONE);
                    ptrace(PTRACE_CONT, new_tid, nullptr, nullptr);
                    attached.push_back(new_tid);
                }
                ptrace(PTRACE_CONT, stopped, nullptr, nullptr);
                continue;
            }

            auto rip = get_rip(stopped);
            auto off = rip - mod.base;
            if (off == bp_offset || off == offsets::sign_entry || off == bp_offset + 1 || off == offsets::sign_entry + 1) {
                hit_tid = stopped;
                std::fprintf(stderr, "hit tid=%d offset=0x%lx\n", hit_tid, off);
                break;
            }
            ptrace(PTRACE_CONT, stopped, nullptr, nullptr);
        } else {
            ptrace(PTRACE_CONT, stopped, nullptr, sig);
        }
    }

    if (hit_tid) {
        auto start = std::chrono::steady_clock::now();
        for (int i = 0; i < max_steps; i++) {
            auto rip = get_rip(hit_tid);
            if (!rip) break;
            auto off = rip - mod.base;
            auto us = std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::steady_clock::now() - start).count();
            std::printf("{\"ts\":%lu,\"rip\":\"0x%lx\",\"off\":\"0x%lx\"}\n", us, rip, off);
            if (rip < mod.base || rip >= mod.base + offsets::module_size) break;
            if (off >= 0x6BC000 && off < 0x6D1000) break;
            if (ptrace(PTRACE_SINGLESTEP, hit_tid, nullptr, nullptr) < 0) break;
            int st;
            waitpid(hit_tid, &st, 0);
            if (!WIFSTOPPED(st)) break;
        }
    }

    for (auto tid : attached) {
        clear_hwbp(tid, 0);
        clear_hwbp(tid, 1);
        ptrace(PTRACE_DETACH, tid, nullptr, nullptr);
    }
    return 0;
}
