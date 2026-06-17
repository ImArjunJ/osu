add_executable(osu_ac_ptrace
    ptrace_tracer.cpp
)

target_compile_options(osu_ac_ptrace PRIVATE -O2 -g)
set_target_properties(osu_ac_ptrace PROPERTIES
    CXX_STANDARD 23
)
