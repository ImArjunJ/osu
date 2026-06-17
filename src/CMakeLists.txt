add_library(osu_ac_introspect SHARED
    preload.cpp
    core/logger.cpp
    core/config.cpp
    hooks/hook_registry.cpp
    hooks/libc_hooks.cpp
    ac/module_tracker.cpp
    ac/export_interceptor.cpp
    ac/vtable_patcher.cpp
    ac/vm_tracer.cpp
    ac/crypto_hooks.cpp
    ac/adapter_monitor.cpp
    platform/linux/resolver.cpp
    platform/linux/memory.cpp
)

target_include_directories(osu_ac_introspect PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(osu_ac_introspect PRIVATE dl pthread)

target_compile_options(osu_ac_introspect PRIVATE
    -fno-exceptions
    -fno-rtti
    -fvisibility=hidden
    -fvisibility-inlines-hidden
)

set_target_properties(osu_ac_introspect PROPERTIES
    PREFIX "lib"
    POSITION_INDEPENDENT_CODE ON
    INTERPROCEDURAL_OPTIMIZATION OFF
)
