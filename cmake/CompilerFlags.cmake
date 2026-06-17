add_compile_options(
    -Wall -Wextra -Wpedantic
    -Wno-gnu-zero-variadic-macro-arguments
)

if(CMAKE_BUILD_TYPE STREQUAL "Release" OR CMAKE_BUILD_TYPE STREQUAL "RelWithDebInfo")
    add_compile_options(-O2)
endif()
