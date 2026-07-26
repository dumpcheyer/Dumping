# oxdump — C++17 IL2CPP dumper. One binary, zero external dependencies.
#
# Quick start (native):
#     cmake -B build-native
#     cmake --build build-native -j
#     ./build-native/oxdump global-metadata.dat libil2cpp.so -o dump.zip
#
# Options:
#     -DCMAKE_BUILD_TYPE=Release   (default) | Debug | RelWithDebInfo
#     -DBUILD_TESTS=ON             build the test suite (default OFF)
#     -DENABLE_LTO=ON              link-time optimization (default ON in Release)
#
# Cross-compile (see README "Cross-compile"):
#     cmake -B build-win -DCMAKE_TOOLCHAIN_FILE=cmake/windows-toolchain.cmake
#     cmake -B build-mac -DCMAKE_TOOLCHAIN_FILE=cmake/macos-toolchain.cmake
#
# Install:
#     cmake --install build-native --prefix /usr/local
#
# The Makefile still works and needs no CMake — this is an alternative.

cmake_minimum_required(VERSION 3.16)

project(oxdump
    VERSION 1.0.0
    DESCRIPTION "C++17 IL2CPP dumper (ELF / Mach-O / PE)"
    LANGUAGES CXX)

# ── Build type default ───────────────────────────────────────────────────
# Single-config generators (Make/Ninja) need an explicit default.
get_property(_is_multi_config GLOBAL PROPERTY GENERATOR_IS_MULTI_CONFIG)
if(NOT _is_multi_config AND NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE "Release" CACHE STRING
        "Build type (Debug/Release/RelWithDebInfo/MinSizeRel)" FORCE)
    set_property(CACHE CMAKE_BUILD_TYPE PROPERTY
        STRINGS Debug Release RelWithDebInfo MinSizeRel)
endif()

# ── Options ──────────────────────────────────────────────────────────────
option(BUILD_TESTS "Build the oxdump test suite" OFF)

# LTO defaults ON for Release-like builds, OFF otherwise.
if(CMAKE_BUILD_TYPE STREQUAL "Release" OR CMAKE_BUILD_TYPE STREQUAL "MinSizeRel")
    set(_lto_default ON)
else()
    set(_lto_default OFF)
endif()
option(ENABLE_LTO "Enable link-time optimization (default ON in Release)" ${_lto_default})

# ── Language standard ────────────────────────────────────────────────────
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Toolchain sanity check: verify real C++17 support (no external deps).
include(${CMAKE_CURRENT_SOURCE_DIR}/cmake/find_deps.cmake)

# ── Common compile settings applied to every oxdump target ───────────────
# Warnings match the Makefile (-Wall -Wextra -Wno-unused-parameter).
add_library(oxdump_flags INTERFACE)
target_include_directories(oxdump_flags INTERFACE
    "${CMAKE_CURRENT_SOURCE_DIR}/include")
if(MSVC)
    target_compile_options(oxdump_flags INTERFACE /W3)
else()
    target_compile_options(oxdump_flags INTERFACE
        -Wall -Wextra -Wno-unused-parameter)
endif()

# pthread on POSIX; the Makefile links -lpthread. On Windows/MinGW the C++
# threading support is baked in, so skip it there.
if(NOT WIN32)
    find_package(Threads REQUIRED)
    target_link_libraries(oxdump_flags INTERFACE Threads::Threads)
endif()

# Some GCC/Clang setups need to be told to link the <filesystem> backend.
include(CheckCXXSourceCompiles)
set(CMAKE_REQUIRED_FLAGS "-std=c++17")
check_cxx_source_compiles("
    #include <filesystem>
    int main() { return std::filesystem::exists(\".\") ? 0 : 1; }
" OXDUMP_FS_NO_EXTRA_LIB)
unset(CMAKE_REQUIRED_FLAGS)
if(NOT OXDUMP_FS_NO_EXTRA_LIB)
    # Older GCC ships std::filesystem in libstdc++fs.
    target_link_libraries(oxdump_flags INTERFACE stdc++fs)
endif()

# ── Sources: discover all src/**/*.cpp automatically ─────────────────────
# CONFIGURE_DEPENDS re-globs when files are added/removed so the build stays
# in sync without re-running cmake by hand.
file(GLOB_RECURSE OXDUMP_SOURCES CONFIGURE_DEPENDS
    "${CMAKE_CURRENT_SOURCE_DIR}/src/*.cpp")

if(NOT OXDUMP_SOURCES)
    message(FATAL_ERROR "No sources found under src/ — nothing to build.")
endif()

# The CLI entry point (its own main()) is kept out of the shared object
# library so the test executables — each with their own main() — can reuse
# every other translation unit without a symbol clash.
set(OXDUMP_MAIN "${CMAKE_CURRENT_SOURCE_DIR}/src/cli/main.cpp")
set(OXDUMP_LIB_SOURCES ${OXDUMP_SOURCES})
list(REMOVE_ITEM OXDUMP_LIB_SOURCES "${OXDUMP_MAIN}")

# Object library shared between the executable and the tests. Built only when
# tests are enabled would save nothing (same TUs), so always use it.
add_library(oxdump_obj OBJECT ${OXDUMP_LIB_SOURCES})
target_link_libraries(oxdump_obj PUBLIC oxdump_flags)

# ── Main executable ──────────────────────────────────────────────────────
add_executable(oxdump "${OXDUMP_MAIN}")
target_link_libraries(oxdump PRIVATE oxdump_obj oxdump_flags)

# ── Link-time optimization ───────────────────────────────────────────────
if(ENABLE_LTO)
    include(CheckIPOSupported)
    check_ipo_supported(RESULT _ipo_ok OUTPUT _ipo_msg LANGUAGES CXX)
    if(_ipo_ok)
        set_property(TARGET oxdump PROPERTY INTERPROCEDURAL_OPTIMIZATION TRUE)
        set_property(TARGET oxdump_obj PROPERTY INTERPROCEDURAL_OPTIMIZATION TRUE)
        message(STATUS "oxdump: LTO enabled")
    else()
        message(WARNING "oxdump: LTO requested but not supported: ${_ipo_msg}")
    endif()
endif()

# ── Install: binary + man page ───────────────────────────────────────────
include(GNUInstallDirs)
install(TARGETS oxdump RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})

set(_manpage "${CMAKE_CURRENT_SOURCE_DIR}/docs/oxdump.1")
if(EXISTS "${_manpage}")
    install(FILES "${_manpage}"
        DESTINATION "${CMAKE_INSTALL_MANDIR}/man1")
endif()

# ── Tests ────────────────────────────────────────────────────────────────
# Each tests/test_*.cpp is a standalone program with its own main(). Every
# test links against oxdump_obj (all TUs except the CLI main) so it can call
# into the parser/model/output code. One executable per file, each registered
# with CTest. The integration tests (metadata/output/generics) need large
# sample files under tests/ and exit non-fatally at run time when absent.
if(BUILD_TESTS)
    enable_testing()

    # A few tests round-trip oxdump's own DEFLATE output through real zlib to
    # prove correctness. This machine has libz.so.1 at runtime but ships no
    # -dev package (no zlib.h, no unversioned .so): tests/zlib_min.h declares
    # the handful of symbols and links the versioned runtime directly. Locate
    # it once; tests that include zlib_min.h link against it.
    find_library(OXDUMP_ZLIB_RUNTIME
        NAMES z libz.so.1 libz.so
        PATHS /lib64 /usr/lib64 /usr/lib /lib)
    if(NOT OXDUMP_ZLIB_RUNTIME)
        # Last resort: the bare versioned runtime path, if present.
        foreach(_zc /lib64/libz.so.1 /usr/lib/x86_64-linux-gnu/libz.so.1)
            if(EXISTS "${_zc}")
                set(OXDUMP_ZLIB_RUNTIME "${_zc}")
                break()
            endif()
        endforeach()
    endif()

    file(GLOB OXDUMP_TEST_SOURCES CONFIGURE_DEPENDS
        "${CMAKE_CURRENT_SOURCE_DIR}/tests/test_*.cpp")
    foreach(_test_src ${OXDUMP_TEST_SOURCES})
        get_filename_component(_test_name "${_test_src}" NAME_WE)

        # Does this test need zlib (via the tests/zlib_min.h shim)?
        file(READ "${_test_src}" _test_body)
        string(FIND "${_test_body}" "zlib_min.h" _needs_zlib)

        if(_needs_zlib GREATER -1 AND NOT OXDUMP_ZLIB_RUNTIME)
            message(STATUS "tests: skipping ${_test_name} (needs zlib runtime, none found)")
            continue()
        endif()

        add_executable(${_test_name} "${_test_src}")
        target_link_libraries(${_test_name} PRIVATE oxdump_obj oxdump_flags)
        target_include_directories(${_test_name} PRIVATE
            "${CMAKE_CURRENT_SOURCE_DIR}/tests")

        if(_needs_zlib GREATER -1)
            target_link_libraries(${_test_name} PRIVATE "${OXDUMP_ZLIB_RUNTIME}")
        endif()

        # Tests read fixtures relative to the project root (e.g.
        # "tests/nov_bin.so"), so run them from there.
        add_test(NAME ${_test_name}
                 COMMAND ${_test_name}
                 WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})
    endforeach()
endif()

# ── Summary ──────────────────────────────────────────────────────────────
message(STATUS "oxdump ${PROJECT_VERSION}")
message(STATUS "  build type : ${CMAKE_BUILD_TYPE}")
message(STATUS "  sources    : ${CMAKE_CXX_COMPILER_ID} ${CMAKE_CXX_COMPILER_VERSION}, C++${CMAKE_CXX_STANDARD}")
message(STATUS "  tests      : ${BUILD_TESTS}")
message(STATUS "  LTO        : ${ENABLE_LTO}")
if(CMAKE_CROSSCOMPILING)
    message(STATUS "  cross      : yes -> ${CMAKE_SYSTEM_NAME}")
endif()
