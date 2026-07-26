# cmake/macos-toolchain.cmake — cross-compile oxdump for macOS (x86-64 /
# arm64) from a non-macOS host using osxcross, OR build natively / with
# Homebrew clang when already on a Mac.
#
# Cross-compiling to macOS from Linux legally requires the macOS SDK, which
# Apple does not redistribute. The usual route is osxcross
# (https://github.com/tpoechtrager/osxcross), which packages the SDK and a
# clang wrapper named like  o64-clang++  /  x86_64-apple-darwinNN-clang++.
#
# Usage
# -----
#   On a macOS host (native, easiest):
#       cmake -B build-mac            # uses AppleClang / system clang
#       cmake --build build-mac -j
#
#   Cross from Linux with osxcross on PATH:
#       export OSXCROSS_ROOT=/opt/osxcross
#       cmake -B build-mac -DCMAKE_TOOLCHAIN_FILE=cmake/macos-toolchain.cmake
#       cmake --build build-mac -j
#
#   Optionally pick the arch / SDK:
#       -DMACOS_ARCH=arm64            (default x86_64)
#       -DMACOS_MIN_VERSION=11.0
#
# If neither a macOS host nor osxcross is detected, configuration fails with a
# clear message: macOS builds genuinely need osxcross or a macOS machine.

set(CMAKE_SYSTEM_NAME Darwin)

if(NOT DEFINED MACOS_ARCH)
    set(MACOS_ARCH x86_64)
endif()
set(CMAKE_SYSTEM_PROCESSOR ${MACOS_ARCH})

if(NOT DEFINED MACOS_MIN_VERSION)
    set(MACOS_MIN_VERSION 10.15)   # 10.15 = first with complete <filesystem>
endif()

# ── Case 1: building on an actual Mac ────────────────────────────────────
if(APPLE)
    # Native / Homebrew clang. Prefer an explicit Homebrew LLVM if present,
    # otherwise fall back to the system/AppleClang compiler.
    find_program(_brew_clangxx NAMES clang++
        PATHS /opt/homebrew/opt/llvm/bin /usr/local/opt/llvm/bin
        NO_DEFAULT_PATH)
    if(_brew_clangxx)
        set(CMAKE_CXX_COMPILER "${_brew_clangxx}")
        get_filename_component(_brew_bin "${_brew_clangxx}" DIRECTORY)
        find_program(_brew_clang NAMES clang PATHS "${_brew_bin}" NO_DEFAULT_PATH)
        if(_brew_clang)
            set(CMAKE_C_COMPILER "${_brew_clang}")
        endif()
    endif()
    set(CMAKE_OSX_ARCHITECTURES "${MACOS_ARCH}")
    set(CMAKE_OSX_DEPLOYMENT_TARGET "${MACOS_MIN_VERSION}")
    return()
endif()

# ── Case 2: cross from Linux via osxcross ────────────────────────────────
# Locate the osxcross install: env OSXCROSS_ROOT, then common prefixes.
if(DEFINED ENV{OSXCROSS_ROOT})
    set(_osxcross_root "$ENV{OSXCROSS_ROOT}")
else()
    set(_osxcross_root "/opt/osxcross")
endif()
set(_osxcross_bin "${_osxcross_root}/target/bin")

# osxcross ships arch-generic wrappers (o64-clang++) and versioned triples.
find_program(OSXCROSS_CXX
    NAMES o64-clang++ oclang++
          x86_64-apple-darwin23-clang++ x86_64-apple-darwin22-clang++
          x86_64-apple-darwin21-clang++ x86_64-apple-darwin20-clang++
    PATHS "${_osxcross_bin}" ENV PATH)
find_program(OSXCROSS_CC
    NAMES o64-clang oclang
          x86_64-apple-darwin23-clang x86_64-apple-darwin22-clang
          x86_64-apple-darwin21-clang x86_64-apple-darwin20-clang
    PATHS "${_osxcross_bin}" ENV PATH)

if(NOT OSXCROSS_CXX)
    message(FATAL_ERROR
        "macOS cross-compile needs osxcross or a macOS host.\n"
        "  Looked for osxcross clang under: ${_osxcross_bin} and PATH.\n"
        "  Install osxcross (https://github.com/tpoechtrager/osxcross) with a\n"
        "  legally obtained macOS SDK, then set OSXCROSS_ROOT, e.g.:\n"
        "      export OSXCROSS_ROOT=/opt/osxcross\n"
        "  Or build on a real Mac (this toolchain auto-detects APPLE hosts).")
endif()

set(CMAKE_C_COMPILER   "${OSXCROSS_CC}")
set(CMAKE_CXX_COMPILER "${OSXCROSS_CXX}")

set(CMAKE_FIND_ROOT_PATH "${_osxcross_root}/target")
set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_PACKAGE ONLY)

set(CMAKE_OSX_DEPLOYMENT_TARGET "${MACOS_MIN_VERSION}")
