# cmake/windows-toolchain.cmake — cross-compile oxdump for Windows x86-64
# using the MinGW-w64 GCC toolchain (x86_64-w64-mingw32-*).
#
# Usage:
#     cmake -B build-win -DCMAKE_TOOLCHAIN_FILE=cmake/windows-toolchain.cmake
#     cmake --build build-win -j
#     file build-win/oxdump.exe        # -> PE32+ executable (console) x86-64
#
# Requirements (install ONE of these on the build host):
#     Debian/Ubuntu : sudo apt install mingw-w64
#     Fedora/RHEL   : sudo dnf install mingw64-gcc-c++
#     Arch          : sudo pacman -S mingw-w64-gcc
#     macOS (brew)  : brew install mingw-w64
#
# The produced oxdump.exe is a static, self-contained console binary — the
# static-libgcc/libstdc++ flags below mean it runs on a bare Windows box with
# no MinGW runtime DLLs to ship.

set(CMAKE_SYSTEM_NAME Windows)
set(CMAKE_SYSTEM_PROCESSOR x86_64)

# Cross toolchain prefix — override with -DTOOLCHAIN_PREFIX=... if your distro
# uses a different triple (rare).
if(NOT DEFINED TOOLCHAIN_PREFIX)
    set(TOOLCHAIN_PREFIX x86_64-w64-mingw32)
endif()

set(CMAKE_C_COMPILER   ${TOOLCHAIN_PREFIX}-gcc)
set(CMAKE_CXX_COMPILER ${TOOLCHAIN_PREFIX}-g++)
set(CMAKE_RC_COMPILER  ${TOOLCHAIN_PREFIX}-windres)

# Where the target environment lives. Search headers/libs there, but run
# host programs (the compiler itself) from the host.
set(CMAKE_FIND_ROOT_PATH /usr/${TOOLCHAIN_PREFIX})
set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_PACKAGE ONLY)

# Statically link the GCC / libstdc++ runtimes and the winpthreads shim so the
# resulting .exe has no external DLL dependencies.
set(_mingw_static "-static -static-libgcc -static-libstdc++")
set(CMAKE_EXE_LINKER_FLAGS_INIT "${_mingw_static}")

# .exe suffix is set automatically by CMake for the Windows system name.
