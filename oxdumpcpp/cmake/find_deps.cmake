# cmake/find_deps.cmake — dependency / toolchain sanity check.
#
# oxdump has ZERO external dependencies: only the C++17 standard library
# (no Boost, no zlib, no miniz). So this file does not go looking for
# libraries — instead it verifies that the selected toolchain actually
# implements the C++17 features oxdump relies on. If a cross toolchain is
# too old, we want a clear error at configure time, not a wall of template
# errors halfway through the build.
#
# Included from the top-level CMakeLists.txt after the C++ standard is set.

include(CheckCXXSourceCompiles)
include(CheckCXXCompilerFlag)

message(STATUS "find_deps: verifying C++17 toolchain support "
               "(oxdump has no external dependencies)")

# Compile the probe as C++17 explicitly, mirroring the project settings.
set(CMAKE_REQUIRED_FLAGS "-std=c++17")
if(NOT WIN32)
    # std::filesystem may live in a separate lib on older GCC; give the probe
    # a fair chance by offering the fallback library if it exists.
    set(CMAKE_REQUIRED_LIBRARIES "")
endif()

# One probe that touches every C++17 feature oxdump uses:
#   - <string_view>, <optional>, structured bindings
#   - if-constexpr, inline variables
#   - <filesystem>
#   - nested namespace definitions (namespace a::b {})
check_cxx_source_compiles("
    #include <string_view>
    #include <optional>
    #include <filesystem>
    #include <cstdint>
    namespace ox::probe {
        inline constexpr int kInline = 17;   // inline variable
        template <typename T>
        int describe(T v) {
            if constexpr (sizeof(T) >= 4) { return kInline; }   // if constexpr
            else { return 0; }
        }
    }
    int main() {
        std::string_view sv = \"c++17\";
        std::optional<int> o = 42;
        auto [a, b] = std::pair<int,int>{1, 2};   // structured bindings
        namespace fs = std::filesystem;
        (void)fs::path{\".\"};
        return (sv.size() > 0 && o && (a + b) == 3)
             ? 0 : ox::probe::describe<std::uint64_t>(0);
    }
" OXDUMP_HAS_CXX17)

unset(CMAKE_REQUIRED_FLAGS)
unset(CMAKE_REQUIRED_LIBRARIES)

if(NOT OXDUMP_HAS_CXX17)
    message(FATAL_ERROR
        "The selected C++ compiler does not provide working C++17 support.\n"
        "  compiler : ${CMAKE_CXX_COMPILER_ID} ${CMAKE_CXX_COMPILER_VERSION}\n"
        "  path     : ${CMAKE_CXX_COMPILER}\n"
        "oxdump needs g++ 9+ / clang++ 10+ (or MinGW-w64 GCC 9+) with a\n"
        "complete <filesystem> implementation. Install a newer toolchain.")
endif()

message(STATUS "find_deps: C++17 OK "
               "(${CMAKE_CXX_COMPILER_ID} ${CMAKE_CXX_COMPILER_VERSION})")
