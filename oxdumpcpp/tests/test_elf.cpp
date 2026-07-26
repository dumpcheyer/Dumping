// tests/test_elf.cpp — дымовой тест разбора ELF64 на реальной libil2cpp.so.
// mmap файла в ByteView, конструирование Elf64, печать ключевых чисел.
#include "oxdump/elf/elf64.h"
#include <cstdio>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

using namespace oxdump;

int main() {
    const char* path = "tests/nov_bin.so";
    int fd = open(path, O_RDONLY);
    if (fd < 0) { std::perror("open"); return 1; }

    struct stat st{};
    if (fstat(fd, &st) != 0) { std::perror("fstat"); close(fd); return 1; }

    void* p = mmap(nullptr, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (p == MAP_FAILED) { std::perror("mmap"); close(fd); return 1; }

    ByteView view{static_cast<const u8*>(p), static_cast<std::size_t>(st.st_size)};

    try {
        elf::Elf64 elf(view);
        std::printf("machine        = 0x%X\n", elf.machine());
        std::printf("segments       = %zu\n", elf.segments().size());
        std::printf("mem_end        = 0x%llX\n",
                    static_cast<unsigned long long>(elf.mem_end()));
        std::printf("r_relative     = %u\n",
                    elf.r_relative() ? *elf.r_relative() : 0u);
        std::printf("reloc count    = %s\n",
                    thousands(elf.reloc_count()).c_str());
        std::printf("reloc source   = %s\n", elf.reloc_source().c_str());

        auto pk = elf.packing_check();
        std::printf("packing_check  = packed=%s zeros=%.1f%% (%s)\n",
                    pk.packed ? "true" : "false",
                    pk.zeros_ratio * 100.0, pk.why.c_str());
    } catch (const std::exception& e) {
        std::printf("EXCEPTION: %s\n", e.what());
        munmap(p, st.st_size);
        close(fd);
        return 1;
    }

    munmap(p, st.st_size);
    close(fd);
    return 0;
}
