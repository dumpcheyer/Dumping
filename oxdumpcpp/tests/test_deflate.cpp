// tests/test_deflate.cpp — проверка собственного DEFLATE-энкодера
// (include/oxdump/io/deflate.h) через СИСТЕМНЫЙ zlib (raw inflate).
//
// Наш энкодер выдаёт «сырой» поток RFC 1951 (без zlib/gzip-обёртки), какой
// ждёт ZIP method 8. Чтобы проверить корректность, распаковываем его через
// zlib с windowBits = -15 (raw inflate) и сверяем байт-в-байт.
//
// ВАЖНО: zlib линкуется ТОЛЬКО в этот тест. Основной бинарь oxdump остаётся
// без внешних зависимостей.
//
// Сборка (см. Makefile, цель test-deflate). На этой машине нет libz.so
// (только libz.so.1) и нет совместимого системного zlib.h, поэтому линкуемся
// напрямую с /lib64/libz.so.1 и берём минимальный прототип из tests/zlib_min.h:
//   g++ -std=c++17 -O2 -Iinclude tests/test_deflate.cpp \
//       /lib64/libz.so.1 -o build/test_deflate
#include "oxdump/io/deflate.h"
#include "zlib_min.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <chrono>
#include <string>
#include <vector>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

using namespace oxdump;

namespace {

int g_failures = 0;
void check(bool cond, const char* what) {
    std::printf("  [%s] %s\n", cond ? "OK " : "FAIL", what);
    if (!cond) ++g_failures;
}

// Raw inflate через zlib: windowBits = -15 → без ожидания zlib-заголовка.
// Возвращает распакованные байты; success=false при ошибке.
std::vector<u8> raw_inflate(const std::vector<u8>& comp, std::size_t expect,
                            bool& success) {
    std::vector<u8> out(expect ? expect : 1);
    z_stream zs{};
    if (inflateInit2(&zs, -15) != Z_OK) { success = false; return {}; }
    zs.next_in   = const_cast<Bytef*>(comp.data());
    zs.avail_in  = static_cast<uInt>(comp.size());
    zs.next_out  = out.data();
    zs.avail_out = static_cast<uInt>(out.size());

    int rc;
    while ((rc = inflate(&zs, Z_NO_FLUSH)) != Z_STREAM_END) {
        if (rc != Z_OK && rc != Z_BUF_ERROR) { break; }
        if (zs.avail_out == 0) {
            std::size_t used = out.size();
            out.resize(out.size() * 2 + 64);
            zs.next_out  = out.data() + used;
            zs.avail_out = static_cast<uInt>(out.size() - used);
        } else if (rc == Z_BUF_ERROR) {
            break; // нет прогресса — выходим
        }
    }
    std::size_t produced = zs.total_out;
    inflateEnd(&zs);
    success = (rc == Z_STREAM_END);
    out.resize(produced);
    return out;
}

bool roundtrip(const std::vector<u8>& in, const char* label) {
    std::vector<u8> comp = io::deflate_compress(in.data(), in.size());
    bool ok = false;
    std::vector<u8> dec = raw_inflate(comp, in.size(), ok);
    bool identical = ok && dec.size() == in.size() &&
                     (in.empty() || std::memcmp(dec.data(), in.data(), in.size()) == 0);
    std::printf("  [%s] %-28s  %zu -> %zu bytes (%.1f%%)\n",
                identical ? "OK " : "FAIL", label, in.size(), comp.size(),
                in.empty() ? 0.0 : 100.0 * comp.size() / in.size());
    if (!identical) ++g_failures;
    return identical;
}

std::vector<u8> str_bytes(const std::string& s) {
    return std::vector<u8>(s.begin(), s.end());
}

} // namespace

int main() {
    std::printf("=== test_deflate ===\n");

    // 1. Малый известный вход.
    check(roundtrip(str_bytes("Hello, World!"), "hello"), "hello round-trip");

    // Пустой вход и одиночный байт — граничные случаи.
    roundtrip({}, "empty");
    roundtrip(str_bytes("A"), "single-byte");

    // Сильно повторяющийся вход — проверяем, что LZ77 реально жмёт.
    {
        std::string rep;
        for (int i = 0; i < 5000; ++i) rep += "public class Foo { int x; }\n";
        std::vector<u8> b = str_bytes(rep);
        std::vector<u8> comp = io::deflate_compress(b.data(), b.size());
        bool ok = false;
        std::vector<u8> dec = raw_inflate(comp, b.size(), ok);
        bool identical = ok && dec.size() == b.size() &&
                         std::memcmp(dec.data(), b.data(), b.size()) == 0;
        std::printf("  [%s] repetitive text          %zu -> %zu bytes (%.1f%%)\n",
                    identical ? "OK " : "FAIL", b.size(), comp.size(),
                    100.0 * comp.size() / b.size());
        if (!identical) ++g_failures;
        check(comp.size() < b.size() / 10, "repetitive text compresses <10%");
    }

    // Псевдослучайный вход — round-trip должен работать, а размер не раздуться.
    {
        std::vector<u8> rnd(200000);
        u32 s = 0x12345678u;
        for (auto& c : rnd) { s = s * 1103515245u + 12345u; c = static_cast<u8>(s >> 16); }
        std::vector<u8> comp = io::deflate_compress(rnd.data(), rnd.size());
        bool ok = false;
        std::vector<u8> dec = raw_inflate(comp, rnd.size(), ok);
        bool identical = ok && dec.size() == rnd.size() &&
                         std::memcmp(dec.data(), rnd.data(), rnd.size()) == 0;
        check(identical, "random data round-trip");
        check(comp.size() <= rnd.size() + rnd.size() / 1000 + 64,
              "random data does not bloat (STORED fallback)");
    }

    // 2 + 3. Реальный dump.cs, если доступен: round-trip и ratio.
    //   Путь передаётся аргументом argv[1] (см. Makefile). Читаем часть/весь
    //   файл, проверяем распаковку и целевой ratio ≤ 40%.
    const char* dump_path = std::getenv("OXDUMP_DUMPCS");
    if (dump_path) {
        int fd = open(dump_path, O_RDONLY);
        if (fd >= 0) {
            struct stat st{};
            fstat(fd, &st);
            std::size_t total = static_cast<std::size_t>(st.st_size);
            void* p = mmap(nullptr, total, PROT_READ, MAP_PRIVATE, fd, 0);
            close(fd);
            if (p != MAP_FAILED) {
                const u8* base = static_cast<const u8*>(p);

                // (2) 100 КБ round-trip.
                {
                    std::size_t sz = total < 100000 ? total : 100000;
                    std::vector<u8> chunk(base, base + sz);
                    check(roundtrip(chunk, "dump.cs 100KB"), "dump.cs 100KB round-trip");
                }

                // (3) до 30 МБ: ratio ≤ 40% и таймингом.
                {
                    std::size_t sz = total < 30u * 1024 * 1024 ? total : 30u * 1024 * 1024;
                    auto t0 = std::chrono::steady_clock::now();
                    std::vector<u8> comp = io::deflate_compress(base, sz);
                    auto t1 = std::chrono::steady_clock::now();
                    double secs = std::chrono::duration<double>(t1 - t0).count();
                    double ratio = 100.0 * comp.size() / sz;
                    std::printf("  ..  dump.cs %.1f MB -> %.1f MB  ratio=%.1f%%  (%.2fs, %.1f MB/s)\n",
                                sz / 1048576.0, comp.size() / 1048576.0, ratio,
                                secs, sz / 1048576.0 / (secs > 0 ? secs : 1e-9));
                    bool ok = false;
                    std::vector<u8> dec = raw_inflate(comp, sz, ok);
                    bool identical = ok && dec.size() == sz &&
                                     std::memcmp(dec.data(), base, sz) == 0;
                    check(identical, "dump.cs large round-trip");
                    check(ratio <= 40.0, "dump.cs ratio <= 40%");
                }
                munmap(p, total);
            }
        } else {
            std::printf("  ..  OXDUMP_DUMPCS set but unreadable: %s (skipped)\n", dump_path);
        }
    } else {
        std::printf("  ..  OXDUMP_DUMPCS not set — skipping real dump.cs tests\n");
    }

    std::printf("=== %s (%d failure%s) ===\n",
                g_failures == 0 ? "PASS" : "FAIL",
                g_failures, g_failures == 1 ? "" : "s");
    return g_failures == 0 ? 0 : 1;
}
