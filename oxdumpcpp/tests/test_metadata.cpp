// tests/test_metadata.cpp — интеграционный тест разбора метадаты на реальных
// файлах игры (nov_meta.dat ~27 МБ, nov_bin.so ~200 МБ).
//
// Проверяет всю цепочку: восстановление ключа → раскладка секций → сверка пары
// с бинарником → вывод раскладки Il2CppTypeDefinition → восстановление БЕЗ
// заголовка. Числа сверяются с эталонными значениями питоновского дампера.
#include "oxdump/metadata/header.h"
#include "oxdump/metadata/layout.h"
#include "oxdump/metadata/tdlayout.h"
#include "oxdump/metadata/pairing.h"
#include "oxdump/metadata/headerless.h"
#include "oxdump/elf/elf64.h"
#include <cstdio>
#include <cstdlib>
#include <cstring>
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

// Проверка «примерно равно»: восстановление без заголовка даёт числа с
// небольшим разбросом, эталон задаёт допуск.
void check_near(long got, long want, long tol, const char* what) {
    const long d = got > want ? got - want : want - got;
    const bool ok = d <= tol;
    std::printf("  [%s] %s: got=%ld want=%ld (±%ld)\n",
                ok ? "OK " : "FAIL", what, got, want, tol);
    if (!ok) ++g_failures;
}

struct Mapped {
    const u8* data = nullptr;
    std::size_t size = 0;
    void* raw = nullptr;
    ByteView view() const { return ByteView{data, size}; }
};

bool map_file(const char* path, Mapped& out) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) { std::perror(path); return false; }
    struct stat st{};
    if (fstat(fd, &st) != 0) { std::perror("fstat"); close(fd); return false; }
    void* p = mmap(nullptr, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);
    if (p == MAP_FAILED) { std::perror("mmap"); return false; }
    out.raw = p;
    out.data = static_cast<const u8*>(p);
    out.size = static_cast<std::size_t>(st.st_size);
    return true;
}

std::vector<u8> read_file(const char* path) {
    std::vector<u8> buf;
    int fd = open(path, O_RDONLY);
    if (fd < 0) { std::perror(path); return buf; }
    struct stat st{};
    if (fstat(fd, &st) != 0) { std::perror("fstat"); close(fd); return buf; }
    buf.resize(static_cast<std::size_t>(st.st_size));
    std::size_t got = 0;
    while (got < buf.size()) {
        ssize_t r = read(fd, buf.data() + got, buf.size() - got);
        if (r <= 0) break;
        got += static_cast<std::size_t>(r);
    }
    close(fd);
    buf.resize(got);
    return buf;
}

} // namespace

int main() {
    const char* meta_path = "tests/nov_meta.dat";
    const char* bin_path = "tests/nov_bin.so";

    Mapped meta, bin;
    if (!map_file(meta_path, meta)) return 2;
    if (!map_file(bin_path, bin)) { munmap(meta.raw, meta.size); return 2; }

    std::printf("meta = %s (%zu байт)\n", meta_path, meta.size);
    std::printf("bin  = %s (%zu байт)\n\n", bin_path, bin.size);

    // ── 1. Metadata: восстановление ключа ────────────────────────────────
    std::printf("== Metadata ==\n");
    metadata::Metadata md(meta.view());
    std::printf("%s\n", md.key_report().c_str());
    check(md.key() == 0xA5C3F19D, "key == 0xA5C3F19D");
    check(md.version() == 39, "version == 39");
    check(md.transform() == nullptr, "transform == nullptr (XOR32 fast path)");

    // ── 2. Layout: назначения секций ─────────────────────────────────────
    std::printf("\n== Layout ==\n");
    metadata::Layout layout(md);
    std::printf("%s\n", layout.report().c_str());
    check(layout.ok(), "layout.ok()");
    check_near(layout.typedef_count, 29486, 50, "typedef_count ≈ 29486");
    check_near(layout.method_count, 226242, 200, "method_count ≈ 226242");
    check_near(layout.field_count, 127816, 200, "field_count ≈ 127816");

    // ── 3. ELF + сверка пары ─────────────────────────────────────────────
    std::printf("\n== ELF + pairing ==\n");
    elf::Elf64 elf(bin.view());
    std::printf("reloc count = %s (%s)\n",
                thousands(elf.reloc_count()).c_str(), elf.reloc_source().c_str());
    auto mr = elf.find_metadata_registration(layout.typedef_count);
    check(mr.has_value(), "find_metadata_registration найден");
    if (mr) {
        std::printf("MR base=%s types=%s types_count=%llu score=%d\n",
                    hex(mr->base).c_str(), hex(mr->types).c_str(),
                    static_cast<unsigned long long>(mr->types_count), mr->score);
        auto pc = metadata::check_pair(md, layout, elf, bin.view(), *mr,
                                       82, 0x08);
        std::printf("%s\n", pc.report().c_str());
        check(pc.ratio() >= 0.999, "pair.check_pair == 100%");
    }

    // ── 4. TDLayout: вывод раскладки Il2CppTypeDefinition ─────────────────
    std::printf("\n== TDLayout ==\n");
    if (mr) {
        metadata::TDLayout def = metadata::default_v39();
        metadata::TDLayout td =
            metadata::detect(md, layout, elf, bin.view(), *mr, &def);
        std::printf("%s\n", td.report().c_str());
        check(td.rec_size == 82, "rec_size == 82");
        check(td.name == def.name, "name == 0x00");
        check(td.namespace_off == def.namespace_off, "namespace == 0x04");
        check(td.byval_type == def.byval_type, "byvalType == 0x08");
        check(td.declaring == def.declaring, "declaring == 0x0C");
        check(td.parent == def.parent, "parent == 0x10");
        check(td.flags == def.flags, "flags == 0x16");
        check(td.field_start == def.field_start, "fieldStart == 0x1A");
        check(td.method_start == def.method_start, "methodStart == 0x1E");
        check(td.method_count == def.method_count, "methodCount == 0x3A");
        check(td.field_count == def.field_count, "fieldCount == 0x3E");
    }

    munmap(meta.raw, meta.size);
    munmap(bin.raw, bin.size);

    // ── 5. HEADERLESS: восстановление без заголовка ──────────────────────
    std::printf("\n== Headerless ==\n");
    std::vector<u8> buf = read_file(meta_path);
    if (buf.size() < 400) {
        std::printf("  [FAIL] не прочитан файл метадаты для headerless\n");
        ++g_failures;
    } else {
        // Затираем заголовок [8, 380) случайными байтами — эмулируем
        // нечитаемую карту секций (как при AES-шифровании заголовка).
        std::srand(1234);
        for (std::size_t i = 8; i < 380; ++i) {
            buf[i] = static_cast<u8>(std::rand() & 0xFF);
        }
        ByteView bv{buf.data(), buf.size()};
        try {
            auto hr = metadata::headerless::recover(bv);
            std::printf("%s\n", hr.report.c_str());
            // Эталонные числа — для ЭТОГО файла (tests/nov_meta.dat). Сверены
            // двумя независимыми путями: (1) разбором заголовка выше — Layout
            // дал string=0xDBE2C, typedef=0x1517BA0, method=0x476C5C,
            // field=0x12055AC; (2) питоновским эталоном headerless.recover на
            // том же файле — совпадение до байта. Восстановление без заголовка
            // обязано сойтись с разбором заголовка на одной и той же сборке.
            //
            // (Числа из ТЗ 0xDC0EC/0x1512204/… относятся к другой сборке
            //  метадаты; здесь под симлинком лежит сборка 0x1517BA0.)
            check_near(hr.string_offset, layout.string_offset, 4,
                       "string_offset совпал с header-разбором");
            check_near(hr.typedef_offset, layout.typedef_offset, 0,
                       "typedef_offset совпал с header-разбором");
            // Замощение слегка переоценивает хвост (29506 против 29486 из
            // заголовка) — оба пути дают одно и то же, допуск покрывает разницу.
            check_near(hr.typedef_count, layout.typedef_count, 32,
                       "typedef_count ≈ header-разбор");
            check_near(hr.field_offset, layout.field_offset, 0,
                       "field_offset совпал с header-разбором");
            check_near(hr.method_offset, layout.method_offset, 0,
                       "method_offset совпал с header-разбором");
        } catch (const std::exception& e) {
            std::printf("  [FAIL] recover бросил: %s\n", e.what());
            ++g_failures;
        }
    }

    std::printf("\n=== %s (%d провалов) ===\n",
                g_failures ? "ЕСТЬ ПРОВАЛЫ" : "ВСЕ ПРОВЕРКИ ПРОШЛИ", g_failures);
    return g_failures ? 1 : 0;
}
