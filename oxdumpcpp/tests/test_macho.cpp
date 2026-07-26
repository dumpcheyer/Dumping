// tests/test_macho.cpp — юнит-тесты разбора Mach-O 64 и совместимости с ELF
// через общий интерфейс binary::BinaryImage.
//
// Три части:
//   1. Диспетчер load(): по первым байтам выбирает Macho или Elf64 и отдаёт
//      их как unique_ptr<BinaryImage> — ровно так CLI выбирает парсер. Гоняем
//      на настоящем ELF (tests/nov_bin.so) и на настоящем Mach-O
//      (tests/macho_bin.dylib), сверяем числа.
//   2. Синтетический Mach-O, собранный в памяти: заголовок + один LC_SEGMENT_64
//      + LC_DYLD_INFO_ONLY с рукописным rebase-байткодом. Проверяем, что все
//      опкоды rebase разобраны и карта релокаций совпадает с ожидаемой —
//      косвенно тестирует и uleb128, и walker.
//   3. Негативные тесты: битая магия, обрезанный заголовок, 32-битный Mach-O.
//
// Настоящий Mach-O — это AppDome-обёртка (не IL2CPP), поэтому find_metadata_
// registration здесь не проверяем: таблиц IL2CPP в нём нет. Но разбор
// заголовка, сегментов и rebase на нём валиден и служит эталоном.
#include "oxdump/macho/macho.h"
#include "oxdump/elf/elf64.h"
#include "oxdump/binary/image.h"
#include <cstdio>
#include <cstring>
#include <memory>
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

// ── диспетчер: то же решение, что принимает CLI ──────────────────────────────
std::unique_ptr<binary::BinaryImage> load(ByteView v) {
    if (v.size >= 4 &&
        (std::memcmp(v.data, "\xcf\xfa\xed\xfe", 4) == 0 ||   // Mach-O 64 LE
         std::memcmp(v.data, "\xce\xfa\xed\xfe", 4) == 0 ||   // Mach-O 32 LE
         std::memcmp(v.data, "\xca\xfe\xba\xbe", 4) == 0 ||   // FAT (BE поля)
         std::memcmp(v.data, "\xbe\xba\xfe\xca", 4) == 0)) {  // FAT (LE поля)
        return std::make_unique<macho::Macho>(v);
    }
    return std::make_unique<elf::Elf64>(v);
}

// mmap файла в ByteView. Возвращает {nullptr,0} при неудаче (файла может не быть).
struct Mapped {
    void* p = nullptr;
    std::size_t size = 0;
    ByteView view() const { return ByteView{static_cast<const u8*>(p), size}; }
    ~Mapped() { if (p && p != MAP_FAILED) munmap(p, size); }
};
bool map_file(const char* path, Mapped& out) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) return false;
    struct stat st{};
    if (fstat(fd, &st) != 0 || st.st_size == 0) { close(fd); return false; }
    void* p = mmap(nullptr, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);
    if (p == MAP_FAILED) return false;
    out.p = p;
    out.size = static_cast<std::size_t>(st.st_size);
    return true;
}

// ── помощники записи в буфер (little-endian) ─────────────────────────────────
void put32(std::vector<u8>& b, std::size_t off, u32 v) {
    for (int i = 0; i < 4; ++i) b[off + i] = (v >> (8 * i)) & 0xFF;
}
void put64(std::vector<u8>& b, std::size_t off, u64 v) {
    for (int i = 0; i < 8; ++i) b[off + i] = (v >> (8 * i)) & 0xFF;
}
void uleb(std::vector<u8>& b, u64 v) {
    do {
        u8 byte = v & 0x7F;
        v >>= 7;
        if (v) byte |= 0x80;
        b.push_back(byte);
    } while (v);
}

// Опкоды rebase — те же константы, что в macho.cpp (здесь для сборки байткода).
constexpr u8 REBASE_OPCODE_DONE                        = 0x00;
constexpr u8 REBASE_OPCODE_SET_TYPE_IMM               = 0x10;
constexpr u8 REBASE_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB = 0x20;
constexpr u8 REBASE_OPCODE_DO_REBASE_IMM_TIMES        = 0x50;
constexpr u8 REBASE_OPCODE_DO_REBASE_ULEB_TIMES_SKIPPING_ULEB = 0x80;

// Собирает минимальный, но валидный Mach-O 64 arm64 dylib с одним сегментом
// __DATA (vmaddr=0x4000, file 0x4000) и LC_DYLD_INFO_ONLY с rebase-байткодом,
// который проставляет указатели по нескольким слотам. Значения-указатели уже
// лежат в файле (как в настоящем Mach-O). Возвращает буфер и ожидаемые слоты.
std::vector<u8> build_macho(std::vector<std::pair<u64,u64>>& expect) {
    // Раскладка файла:
    //   [0x000] mach_header_64 (32)
    //   [0x020] LC_SEGMENT_64 __TEXT   (72)   vmaddr 0,      file 0,     размер 0x4000
    //   [0x068] LC_SEGMENT_64 __DATA   (72)   vmaddr 0x4000, file 0x4000,размер 0x1000
    //   [0x0B0] LC_DYLD_INFO_ONLY (48)
    //   ...
    //   [0x4000] __DATA raw: слоты указателей
    //   rebase-байткод кладём в __TEXT-хвосте, скажем на 0x1000.
    const u32 CPU_ARM64 = 0x0100000C;
    const u32 LC_SEGMENT_64 = 0x19;
    const u32 LC_DYLD_INFO_ONLY = 0x80000022;

    std::vector<u8> b(0x5000, 0);

    // ── rebase-байткод (в __TEXT на 0x1000) ──────────────────────────────
    // Сегмент 1 (__DATA), смещение 0. Разложим 3 подряд (IMM_TIMES=3), затем
    // пропустим один слот и разложим ещё 2 (TIMES_SKIPPING_ULEB, skip=8).
    std::vector<u8> bc;
    bc.push_back(REBASE_OPCODE_SET_TYPE_IMM | 1);                 // type=POINTER
    bc.push_back(REBASE_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB | 1);  // seg=1 (__DATA)
    uleb(bc, 0);                                                  // offset=0
    bc.push_back(REBASE_OPCODE_DO_REBASE_IMM_TIMES | 3);         // 3 слота подряд
    // после 3 слотов addr=0x18; пропускаем 1 (skip=8) на каждом шаге:
    bc.push_back(REBASE_OPCODE_DO_REBASE_ULEB_TIMES_SKIPPING_ULEB);
    uleb(bc, 2);                                                  // count=2
    uleb(bc, 8);                                                  // skip=8 (итого шаг 16)
    bc.push_back(REBASE_OPCODE_DONE);

    const u32 rebase_off = 0x1000;
    for (std::size_t i = 0; i < bc.size(); ++i) b[rebase_off + i] = bc[i];
    const u32 rebase_size = static_cast<u32>(bc.size());

    // ── значения-указатели в __DATA (file 0x4000 == vmaddr 0x4000) ───────
    // Слоты: 0x4000,0x4008,0x4010 (подряд), затем 0x4018 пропущен,
    // 0x4020 и 0x4030 (шаг 16). Все указывают внутрь __DATA (валидные VA).
    const u64 slots[] = {0x4000, 0x4008, 0x4010, 0x4020, 0x4030};
    const u64 vals[]  = {0x4100, 0x4108, 0x4110, 0x4120, 0x4130};
    for (int i = 0; i < 5; ++i) {
        put64(b, slots[i], vals[i]);
        expect.emplace_back(slots[i], vals[i]);
    }

    // ── mach_header_64 ───────────────────────────────────────────────────
    put32(b, 0, 0xFEEDFACF);   // magic
    put32(b, 4, CPU_ARM64);    // cputype
    put32(b, 8, 0);            // cpusubtype
    put32(b, 12, 6);           // filetype = MH_DYLIB
    put32(b, 16, 3);           // ncmds
    put32(b, 20, 72 + 72 + 48);// sizeofcmds
    put32(b, 24, 0);           // flags
    put32(b, 28, 0);           // reserved

    // ── LC_SEGMENT_64 __TEXT ─────────────────────────────────────────────
    std::size_t o = 32;
    put32(b, o, LC_SEGMENT_64); put32(b, o + 4, 72);
    std::memcpy(&b[o + 8], "__TEXT", 6);
    put64(b, o + 24, 0x0);      // vmaddr
    put64(b, o + 32, 0x4000);   // vmsize
    put64(b, o + 40, 0x0);      // fileoff
    put64(b, o + 48, 0x4000);   // filesize
    put32(b, o + 56, 5); put32(b, o + 60, 5);  // maxprot/initprot
    put32(b, o + 64, 0); put32(b, o + 68, 0);  // nsects/flags
    o += 72;

    // ── LC_SEGMENT_64 __DATA ─────────────────────────────────────────────
    put32(b, o, LC_SEGMENT_64); put32(b, o + 4, 72);
    std::memcpy(&b[o + 8], "__DATA", 6);
    put64(b, o + 24, 0x4000);   // vmaddr
    put64(b, o + 32, 0x1000);   // vmsize
    put64(b, o + 40, 0x4000);   // fileoff
    put64(b, o + 48, 0x1000);   // filesize
    put32(b, o + 56, 3); put32(b, o + 60, 3);
    put32(b, o + 64, 0); put32(b, o + 68, 0);
    o += 72;

    // ── LC_DYLD_INFO_ONLY ────────────────────────────────────────────────
    put32(b, o, LC_DYLD_INFO_ONLY); put32(b, o + 4, 48);
    put32(b, o + 8, rebase_off);    // rebase_off
    put32(b, o + 12, rebase_size);  // rebase_size
    // остальные поля (bind/export) — нули, нам не нужны
    o += 48;

    return b;
}

// ── часть 1: диспетчер на настоящем ELF ──────────────────────────────────────
void test_dispatch_elf() {
    std::printf("== диспетчер: настоящий ELF (tests/nov_bin.so) ==\n");
    Mapped m;
    if (!map_file("tests/nov_bin.so", m)) {
        std::printf("  [SKIP] tests/nov_bin.so недоступен\n");
        return;
    }
    // Через диспетчер должен получиться Elf64.
    auto img = load(m.view());
    check(dynamic_cast<elf::Elf64*>(img.get()) != nullptr,
          "диспетчер выбрал Elf64 для ELF");
    check(dynamic_cast<macho::Macho*>(img.get()) == nullptr,
          "это не Macho");
    // Числа те же, что даёт прямой разбор.
    check(img->segments().size() == 4, "4 сегмента PT_LOAD");
    check(img->reloc_count() > 1'000'000, "> 1M релокаций (DT_RELA)");
    check(img->reloc_source() == "DT_RELA", "источник релокаций DT_RELA");
    // va2fo/ptr работают через интерфейс. Берём адрес в СЕРЕДИНЕ первого
    // сегмента: сам vaddr первого сегмента у этого ELF равен 0, а is_valid_va
    // намеренно отвергает 0 — поэтому проверяем ненулевой адрес внутри образа.
    const auto& s0 = img->segments().front();
    const u64 mid = s0.vaddr + s0.filesz / 2;
    check(img->va2fo(mid).has_value(), "va2fo середины первого сегмента разрешается");
    check(img->is_valid_va(mid), "ненулевой VA внутри образа валиден");
    check(!img->is_valid_va(0), "нулевой VA невалиден");
}

// ── часть 1b: диспетчер на настоящем Mach-O ──────────────────────────────────
void test_dispatch_macho_real() {
    std::printf("== диспетчер: настоящий Mach-O (tests/macho_bin.dylib) ==\n");
    Mapped m;
    if (!map_file("tests/macho_bin.dylib", m)) {
        std::printf("  [SKIP] tests/macho_bin.dylib недоступен\n");
        return;
    }
    auto img = load(m.view());
    auto* mo = dynamic_cast<macho::Macho*>(img.get());
    check(mo != nullptr, "диспетчер выбрал Macho для Mach-O");
    if (!mo) return;
    check(dynamic_cast<elf::Elf64*>(img.get()) == nullptr, "это не Elf64");

    // Эталонные числа, снятые независимым разбором этого файла:
    //   4 сегмента, mem_end=0xc98000, cputype arm64, 27521 rebase.
    check(img->segments().size() == 4, "4 сегмента (__TEXT/__DATA/__ASSETS/__LINKEDIT)");
    check(mo->cpu_type() == 0x0100000C, "cputype = arm64 (0x0100000C)");
    check(img->mem_end() == 0xc98000, "mem_end = 0xc98000");
    check(img->reloc_count() == 27521, "27521 записей rebase");
    check(img->reloc_source().find("LC_DYLD_INFO rebase") != std::string::npos,
          "источник релокаций содержит 'LC_DYLD_INFO rebase'");

    // Имена сегментов заполнены (после сортировки по vaddr __TEXT первый).
    check(img->segments().front().name == "__TEXT", "первый сегмент __TEXT");

    // Известные пары из карты rebase (снято независимым декодером):
    //   va=0xb50160 -> 0xbec050, va=0xb50168 -> 0x3aef40, va=0xb50170 -> 0x3b8138
    check(img->ptr(0xb50160) == 0xbec050, "rebase[0xb50160] == 0xbec050");
    check(img->ptr(0xb50168) == 0x3aef40, "rebase[0xb50168] == 0x3aef40");
    check(img->ptr(0xb50170) == 0x3b8138, "rebase[0xb50170] == 0x3b8138");

    // Значения rebase ведут внутрь образа — reloc_values() их и отдаёт.
    const auto vals = img->reloc_values();
    check(!vals.empty(), "reloc_values() непустой");
    bool all_in_image = true;
    for (std::size_t i = 0; i < vals.size() && i < 500; ++i) {
        if (!img->va2fo(vals[i])) { all_in_image = false; break; }
    }
    check(all_in_image, "первые 500 reloc_values ведут внутрь образа");

    // packing_check: у нормального dylib слоты указывают внутрь образа.
    auto pk = img->packing_check();
    check(!pk.packed, "packing_check: не упакован");
    std::printf("       packing: %s\n", pk.why.c_str());
}

// ── часть 2: синтетический Mach-O + rebase-байткод ───────────────────────────
void test_synthetic_macho() {
    std::printf("== синтетический Mach-O (заголовок + сегменты + rebase) ==\n");
    std::vector<std::pair<u64,u64>> expect;
    std::vector<u8> buf = build_macho(expect);
    ByteView v{buf.data(), buf.size()};

    std::unique_ptr<binary::BinaryImage> img;
    try {
        img = std::make_unique<macho::Macho>(v);
    } catch (const std::exception& e) {
        check(false, "конструктор Macho не должен бросать");
        std::printf("       исключение: %s\n", e.what());
        return;
    }
    check(img->segments().size() == 2, "2 сегмента (__TEXT, __DATA)");
    check(img->mem_end() == 0x5000, "mem_end = 0x5000 (__DATA vmaddr+vmsize)");
    check(dynamic_cast<macho::Macho*>(img.get())->cpu_type() == 0x0100000C,
          "cputype arm64");

    // Карта rebase должна содержать ровно 5 ожидаемых слотов с их значениями.
    check(img->reloc_count() == expect.size(), "число rebase == 5 (все опкоды)");
    bool all_ok = true;
    for (const auto& kv : expect) {
        if (img->ptr(kv.first) != kv.second) { all_ok = false; break; }
    }
    check(all_ok, "все rebase-слоты дают ожидаемые значения");

    // Пропущенный слот (0x4018) в карту НЕ попал — ptr() читает сырые байты (0).
    check(img->reloc_count() == 5 && img->ptr(0x4018) == 0,
          "пропущенный SKIPPING-слот 0x4018 не в карте (сырое чтение = 0)");

    // va2fo арифметика: __DATA vmaddr 0x4000 == fileoff 0x4000.
    auto fo = img->va2fo(0x4008);
    check(fo.has_value() && *fo == 0x4008, "va2fo(0x4008) == fileoff 0x4008");
    check(img->is_valid_va(0x4000) && !img->is_valid_va(0x9999),
          "is_valid_va различает внутри/снаружи образа");
}

// ── часть 3: негативные тесты ────────────────────────────────────────────────
void test_negative() {
    std::printf("== негативные тесты (битые Mach-O) ==\n");

    auto throws = [](ByteView v) -> bool {
        try { macho::Macho m(v); return false; }
        catch (const BinaryError&) { return true; }
        catch (...) { return false; }
    };

    // Пустой ввод.
    check(throws(ByteView{nullptr, 0}), "пустой ввод -> BinaryError");

    // Неверная магия (это ELF-магия).
    std::vector<u8> elfish(64, 0);
    elfish[0] = 0x7F; elfish[1] = 'E'; elfish[2] = 'L'; elfish[3] = 'F';
    check(throws(ByteView{elfish.data(), elfish.size()}), "ELF-магия -> BinaryError");

    // Обрезанный заголовок (магия есть, но < 32 байт).
    std::vector<u8> tiny = {0xCF, 0xFA, 0xED, 0xFE, 0x0C, 0x00, 0x00, 0x01};
    check(throws(ByteView{tiny.data(), tiny.size()}), "обрезанный заголовок -> BinaryError");

    // 32-битный Mach-O (magic 0xFEEDFACE) — осознанно не поддержан.
    std::vector<u8> m32(64, 0);
    m32[0] = 0xCE; m32[1] = 0xFA; m32[2] = 0xED; m32[3] = 0xFE;
    check(throws(ByteView{m32.data(), m32.size()}), "32-битный Mach-O -> BinaryError");
}

} // namespace

int main() {
    std::printf("=== test_macho ===\n");
    test_dispatch_elf();
    test_dispatch_macho_real();
    test_synthetic_macho();
    test_negative();
    std::printf("\n%s (%d провалов)\n",
                g_failures == 0 ? "ВСЕ ТЕСТЫ ПРОШЛИ" : "ЕСТЬ ПРОВАЛЫ", g_failures);
    return g_failures == 0 ? 0 : 1;
}
