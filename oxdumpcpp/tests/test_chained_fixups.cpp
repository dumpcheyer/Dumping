// tests/test_chained_fixups.cpp — юнит-тесты разбора LC_DYLD_CHAINED_FIXUPS
// (цепочки фиксапов, iOS 15+/arm64e) в macho::Macho.
//
// Настоящего arm64e-бинаря с цепочками в песочнице нет (все доступные Mach-O
// используют LC_DYLD_INFO rebase), поэтому тесты синтетические. Три части:
//
//   1. detail::unpack_chain_entry — чистая функция распаковки одного звена.
//      Проверяем ВСЕ четыре поддержанных формата указателей (ARM64E=1,
//      PTR_64=2, PTR_64_OFFSET=8, ARM64E_USERLAND24=12) на рукописных словах с
//      заранее вычисленными target/next/bind/ordinal. Раскладки битов сверены с
//      <mach-o/fixup-chains.h>: у arm64e поле next — 11 бит на [51,62), bind на
//      бите 62, auth на 63; у PTR_64 next — 12 бит на [51,63), bind на 63.
//
//   2. Полный синтетический Mach-O 64 arm64 с LC_DYLD_CHAINED_FIXUPS: заголовок
//      + три сегмента (__TEXT/__DATA/__LINKEDIT) + валидный
//      dyld_chained_fixups_header → starts_in_image → starts_in_segment → одна
//      страница с цепочкой из 5 rebase-звеньев (формат PTR_64_OFFSET). Гоняем
//      через macho::Macho и сверяем карту reloc_ (через ptr()): 5 целей,
//      посчитанных вручную. Плюс проверяем reloc_source() и что bind'ы в цепочке
//      считаются, но не попадают в reloc_.
//
//   3. Негативные пути: битая версия заголовка, неизвестный pointer_format,
//      цепочка, убегающая за конец страницы/файла. Разбор не должен падать —
//      он молча останавливает битую цепочку и оставляет reloc_ пустым (или
//      частичным), а конструктор не бросает.
#include "oxdump/macho/macho.h"
#include "oxdump/binary/image.h"
#include <cstdio>
#include <cstring>
#include <memory>
#include <vector>

using namespace oxdump;

namespace {

int g_failures = 0;

void check(bool cond, const char* what) {
    std::printf("  [%s] %s\n", cond ? "OK " : "FAIL", what);
    if (!cond) ++g_failures;
}

// ── помощники записи в буфер (little-endian) ─────────────────────────────────
void put16(std::vector<u8>& b, std::size_t off, u16 v) {
    b[off] = v & 0xFF; b[off + 1] = (v >> 8) & 0xFF;
}
void put32(std::vector<u8>& b, std::size_t off, u32 v) {
    for (int i = 0; i < 4; ++i) b[off + i] = (v >> (8 * i)) & 0xFF;
}
void put64(std::vector<u8>& b, std::size_t off, u64 v) {
    for (int i = 0; i < 8; ++i) b[off + i] = (v >> (8 * i)) & 0xFF;
}

// ── кодировщики сырых слов цепочки (зеркало раскладок из fixup-chains.h) ──────
// ARM64E rebase:      target:43, high8:8, next:11, bind:1(=0), auth:1(=0)
u64 enc_arm64e_rebase(u64 target43, u8 high8, u32 next) {
    return (target43 & ((u64{1} << 43) - 1)) |
           (static_cast<u64>(high8) << 43) |
           (static_cast<u64>(next & 0x7FF) << 51);
}
// ARM64E auth-rebase: target:32, diversity:16, addrDiv:1, key:2, next:11,
//                     bind:1(=0), auth:1(=1)
u64 enc_arm64e_auth_rebase(u32 target32, u8 key, u8 addr_div, u16 div, u32 next) {
    return (static_cast<u64>(target32)) |
           (static_cast<u64>(div) << 32) |
           (static_cast<u64>(addr_div & 1) << 48) |
           (static_cast<u64>(key & 3) << 49) |
           (static_cast<u64>(next & 0x7FF) << 51) |
           (u64{1} << 63);
}
// ARM64E bind:        ordinal:16, ..., next:11, bind:1(=1), auth:1(=0)
u64 enc_arm64e_bind(u16 ordinal, u32 next) {
    return (static_cast<u64>(ordinal)) |
           (static_cast<u64>(next & 0x7FF) << 51) |
           (u64{1} << 62);
}
// ARM64E_USERLAND24 bind: 24-битный ordinal.
u64 enc_user24_bind(u32 ordinal24, u32 next) {
    return (static_cast<u64>(ordinal24 & 0xFFFFFF)) |
           (static_cast<u64>(next & 0x7FF) << 51) |
           (u64{1} << 62);
}
// PTR_64 rebase:      target:36, high8:8, reserved:7, next:12, bind:1(=0)
u64 enc_ptr64_rebase(u64 target36, u8 high8, u32 next) {
    return (target36 & ((u64{1} << 36) - 1)) |
           (static_cast<u64>(high8) << 36) |
           (static_cast<u64>(next & 0xFFF) << 51);
}
// PTR_64 bind:        ordinal:24, addend:8, reserved:19, next:12, bind:1(=1)
u64 enc_ptr64_bind(u32 ordinal24, u32 next) {
    return (static_cast<u64>(ordinal24 & 0xFFFFFF)) |
           (static_cast<u64>(next & 0xFFF) << 51) |
           (u64{1} << 63);
}

// ── часть 1: detail::unpack_chain_entry по каждому формату ────────────────────
void test_unpack_arm64e() {
    std::printf("== unpack_chain_entry: ARM64E (формат 1) ==\n");
    const u64 IB = 0x100000000ull;  // произвольная база образа для проверки

    // plain rebase: target=0x4100, high8=0, next=2 (шаг 8 байт). target
    // абсолютный (не userland) → просто 0x4100.
    {
        auto e = macho::detail::unpack_chain_entry(enc_arm64e_rebase(0x4100, 0, 2), 1, IB);
        check(!e.is_bind, "rebase: is_bind=false");
        check(e.target == 0x4100, "rebase: target == 0x4100");
        check(e.next_delta == 8, "rebase: next_delta == 8 (next=2 ×4)");
    }
    // rebase с high8=0xAB: полный указатель = 0xAB<<56 | target.
    {
        auto e = macho::detail::unpack_chain_entry(enc_arm64e_rebase(0x12345, 0xAB, 1), 1, IB);
        check(e.target == ((u64{0xAB} << 56) | 0x12345), "rebase: high8 в старший байт");
        check(e.next_delta == 4, "rebase high8: next_delta == 4");
    }
    // auth-rebase: target:32 — это СМЕЩЕНИЕ от базы образа → IB + 0x2000.
    {
        auto e = macho::detail::unpack_chain_entry(
            enc_arm64e_auth_rebase(0x2000, /*key*/2, /*addrDiv*/1, /*div*/0x1234, /*next*/3), 1, IB);
        check(!e.is_bind, "auth-rebase: is_bind=false");
        check(e.target == IB + 0x2000, "auth-rebase: target == image_base + 0x2000");
        check(e.next_delta == 12, "auth-rebase: next_delta == 12 (next=3 ×4)");
    }
    // bind: ordinal в младших 16 битах, next=0 (конец цепочки).
    {
        auto e = macho::detail::unpack_chain_entry(enc_arm64e_bind(0x42, 0), 1, IB);
        check(e.is_bind, "bind: is_bind=true");
        check(e.import_ordinal == 0x42, "bind: ordinal == 0x42");
        check(e.next_delta == 0, "bind next=0: next_delta == 0 (bit62=bind не течёт в next)");
        check(e.target == 0, "bind: target == 0 (импорт не резолвим)");
    }
    // bind с next!=0: убеждаемся, что бит bind (62) не искажает поле next (51..62).
    {
        auto e = macho::detail::unpack_chain_entry(enc_arm64e_bind(0x7, 3), 1, IB);
        check(e.is_bind && e.import_ordinal == 0x7, "bind next!=0: ordinal == 0x7");
        check(e.next_delta == 12, "bind next!=0: next_delta == 12 (next=3, bind-бит изолирован)");
    }
}

void test_unpack_ptr64() {
    std::printf("== unpack_chain_entry: PTR_64 (2) и PTR_64_OFFSET (8) ==\n");
    const u64 IB = 0x100000000ull;

    // PTR_64 rebase: target=0x123456789 (36-бит), next=4 (шаг 16).
    {
        auto e = macho::detail::unpack_chain_entry(enc_ptr64_rebase(0x123456789ull, 0, 4), 2, IB);
        check(!e.is_bind, "PTR_64 rebase: is_bind=false");
        check(e.target == 0x123456789ull, "PTR_64 rebase: target == 0x123456789 (абсолют)");
        check(e.next_delta == 16, "PTR_64 rebase: next_delta == 16 (next=4 ×4)");
    }
    // PTR_64 rebase с high8=0x80 в старшем байте.
    {
        auto e = macho::detail::unpack_chain_entry(enc_ptr64_rebase(0x1000, 0x80, 1), 2, IB);
        check(e.target == ((u64{0x80} << 56) | 0x1000), "PTR_64 rebase: high8 в старший байт");
    }
    // PTR_64_OFFSET: target — СМЕЩЕНИЕ от базы образа → IB + 0x3000.
    {
        auto e = macho::detail::unpack_chain_entry(enc_ptr64_rebase(0x3000, 0, 1), 8, IB);
        check(e.target == IB + 0x3000, "PTR_64_OFFSET rebase: target == image_base + 0x3000");
        check(e.next_delta == 4, "PTR_64_OFFSET rebase: next_delta == 4");
    }
    // PTR_64 bind: ordinal 24-бит.
    {
        auto e = macho::detail::unpack_chain_entry(enc_ptr64_bind(0x99, 0), 2, IB);
        check(e.is_bind, "PTR_64 bind: is_bind=true");
        check(e.import_ordinal == 0x99, "PTR_64 bind: ordinal == 0x99");
        check(e.next_delta == 0, "PTR_64 bind: next_delta == 0");
    }
}

void test_unpack_user24() {
    std::printf("== unpack_chain_entry: ARM64E_USERLAND24 (12) ==\n");
    const u64 IB = 0x100000000ull;

    // rebase: как ARM64E, но userland → target прибавляет базу образа.
    {
        auto e = macho::detail::unpack_chain_entry(enc_arm64e_rebase(0x5000, 0, 1), 12, IB);
        check(!e.is_bind, "USERLAND24 rebase: is_bind=false");
        check(e.target == IB + 0x5000, "USERLAND24 rebase: target == image_base + 0x5000");
        check(e.next_delta == 4, "USERLAND24 rebase: next_delta == 4");
    }
    // bind: ordinal ШИРЕ — 24 бита (в arm64e классическом только 16).
    {
        auto e = macho::detail::unpack_chain_entry(enc_user24_bind(0xABCDEF, 0), 12, IB);
        check(e.is_bind, "USERLAND24 bind: is_bind=true");
        check(e.import_ordinal == 0xABCDEF, "USERLAND24 bind: 24-битный ordinal == 0xABCDEF");
    }
}

void test_unpack_bad_format() {
    std::printf("== unpack_chain_entry: неизвестный формат ==\n");
    // Неподдержанный pointer_format → пустая запись (next_delta=0 остановит цепь).
    auto e = macho::detail::unpack_chain_entry(0xFFFFFFFFFFFFFFFFull, /*fmt*/99, 0);
    check(e.target == 0 && e.next_delta == 0 && !e.is_bind && e.import_ordinal == 0,
          "неизвестный формат → пустая ChainEntry");
}

// ── построение синтетического Mach-O с LC_DYLD_CHAINED_FIXUPS ─────────────────
//
// Раскладка файла (image_base = __TEXT vmaddr = 0):
//   __TEXT     vmaddr 0,      fileoff 0,      filesz 0x4000, vmsize 0x4000
//   __DATA     vmaddr 0x4000, fileoff 0x4000, filesz 0x4000, vmsize 0x4000
//   __LINKEDIT vmaddr 0x8000, fileoff 0x8000, filesz 0x1000, vmsize 0x1000
// Цепочка из 5 rebase-звеньев (PTR_64_OFFSET) лежит в __DATA по смещениям
// 0,8,16,24,32 (шаг next=2 ⇒ 8 байт), последнее звено с next=0. Блок фиксапов —
// в __LINKEDIT. Параметры варьируются аргументами для негативных тестов.
struct FixupOpts {
    u32 version = 0;              // dyld_chained_fixups_header.fixups_version
    u16 pointer_format = 8;      // DYLD_CHAINED_PTR_64_OFFSET
    bool runaway = false;        // сделать шаг next огромным (убежать за страницу)
};

std::vector<u8> build_macho_chained(FixupOpts opt, std::vector<std::pair<u64,u64>>& expect) {
    const u32 CPU_ARM64 = 0x0100000C;
    const u32 LC_SEGMENT_64 = 0x19;
    const u32 LC_DYLD_CHAINED_FIXUPS = 0x80000034;

    const u64 PAGE = 0x4000;
    const u64 DATA_FO = 0x4000, DATA_VA = 0x4000;
    const u64 LINK_FO = 0x8000;

    std::vector<u8> b(0x9000, 0);

    // ── цепочка rebase-звеньев в __DATA ──────────────────────────────────
    // 5 целей (смещения от базы 0 ⇒ target VA == само смещение).
    const u64 targets[5] = {0x100, 0x208, 0x310, 0x418, 0x520};
    for (int i = 0; i < 5; ++i) {
        const bool last = (i == 4);
        u32 next = last ? 0 : 2;              // 2 ×4 = 8 байт до след. звена
        // Максимальный next (12 бит) на 3-м звене: 0xFFF ×4 = 0x3FFC байт. От
        // файла 0x4010 это уводит на 0x800C ≥ page_hi(0x8000) — цепочка честно
        // убегает за конец страницы, и разбор обязан её оборвать.
        if (opt.runaway && i == 2) next = 0xFFF;
        // PTR_64_OFFSET: target — смещение от базы, high8=0.
        const u64 word = enc_ptr64_rebase(targets[i], 0, next);
        put64(b, DATA_FO + static_cast<std::size_t>(i) * 8, word);
        // ожидаемые пары (VA слота → target VA). При runaway после 3-го звена
        // цепочка уводит в никуда — 4-е и 5-е не проставятся.
        if (!(opt.runaway && i >= 3)) {
            expect.emplace_back(DATA_VA + static_cast<u64>(i) * 8, targets[i]);
        }
    }

    // ── блок chained-fixups в __LINKEDIT (начало на LINK_FO) ─────────────
    // dyld_chained_fixups_header (32 байта):
    const std::size_t H = LINK_FO;
    const u32 starts_offset = 0x20;              // starts_in_image сразу за header
    put32(b, H + 0,  opt.version);               // fixups_version
    put32(b, H + 4,  starts_offset);             // starts_offset
    put32(b, H + 8,  0);                          // imports_offset
    put32(b, H + 12, 0);                          // symbols_offset
    put32(b, H + 16, 0);                          // imports_count
    put32(b, H + 20, 1);                          // imports_format (DYLD_CHAINED_IMPORT)
    put32(b, H + 24, 0);                          // symbols_format

    // dyld_chained_starts_in_image: seg_count=3, seg_info_offset[3].
    const std::size_t SII = H + starts_offset;
    const u32 seg_count = 3;
    put32(b, SII + 0, seg_count);
    const u32 sii_hdr = 4 + seg_count * 4;       // = 16
    const u32 seg_struct_off = starts_offset + sii_hdr;  // от начала header
    // seg0(__TEXT)=0, seg1(__DATA)=<offset относительно starts_in_image>, seg2=0.
    put32(b, SII + 4 + 0 * 4, 0);
    put32(b, SII + 4 + 1 * 4, sii_hdr);          // = seg_struct_off - starts_offset
    put32(b, SII + 4 + 2 * 4, 0);

    // dyld_chained_starts_in_segment для __DATA.
    const std::size_t SIS = H + seg_struct_off;
    const u16 page_count = 1;
    const u32 seg_fixed = 4 + 2 + 2 + 8 + 4 + 2; // = 22
    put32(b, SIS + 0,  seg_fixed + page_count * 2);  // size
    put16(b, SIS + 4,  static_cast<u16>(PAGE));      // page_size
    put16(b, SIS + 6,  opt.pointer_format);          // pointer_format
    put64(b, SIS + 8,  DATA_FO);                     // segment_offset (файловое)
    put32(b, SIS + 16, 0);                           // max_valid_pointer
    put16(b, SIS + 20, page_count);                  // page_count
    put16(b, SIS + 22, 0);                           // page_start[0] = 0

    // ── mach_header_64 ───────────────────────────────────────────────────
    put32(b, 0, 0xFEEDFACF);   // magic
    put32(b, 4, CPU_ARM64);    // cputype
    put32(b, 8, 0);            // cpusubtype
    put32(b, 12, 6);           // filetype = MH_DYLIB
    put32(b, 16, 4);           // ncmds (3× SEGMENT + 1× CHAINED_FIXUPS)
    put32(b, 20, 72 * 3 + 16); // sizeofcmds
    put32(b, 24, 0);           // flags
    put32(b, 28, 0);           // reserved

    // ── 3× LC_SEGMENT_64 ─────────────────────────────────────────────────
    auto seg = [&](std::size_t o, const char* name, u64 vmaddr, u64 vmsize,
                   u64 fileoff, u64 filesize) {
        put32(b, o, LC_SEGMENT_64); put32(b, o + 4, 72);
        std::memcpy(&b[o + 8], name, std::strlen(name));
        put64(b, o + 24, vmaddr);
        put64(b, o + 32, vmsize);
        put64(b, o + 40, fileoff);
        put64(b, o + 48, filesize);
        put32(b, o + 56, 5); put32(b, o + 60, 5);
        put32(b, o + 64, 0); put32(b, o + 68, 0);
    };
    std::size_t o = 32;
    seg(o, "__TEXT",     0x0,    0x4000, 0x0,    0x4000); o += 72;
    seg(o, "__DATA",     0x4000, 0x4000, 0x4000, 0x4000); o += 72;
    seg(o, "__LINKEDIT", 0x8000, 0x1000, 0x8000, 0x1000); o += 72;

    // ── LC_DYLD_CHAINED_FIXUPS (linkedit_data_command) ───────────────────
    // cmd, cmdsize, dataoff, datasize.
    put32(b, o, LC_DYLD_CHAINED_FIXUPS); put32(b, o + 4, 16);
    put32(b, o + 8, static_cast<u32>(LINK_FO));   // dataoff → блок фиксапов
    put32(b, o + 12, 0x100);                       // datasize (с запасом)
    o += 16;

    return b;
}

// ── часть 2: полный синтетический Mach-O + цепочка ───────────────────────────
void test_synthetic_chained() {
    std::printf("== синтетический Mach-O + LC_DYLD_CHAINED_FIXUPS (PTR_64_OFFSET) ==\n");
    std::vector<std::pair<u64,u64>> expect;
    std::vector<u8> buf = build_macho_chained(FixupOpts{}, expect);
    ByteView v{buf.data(), buf.size()};

    std::unique_ptr<binary::BinaryImage> img;
    try {
        img = std::make_unique<macho::Macho>(v);
    } catch (const std::exception& e) {
        check(false, "конструктор Macho не должен бросать на валидных цепочках");
        std::printf("       исключение: %s\n", e.what());
        return;
    }

    check(img->segments().size() == 3, "3 сегмента (__TEXT/__DATA/__LINKEDIT)");
    check(img->reloc_source().find("LC_DYLD_CHAINED_FIXUPS") != std::string::npos,
          "reloc_source упоминает LC_DYLD_CHAINED_FIXUPS");
    check(img->reloc_count() == expect.size(), "reloc_count == 5 (все звенья цепочки)");

    bool all_ok = true;
    for (const auto& kv : expect) {
        if (img->ptr(kv.first) != kv.second) {
            all_ok = false;
            std::printf("       mismatch VA=0x%llX got=0x%llX want=0x%llX\n",
                        (unsigned long long)kv.first,
                        (unsigned long long)img->ptr(kv.first),
                        (unsigned long long)kv.second);
        }
    }
    check(all_ok, "все 5 rebase-целей вычислены верно");

    // Точечная проверка нескольких значений (≥5 указателей, как требует ТЗ).
    check(img->ptr(0x4000) == 0x100, "chain[0x4000] == 0x100");
    check(img->ptr(0x4008) == 0x208, "chain[0x4008] == 0x208");
    check(img->ptr(0x4010) == 0x310, "chain[0x4010] == 0x310");
    check(img->ptr(0x4018) == 0x418, "chain[0x4018] == 0x418");
    check(img->ptr(0x4020) == 0x520, "chain[0x4020] == 0x520");
}

// ── часть 2b: цепочка с bind-звеньями (импорты пропускаются) ──────────────────
void test_chained_with_binds() {
    std::printf("== цепочка с bind-звеньями (импорты считаются, но не в reloc_) ==\n");
    // Строим вручную: __DATA[0]=rebase, __DATA[8]=bind, __DATA[16]=rebase(end).
    std::vector<u8> b(0x9000, 0);
    const u32 CPU_ARM64 = 0x0100000C;
    const u32 LC_SEGMENT_64 = 0x19;
    const u32 LC_DYLD_CHAINED_FIXUPS = 0x80000034;
    const u64 PAGE = 0x4000, DATA_FO = 0x4000, LINK_FO = 0x8000;

    // Звенья формата ARM64E (1): rebase, bind, rebase.
    put64(b, DATA_FO + 0,  enc_arm64e_rebase(0x100, 0, 2));   // rebase → 0x100, шаг 8
    put64(b, DATA_FO + 8,  enc_arm64e_bind(0x55, 2));         // bind ordinal 0x55, шаг 8
    put64(b, DATA_FO + 16, enc_arm64e_rebase(0x300, 0, 0));   // rebase → 0x300, конец

    // header + starts (как в build_macho_chained, формат ARM64E).
    const std::size_t H = LINK_FO;
    put32(b, H + 4, 0x20);                       // starts_offset
    put32(b, H + 20, 1);                          // imports_format
    const std::size_t SII = H + 0x20;
    put32(b, SII + 0, 3);                         // seg_count
    put32(b, SII + 4 + 1 * 4, 16);               // __DATA seg_info_offset
    const std::size_t SIS = H + 0x20 + 16;
    put32(b, SIS + 0, 22 + 2);                    // size
    put16(b, SIS + 4, static_cast<u16>(PAGE));    // page_size
    put16(b, SIS + 6, 1);                         // pointer_format = ARM64E
    put64(b, SIS + 8, DATA_FO);                   // segment_offset
    put16(b, SIS + 20, 1);                        // page_count
    put16(b, SIS + 22, 0);                        // page_start[0]

    // header + сегменты + команда.
    put32(b, 0, 0xFEEDFACF); put32(b, 4, CPU_ARM64); put32(b, 12, 6);
    put32(b, 16, 4); put32(b, 20, 72 * 3 + 16);
    auto seg = [&](std::size_t o, const char* name, u64 va, u64 vs, u64 fo, u64 fs) {
        put32(b, o, LC_SEGMENT_64); put32(b, o + 4, 72);
        std::memcpy(&b[o + 8], name, std::strlen(name));
        put64(b, o + 24, va); put64(b, o + 32, vs);
        put64(b, o + 40, fo); put64(b, o + 48, fs);
        put32(b, o + 56, 5); put32(b, o + 60, 5);
    };
    std::size_t o = 32;
    seg(o, "__TEXT", 0, 0x4000, 0, 0x4000); o += 72;
    seg(o, "__DATA", 0x4000, 0x4000, 0x4000, 0x4000); o += 72;
    seg(o, "__LINKEDIT", 0x8000, 0x1000, 0x8000, 0x1000); o += 72;
    put32(b, o, LC_DYLD_CHAINED_FIXUPS); put32(b, o + 4, 16);
    put32(b, o + 8, static_cast<u32>(LINK_FO)); put32(b, o + 12, 0x100);

    ByteView v{b.data(), b.size()};
    try {
        macho::Macho m(v);
        // Два rebase попали в карту, bind — нет.
        check(m.reloc_count() == 2, "reloc_count == 2 (два rebase, bind пропущен)");
        check(m.ptr(0x4000) == 0x100, "rebase[0x4000] == 0x100");
        check(m.ptr(0x4010) == 0x300, "rebase[0x4010] == 0x300 (после bind-звена)");
        // bind-слот НЕ переписан в карту reloc_: ptr() отдаёт сырое слово из
        // файла (упакованное bind-звено), а не разрешённый target. Именно это
        // отличает пропуск импорта от подстановки rebase.
        check(m.ptr(0x4008) == enc_arm64e_bind(0x55, 2),
              "bind-слот 0x4008 не в reloc_ (ptr читает сырое bind-слово)");
        check(m.reloc_source().find("bind") != std::string::npos,
              "reloc_source отмечает пропущенные bind'ы");
    } catch (const std::exception& e) {
        check(false, "конструктор не должен бросать на цепочке с bind");
        std::printf("       исключение: %s\n", e.what());
    }
}

// ── часть 3: негативные пути ──────────────────────────────────────────────────
void test_bad_version() {
    std::printf("== негатив: битая версия заголовка ==\n");
    std::vector<std::pair<u64,u64>> expect;
    FixupOpts opt; opt.version = 5;   // не 0 → не поддержано
    std::vector<u8> buf = build_macho_chained(opt, expect);
    ByteView v{buf.data(), buf.size()};
    try {
        macho::Macho m(v);
        // Конструктор не бросает; карта пуста (версия не разобрана), нет
        // LC_DYLD_INFO для отката → reloc пуст.
        check(m.reloc_count() == 0, "битая версия → reloc пуст (разбор остановлен)");
        check(m.reloc_source().find("версия") != std::string::npos,
              "reloc_source отмечает неподдержанную версию");
    } catch (const std::exception& e) {
        check(false, "битая версия не должна ронять конструктор");
        std::printf("       исключение: %s\n", e.what());
    }
}

void test_bad_pointer_format() {
    std::printf("== негатив: неизвестный pointer_format ==\n");
    std::vector<std::pair<u64,u64>> expect;
    FixupOpts opt; opt.pointer_format = 0x1234;   // мусорный формат
    std::vector<u8> buf = build_macho_chained(opt, expect);
    ByteView v{buf.data(), buf.size()};
    try {
        macho::Macho m(v);
        // unpack вернёт пустую запись (next=0) на первом же звене → 0 целей.
        check(m.reloc_count() == 0, "неизвестный формат → 0 rebase-целей");
    } catch (const std::exception& e) {
        check(false, "неизвестный формат не должен ронять конструктор");
        std::printf("       исключение: %s\n", e.what());
    }
}

void test_chain_runaway() {
    std::printf("== негатив: цепочка убегает за конец страницы ==\n");
    std::vector<std::pair<u64,u64>> expect;
    FixupOpts opt; opt.runaway = true;   // на 3-м звене гигантский шаг next
    std::vector<u8> buf = build_macho_chained(opt, expect);
    ByteView v{buf.data(), buf.size()};
    try {
        macho::Macho m(v);
        // Первые 3 звена (0x4000,0x4008,0x4010) успели проставиться, затем шаг
        // 0x400×4 = 0x1000 уводит за пределы страницы 0x4000 → разбор
        // останавливается. Ожидаем ровно 3 записи.
        check(m.reloc_count() == expect.size(),
              "runaway: проставлены только 3 звена до ухода за страницу");
        check(m.reloc_count() == 3, "runaway: ровно 3 записи");
        check(m.ptr(0x4000) == 0x100 && m.ptr(0x4008) == 0x208 && m.ptr(0x4010) == 0x310,
              "runaway: первые 3 цели корректны");
        // 4-е звено НЕ в карте: цепочка оборвалась на уходе за страницу, поэтому
        // ptr(0x4018) отдаёт сырое слово файла (упакованный rebase 0x418, next=2),
        // а НЕ разрешённый target 0x418.
        check(m.ptr(0x4018) == enc_ptr64_rebase(0x418, 0, 2),
              "runaway: 4-е звено (0x4018) не проставлено (ptr читает сырое слово)");
    } catch (const std::exception& e) {
        check(false, "runaway-цепочка не должна ронять конструктор");
        std::printf("       исключение: %s\n", e.what());
    }
}

} // namespace

int main() {
    std::printf("=== test_chained_fixups ===\n");
    // Часть 1: чистая функция распаковки по каждому формату.
    test_unpack_arm64e();
    test_unpack_ptr64();
    test_unpack_user24();
    test_unpack_bad_format();
    // Часть 2: интеграция через macho::Macho.
    test_synthetic_chained();
    test_chained_with_binds();
    // Часть 3: негативные пути.
    test_bad_version();
    test_bad_pointer_format();
    test_chain_runaway();

    std::printf("\n%s (%d провалов)\n",
                g_failures == 0 ? "ВСЕ ТЕСТЫ ПРОШЛИ" : "ЕСТЬ ПРОВАЛЫ", g_failures);
    return g_failures == 0 ? 0 : 1;
}
