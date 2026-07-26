// tests/test_arm64.cpp — модульный тест декодера AArch64 (oxdump::arm64).
//
// Эталон получен независимо (Capstone 5.0.7) на реальных инструкциях из
// tests/nov_bin.so и на синтезированных кодировках редких форм (LDR/LDRSW/PRFM
// literal, TBZ с битом >31, B.cond). Проверяются:
//   • классификация опкода и все поля Insn (rd/rn/rm/imm/cond/bit/флаги);
//   • PC-относительная арифметика (ADRP страница, ADR/ветвления → целевой VA);
//   • разбор пар ADRP+ADD и ADRP+LDR через extract_xrefs;
//   • определение границы функции (RET, косвенный BR) в decode_function;
//   • семантика is_terminator()/has_pc_ref().
//
// Тест самодостаточный: свой main(), без внешних фреймворков. Часть проверок
// читает реальный бинарь по mmap; если файла нет, эти проверки пропускаются
// (остальные, на «зашитых» словах, идут всегда).
#include "oxdump/arm64/disasm.h"
#include <cstdio>
#include <cstring>
#include <optional>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

using namespace oxdump;
using namespace oxdump::arm64;

namespace {

int g_failures = 0;

void check(bool cond, const char* what) {
    std::printf("  [%s] %s\n", cond ? "OK " : "FAIL", what);
    if (!cond) ++g_failures;
}

const char* opname(Op o) {
    switch (o) {
        case Op::ADRP: return "ADRP"; case Op::ADR: return "ADR";
        case Op::ADD_imm: return "ADD_imm"; case Op::MOV_reg: return "MOV_reg";
        case Op::LDR_imm: return "LDR_imm"; case Op::LDR_lit: return "LDR_lit";
        case Op::LDRSW_lit: return "LDRSW_lit"; case Op::PRFM_lit: return "PRFM_lit";
        case Op::B: return "B"; case Op::BL: return "BL"; case Op::B_cond: return "B_cond";
        case Op::CBZ: return "CBZ"; case Op::CBNZ: return "CBNZ";
        case Op::TBZ: return "TBZ"; case Op::TBNZ: return "TBNZ";
        case Op::BR: return "BR"; case Op::BLR: return "BLR"; case Op::RET: return "RET";
        case Op::NOP: return "NOP"; default: return "Unknown";
    }
}

// Полное ожидание по одной инструкции. Значения сверены с Capstone.
struct Expect {
    u64 pc;
    u32 raw;
    Op  op;
    u8  rd, rn, rm;
    s64 imm;
    u8  cond, bit;
    bool sf, wb, post;
    const char* note;
};

void check_one(const Expect& e) {
    const Insn in = decode(e.raw, e.pc);
    bool ok = in.op == e.op && in.rd == e.rd && in.rn == e.rn && in.rm == e.rm &&
              in.imm == e.imm && in.cond == e.cond && in.bit == e.bit &&
              in.sf == e.sf && in.writeback == e.wb && in.post_index == e.post;
    std::printf("  [%s] %-42s raw=%08X op=%s", ok ? "OK " : "FAIL",
                e.note, e.raw, opname(in.op));
    if (!ok) {
        std::printf("  (want op=%s rd=%u rn=%u rm=%u imm=%lld cond=%u bit=%u sf=%d wb=%d post=%d;"
                    " got rd=%u rn=%u rm=%u imm=%lld cond=%u bit=%u sf=%d wb=%d post=%d)",
                    opname(e.op), e.rd, e.rn, e.rm, (long long)e.imm, e.cond, e.bit,
                    e.sf, e.wb, e.post,
                    in.rd, in.rn, in.rm, (long long)in.imm, in.cond, in.bit,
                    in.sf, in.writeback, in.post_index);
        ++g_failures;
    }
    std::printf("\n");
}

// ── (1) Реальные инструкции из nov_bin.so (адреса/кодировки — из .text). ────
// Каждая строка сверена с Capstone: op и целевой VA/непосредственное значение.
void test_real_instructions() {
    std::printf("\n[real .text instructions vs. Capstone]\n");
    const Expect v[] = {
        // адресация и арифметика
        {0x4694424ULL, 0xf0035c20U, Op::ADRP,    0,  0, 0, 0xb21b000LL, 0,  0, 0,0,0, "adrp x0,#0xb21b000"},
        {0x4694428ULL, 0x913c4000U, Op::ADD_imm, 0,  0, 0, 0xf10LL,     0,  0, 0,0,0, "add x0,x0,#0xf10"},
        {0x4694448ULL, 0xaa0003f0U, Op::MOV_reg, 16, 0, 0, 0LL,         0,  0, 1,0,0, "mov x16,x0"},
        {0x4694460ULL, 0x10ffff00U, Op::ADR,     0,  0, 0, 0x4694440LL, 0,  0, 0,0,0, "adr x0,#0x4694440"},
        // ветвления
        {0x469442cULL, 0x15ae053dU, Op::B,       0,  0, 0, 0xb215920LL, 0,  0, 0,0,0, "b #0xb215920"},
        {0x4694484ULL, 0x95ae0533U, Op::BL,      0,  0, 0, 0xb215950LL, 0,  0, 0,0,0, "bl #0xb215950"},
        {0x469452cULL, 0x54000100U, Op::B_cond,  0,  0, 0, 0x469454cLL, 0,  0, 0,0,0, "b.eq #0x469454c"},
        {0x4694444ULL, 0xb4000060U, Op::CBZ,     0,  0, 0, 0x4694450LL, 0,  0, 1,0,0, "cbz x0,#0x4694450"},
        {0x46944bcULL, 0x35000069U, Op::CBNZ,    9,  0, 0, 0x46944c8LL, 0,  0, 0,0,0, "cbnz w9,#0x46944c8"},
        {0x469521cULL, 0x37000048U, Op::TBNZ,    8,  0, 0, 0x4695224LL, 0,  0, 0,0,0, "tbnz w8,#0,#0x4695224"},
        {0x4696dc0ULL, 0x36f803a8U, Op::TBZ,     8,  0, 0, 0x4696e34LL, 0, 31, 0,0,0, "tbz w8,#0x1f,#0x4696e34"},
        {0x469444cULL, 0xd61f0200U, Op::BR,      0, 16, 0, 0LL,         0,  0, 0,0,0, "br x16"},
        {0x4694560ULL, 0xd63f0100U, Op::BLR,     0,  8, 0, 0LL,         0,  0, 0,0,0, "blr x8"},
        {0x4694434ULL, 0xd65f03c0U, Op::RET,     0, 30, 0, 0LL,         0,  0, 0,0,0, "ret"},
        // загрузки
        {0x4694494ULL, 0xf9400408U, Op::LDR_imm, 8,  0, 0, 8LL,         0,  0, 1,0,0, "ldr x8,[x0,#8]"},
        {0x46944e0ULL, 0xf84207feU, Op::LDR_imm, 30,31, 0, 32LL,        0,  0, 1,1,1, "ldr x30,[sp],#0x20 (post)"},
        // наполнитель
        {0x4694420ULL, 0xd503245fU, Op::NOP,     0,  0, 0, 0LL,         0,  0, 0,0,0, "bti c (hint)"},
        {0x469445cULL, 0xd503201fU, Op::NOP,     0,  0, 0, 0LL,         0,  0, 0,0,0, "nop"},
        // НЕ должно опознаваться как LDR: это STR (другой opc).
        {0x4694480ULL, 0xf81f0ffeU, Op::Unknown, 0,  0, 0, 0LL,         0,  0, 0,0,0, "str x30,[sp,#-0x10]! (not a load)"},
    };
    for (const Expect& e : v) check_one(e);
}

// ── (2) Синтезированные редкие формы (в этом бинаре не встречаются). ────────
// Кодировки собраны по ARM ARM и сверены с Capstone отдельно.
void test_synthetic_forms() {
    std::printf("\n[synthetic rare forms vs. Capstone]\n");
    const Expect v[] = {
        // LDR (literal) x3: target = pc + 4*4 = 0x1010
        {0x1000ULL, 0x58000083U, Op::LDR_lit,   3, 0, 0, 0x1010LL, 0,  0, 1,0,0, "ldr x3,#0x1010 (literal)"},
        // LDRSW (literal) x9: target = pc + 3*4 = 0x100c
        {0x1000ULL, 0x98000069U, Op::LDRSW_lit, 9, 0, 0, 0x100cLL, 0,  0, 1,0,0, "ldrsw x9,#0x100c (literal)"},
        // PRFM (literal): target = pc + 8*4 = 0x1020
        {0x1000ULL, 0xd8000100U, Op::PRFM_lit,  0, 0, 0, 0x1020LL, 0,  0, 0,0,0, "prfm #0x1020 (literal)"},
        // TBZ high bit (bit 40): b5=1,b40=8 → bit=40, target 0x100c
        {0x1000ULL, 0xb6400068U, Op::TBZ,       8, 0, 0, 0x100cLL, 0, 40, 0,0,0, "tbz x8,#0x28,#0x100c (bit>31)"},
        // B.ne: cond=1 (NE), target 0x1020
        {0x1000ULL, 0x54000101U, Op::B_cond,    0, 0, 0, 0x1020LL, 1,  0, 0,0,0, "b.ne #0x1020"},
    };
    for (const Expect& e : v) check_one(e);
}

// ── (3) PC-относительная арифметика: знак и границы. ────────────────────────
void test_pcrel_math() {
    std::printf("\n[PC-relative math edge cases]\n");
    // ADRP с отрицательным смещением (adr x0,#0x4694440 из pc 0x4694460):
    {
        const Insn in = decode(0x10ffff00U, 0x4694460ULL);
        check(in.op == Op::ADR && (u64)in.imm == 0x4694440ULL,
              "ADR negative offset resolves backward");
    }
    // ADRP всегда обнуляет младшие 12 бит PC перед добавлением страницы.
    {
        // adrp x0,#0xb21b000 из pc 0x4694424 (не выровнен) — младшие биты PC не влияют.
        const Insn a = decode(0xf0035c20U, 0x4694424ULL);
        const Insn b = decode(0xf0035c20U, 0x4694420ULL);   // тот же raw, PC на границе страницы
        check(a.op == Op::ADRP && a.imm == b.imm && (u64)a.imm == 0xb21b000ULL,
              "ADRP masks low 12 bits of PC");
    }
    // B с большим отрицательным смещением: 0x17ffffd9 (b #0x5a11958 из 0x5a119f4).
    {
        const Insn in = decode(0x17ffffd9U, 0x5a119f4ULL);
        check(in.op == Op::B && (u64)in.imm == 0x5a11958ULL,
              "B large negative displacement");
    }
    // TBZ бит 0 против бита 31: разные значения bit.
    {
        const Insn lo = decode(0x37000048U, 0x469521cULL);   // tbnz w8,#0
        const Insn hi = decode(0x36f803a8U, 0x4696dc0ULL);   // tbz  w8,#0x1f
        check(lo.bit == 0 && hi.bit == 31, "TBZ/TBNZ bit index low vs high");
    }
}

// ── (4) is_terminator() / has_pc_ref() / is_branch() семантика. ─────────────
void test_semantics() {
    std::printf("\n[Insn semantic predicates]\n");
    check(decode(0xd65f03c0U, 0).is_terminator(), "RET is terminator");
    check(decode(0xd61f0200U, 0).is_terminator(), "BR is terminator");
    check(decode(0x15ae053dU, 0x469442cULL).is_terminator(), "B is terminator");
    check(!decode(0x95ae0533U, 0x4694484ULL).is_terminator(), "BL is NOT terminator");
    check(!decode(0x54000100U, 0x469452cULL).is_terminator(), "B.cond is NOT terminator");
    check(!decode(0xd63f0100U, 0).is_terminator(), "BLR is NOT terminator");

    check(decode(0xf0035c20U, 0x4694424ULL).has_pc_ref(), "ADRP has pc ref");
    check(decode(0x10ffff00U, 0x4694460ULL).has_pc_ref(), "ADR has pc ref");
    check(decode(0x15ae053dU, 0x469442cULL).has_pc_ref(), "B has pc ref (target)");
    check(!decode(0x913c4000U, 0x4694428ULL).has_pc_ref(), "ADD_imm has NO pc ref");
    check(!decode(0xf9400408U, 0x4694494ULL).has_pc_ref(), "LDR_imm has NO pc ref");
    check(!decode(0xaa0003f0U, 0).has_pc_ref(), "MOV_reg has NO pc ref");

    check(decode(0xd63f0100U, 0).is_branch(), "BLR is branch");
    check(decode(0x35000069U, 0x46944bcULL).is_branch(), "CBNZ is branch");
    check(!decode(0xd65f03c0U, 0).is_branch(), "RET is not a branch");
}

// ── (5) extract_xrefs: пары ADRP+ADD и ADRP+LDR + MOV-перенос. ──────────────
void test_extract_xrefs() {
    std::printf("\n[extract_xrefs: address-pair reconstruction]\n");
    // Соберём короткий кодовый блок из РЕАЛЬНЫХ слов thunk-а @0x5a11974:
    //   adrp x8, #0x1e61000     (90fe2288)  page in x8
    //   add  x8, x8, #0x684     (911a1108)  → xref page(x8)+0x684
    //   adrp x9, #0x1e1b000     (d0fe2049)  page in x9
    //   add  x9, x9, #0x40      (91010129)  → xref page(x9)+0x40
    // Ожидаемые цели вычисляем ЧЕРЕЗ сам декодер (страница ADRP зависит от base),
    // чтобы тест не зависел от выбора base.
    const u64 base = 0x5a11974ULL;
    u32 code[] = {
        0x90fe2288U,  // adrp x8,#0x1e61000   @base+0
        0x911a1108U,  // add  x8,x8,#0x684    @base+4  → page8+0x684
        0xd0fe2049U,  // adrp x9,#0x1e1b000   @base+8
        0x91010129U,  // add  x9,x9,#0x40     @base+12 → page9+0x40
    };
    const Insn adrp8 = decode(code[0], base + 0);
    const Insn adrp9 = decode(code[2], base + 8);
    check(adrp8.op == Op::ADRP && (u64)adrp8.imm == 0x1e61000ULL,
          "ADRP x8 page precondition = 0x1e61000");
    check(adrp9.op == Op::ADRP && (u64)adrp9.imm == 0x1e1b000ULL,
          "ADRP x9 page precondition = 0x1e1b000");
    const u64 want8 = (u64)adrp8.imm + 0x684ULL;
    const u64 want9 = (u64)adrp9.imm + 0x40ULL;

    auto xr = extract_xrefs(reinterpret_cast<const u8*>(code), sizeof(code), base);
    bool has8 = false, has9 = false;
    for (u64 v : xr) {
        if (v == want8) has8 = true;
        if (v == want9) has9 = true;
    }
    check(has8, "ADRP+ADD pair (x8) → 0x1e61684");
    check(has9, "ADRP+ADD pair (x9) → 0x1e1b040");
    check(xr.size() == 2, "extract_xrefs returns exactly the 2 distinct targets");

    // Отдельно: MOV переносит страницу. adrp x2; mov x3,x2; add x3,x3,#0x10.
    u32 code2[] = {
        0xf0035c22U,  // adrp x2,#0xb21b000
        0xaa0203e3U,  // mov  x3,x2
        0x91004063U,  // add  x3,x3,#0x10   → 0xb21b010
    };
    auto xr2 = extract_xrefs(reinterpret_cast<const u8*>(code2), sizeof(code2), 0x4694420ULL);
    bool via_mov = false;
    for (u64 v : xr2) if (v == 0xb21b010ULL) via_mov = true;
    check(via_mov, "MOV propagates ADRP page (ADRP;MOV;ADD → 0xb21b010)");

    // ADR в одиночку тоже даёт xref.
    u32 code3[] = { 0x10ffff00U };  // adr x0,#0x4694440
    auto xr3 = extract_xrefs(reinterpret_cast<const u8*>(code3), sizeof(code3), 0x4694460ULL);
    check(xr3.size() == 1 && xr3[0] == 0x4694440ULL, "standalone ADR → xref target");
}

// ── (6) decode_function: границы функции на реальном коде. ──────────────────
// Move-only RAII-обёртка над mmap. Копирование запрещено, move обнуляет
// источник — иначе возврат по значению разрушил бы временный объект и
// освободил маппинг (double-munmap / use-after-unmap).
struct Mapped {
    const u8* data = nullptr;
    std::size_t size = 0;
    int fd = -1;
    void* raw = nullptr;

    Mapped() = default;
    Mapped(const Mapped&) = delete;
    Mapped& operator=(const Mapped&) = delete;
    Mapped(Mapped&& o) noexcept
        : data(o.data), size(o.size), fd(o.fd), raw(o.raw) {
        o.data = nullptr; o.size = 0; o.fd = -1; o.raw = nullptr;
    }
    Mapped& operator=(Mapped&&) = delete;
    ~Mapped() {
        if (raw && raw != MAP_FAILED) munmap(raw, size);
        if (fd >= 0) close(fd);
    }
};

std::optional<Mapped> map_file(const char* path) {
    Mapped m;
    m.fd = open(path, O_RDONLY);
    if (m.fd < 0) return std::nullopt;
    struct stat st{};
    if (fstat(m.fd, &st) != 0 || st.st_size <= 0) return std::nullopt;
    m.size = static_cast<std::size_t>(st.st_size);
    m.raw = mmap(nullptr, m.size, PROT_READ, MAP_PRIVATE, m.fd, 0);
    if (m.raw == MAP_FAILED) { m.raw = nullptr; return std::nullopt; }
    m.data = static_cast<const u8*>(m.raw);
    return m;
}

// PT_LOAD-сегмент для va→fo (значения из readelf по nov_bin.so).
long va2fo(u64 va) {
    struct Seg { u64 va, off, fs; };
    static const Seg segs[] = {
        {0x0ULL,       0x0ULL,       0x469041cULL},
        {0x4694420ULL, 0x4690420ULL, 0x6b83af0ULL},
    };
    for (const Seg& s : segs)
        if (va >= s.va && va < s.va + s.fs) return static_cast<long>(s.off + (va - s.va));
    return -1;
}

void test_function_boundary() {
    std::printf("\n[decode_function boundary detection]\n");
    auto m = map_file("tests/nov_bin.so");
    if (!m) {
        std::printf("  [SKIP] tests/nov_bin.so not available — boundary tests skipped\n");
        return;
    }
    // Короткая функция @0x4694440: bti; cbz; mov x16,x0; br x16 (заканчивается BR).
    {
        const u64 rva = 0x4694440ULL;
        const long fo = va2fo(rva);
        auto fn = decode_function(m->data + fo, 4096, rva);
        check(fn.size() == 4, "func @0x4694440: 4 instructions");
        check(!fn.empty() && fn.back().op == Op::BR && fn.back().is_terminator(),
              "func @0x4694440: terminates at BR");
    }
    // Функция @0x4694480: длиннее, заканчивается RET на 0x46944e4 (26 инстр.).
    {
        const u64 rva = 0x4694480ULL;
        const long fo = va2fo(rva);
        auto fn = decode_function(m->data + fo, 4096, rva);
        check(fn.size() == 26, "func @0x4694480: 26 instructions");
        check(!fn.empty() && fn.back().op == Op::RET && fn.back().pc == 0x46944e4ULL,
              "func @0x4694480: terminates at RET @0x46944e4");
    }
    // RET прямо на входе: одна инструкция.
    {
        const u64 rva = 0x4694434ULL;
        const long fo = va2fo(rva);
        auto fn = decode_function(m->data + fo, 4096, rva);
        check(fn.size() == 1 && fn[0].op == Op::RET, "func @0x4694434: single RET");
    }
    // Потолок безопасности: max_bytes ограничен 4096 даже при запросе больше.
    {
        const u64 rva = 0x4694420ULL;
        const long fo = va2fo(rva);
        auto fn = decode_function(m->data + fo, 1u << 20, rva);
        check(fn.size() * 4 <= 4096, "decode_function caps at 4096 bytes");
    }
}

}  // namespace

int main() {
    std::printf("=== test_arm64: AArch64 decoder ===\n");
    test_real_instructions();
    test_synthetic_forms();
    test_pcrel_math();
    test_semantics();
    test_extract_xrefs();
    test_function_boundary();

    std::printf("\n=== %s (failures: %d) ===\n",
                g_failures == 0 ? "PASS" : "FAIL", g_failures);
    return g_failures == 0 ? 0 : 1;
}
