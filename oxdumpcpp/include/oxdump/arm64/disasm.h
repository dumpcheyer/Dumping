// oxdump/arm64/disasm.h — компактный дизассемблер AArch64 для нужд дампера.
//
// ЗАЧЕМ. Прежний xref-пасс нёс мини-декодер на 4 формы (ADRP/ADD/LDR/RET) и
// находил на тестовой цели всего 6 подсказок. Настоящий декодер видит больше
// адресных ссылок и, что важнее, открывает дорогу будущим фичам: построению
// графа вызовов и деобфускации по перекрёстным ссылкам. Это НЕ полный
// дизассемблер с красивой печатью — только декод плюс извлечение ссылок на VA,
// ровно те формы, что нужны дамперу.
//
// ЧТО ДЕКОДИРУЕТСЯ.
//   • PC-относительные адреса: ADR, ADRP, LDR (literal), LDRSW (literal),
//     PRFM (literal) — все несут целевой VA прямо в поле imm декода.
//   • Вычисление адреса: ADD (immediate), MOV (register, алиас ORR).
//   • Загрузки: LDR (immediate, unsigned/signed/pre/post-index).
//   • Ветвления: B, BL, B.cond, CBZ/CBNZ, TBZ/TBNZ, BR, BLR, RET.
//   • NOP/BTI/прочие hint-инструкции сведены к Op::NOP (наполнитель).
//
// СЕМАНТИКА imm. Для форм с PC-относительным адресом (ADRP/ADR/*_lit и всех
// ветвлений с целью) поле imm — это уже ВЫЧИСЛЕННЫЙ целевой VA, а не сырое
// смещение: вызывающему не нужно повторять арифметику PC. Для ADD/LDR imm —
// это непосредственный операнд (смещение), НЕ адрес.
//
// Формат little-endian A64: одно слово = 4 байта. Все декоды noexcept и без
// аллокаций — их зовут в горячем цикле по миллионам инструкций.
#pragma once
#include "oxdump/common.h"
#include <vector>
#include <cstddef>

namespace oxdump::arm64 {

// Опкоды, которые нас интересуют. Всё, что декодер не распознал, — Unknown;
// это не ошибка, а «данная форма дамперу неинтересна» (арифметика, SIMD, …).
enum class Op : u16 {
    Unknown,
    ADRP,      // ADRP Xd, page      : imm = целевой VA страницы
    ADR,       // ADR  Xd, label     : imm = целевой VA
    ADD_imm,   // ADD  Xd, Xn, #imm  : imm = непосредственное (уже с учётом sh)
    MOV_reg,   // MOV  Xd, Xm        : алиас ORR Xd, XZR, Xm  (rm = источник)
    LDR_imm,   // LDR  Xt, [Xn,#off] : imm = байтовое смещение; pre/post — см. imm/флаги
    LDR_lit,   // LDR  Xt, label     : imm = целевой VA (PC + off*4)
    LDRSW_lit, // LDRSW Xt, label    : imm = целевой VA
    PRFM_lit,  // PRFM  op, label    : imm = целевой VA
    B,         // B    label         : imm = целевой VA
    BL,        // BL   label         : imm = целевой VA
    B_cond,    // B.cc label         : imm = целевой VA; cond = условие
    CBZ,       // CBZ  Xt, label     : imm = целевой VA
    CBNZ,      // CBNZ Xt, label     : imm = целевой VA
    TBZ,       // TBZ  Xt, #bit,lbl  : imm = целевой VA; bit = тестируемый бит
    TBNZ,      // TBNZ Xt, #bit,lbl  : imm = целевой VA; bit = тестируемый бит
    BR,        // BR   Xn            : косвенный переход (терминатор)
    BLR,       // BLR  Xn            : косвенный вызов
    RET,       // RET  {Xn}          : возврат (терминатор)
    NOP,       // NOP / BTI / hint   : наполнитель
};

// Одна декодированная инструкция. Плоская POD-структура: копируется дёшево,
// вектор таких — естественный результат decode_function().
struct Insn {
    u32 raw = 0;         // сырые 4 байта инструкции
    u64 pc = 0;          // её собственный PC (VA)
    Op  op = Op::Unknown;
    u8  rd = 0;          // регистр-приёмник (0..31, 31 = xzr/sp по контексту)
    u8  rn = 0;          // регистр-источник 1
    u8  rm = 0;          // регистр-источник 2 (для reg-reg форм)
    s64 imm = 0;         // непосредственное / целевой VA (см. семантику выше)
    u8  cond = 0;        // условие для B.cond (0..15)
    u8  bit = 0;         // тестируемый бит для TBZ/TBNZ (0..63)
    bool sf = false;     // 1 = 64-битная форма (для CBZ/CBNZ/LDR и т.п.)
    bool writeback = false; // pre/post-index у LDR_imm (rn изменяется)
    bool post_index = false; // post-index (offset применяется после доступа)

    // Терминатор потока управления: безусловный переход/возврат. На таком
    // инструкции линейный разбор тела функции останавливается.
    bool is_terminator() const noexcept {
        return op == Op::RET || op == Op::BR || op == Op::B;
    }

    // Несёт ли инструкция конкретный VA (для сбора xref). Для этих форм поле
    // imm — уже готовый целевой VA. ADD_imm/LDR_imm сюда НЕ входят: их imm —
    // смещение, а не адрес (адрес получается в паре с предшествующим ADRP).
    bool has_pc_ref() const noexcept {
        switch (op) {
            case Op::ADRP: case Op::ADR:
            case Op::LDR_lit: case Op::LDRSW_lit: case Op::PRFM_lit:
            case Op::B: case Op::BL: case Op::B_cond:
            case Op::CBZ: case Op::CBNZ: case Op::TBZ: case Op::TBNZ:
                return true;
            default:
                return false;
        }
    }

    // Любой прямой переход/вызов с известной целью (для будущего графа вызовов).
    bool is_branch() const noexcept {
        switch (op) {
            case Op::B: case Op::BL: case Op::B_cond:
            case Op::CBZ: case Op::CBNZ: case Op::TBZ: case Op::TBNZ:
            case Op::BR: case Op::BLR:
                return true;
            default:
                return false;
        }
    }
};

// Декодировать одну инструкцию. pc — VA самой инструкции (нужен для
// PC-относительных форм). Не бросает; нераспознанное → Op::Unknown.
Insn decode(u32 raw, u64 pc) noexcept;

// Линейно декодировать поток инструкций до первого is_terminator() или до
// исчерпания max_bytes (потолок безопасности, обычно 4096). base_pc — VA
// первой инструкции. Терминатор включается в результат.
std::vector<Insn> decode_function(const u8* code, std::size_t max_bytes,
                                  u64 base_pc);

// Извлечь все PC-относительные ссылки на VA из диапазона [base_pc, +bytes).
// Разбирает пары ADRP+ADD и ADRP+LDR (даёт итоговый вычисленный адрес),
// одиночные ADR и все *_lit-формы. Возвращает МНОЖЕСТВО целевых VA
// (отсортированное, без дублей). Ветвления сюда НЕ включаются — это ссылки на
// код, а xref-пассу нужны ссылки на данные/строки.
std::vector<u64> extract_xrefs(const u8* code, std::size_t bytes, u64 base_pc);

} // namespace oxdump::arm64
