// oxdump/arm64/disasm.cpp — реализация компактного декодера AArch64.
//
// Порядок разбора важен: сначала самые узкие маски (RET/BR/BLR, hint-space),
// затем PC-относительные формы, затем остальное. Каждая проверка — маска AND
// плюс сравнение с сигнатурой из ARM ARM (DDI0487). Никаких таблиц: форм
// немного, «плоский» каскад if читается прямее и оптимизируется компилятором в
// набор сравнений.
//
// Ссылки на разделы ARM ARM даны в комментариях у соответствующих форм.
#include "oxdump/arm64/disasm.h"
#include <algorithm>
#include <cstring>

namespace oxdump::arm64 {

namespace {

// Знаковое расширение младших `bits` бит значения v до s64.
inline s64 sext(u64 v, unsigned bits) noexcept {
    const u64 m = 1ull << (bits - 1);
    return static_cast<s64>((v ^ m) - m);
}

// Выделить поле [hi:lo] (включительно) из слова.
inline u32 bitfield(u32 w, unsigned lo, unsigned hi) noexcept {
    return (w >> lo) & ((1u << (hi - lo + 1)) - 1u);
}

} // namespace

Insn decode(u32 raw, u64 pc) noexcept {
    Insn in;
    in.raw = raw;
    in.pc = pc;

    // ── Ветвления с косвенным регистром и возврат (C4.1.7.1, unconditional
    //    branch register). RET/BR/BLR отличаются полями opc[24:21] в общем
    //    префиксе 1101 011. Маска 0xFFFFFC1F фиксирует всё, кроме Rn[9:5]. ──
    if ((raw & 0xFFFFFC1Fu) == 0xD65F0000u) {          // RET {Xn}
        in.op = Op::RET;
        in.rn = static_cast<u8>(bitfield(raw, 5, 9));
        return in;
    }
    if ((raw & 0xFFFFFC1Fu) == 0xD61F0000u) {          // BR Xn
        in.op = Op::BR;
        in.rn = static_cast<u8>(bitfield(raw, 5, 9));
        return in;
    }
    if ((raw & 0xFFFFFC1Fu) == 0xD63F0000u) {          // BLR Xn
        in.op = Op::BLR;
        in.rn = static_cast<u8>(bitfield(raw, 5, 9));
        return in;
    }

    // ── Hint-пространство: NOP, BTI, PACIASP и т.п. (C4.1.5). Все имеют вид
    //    1101 0101 0000 0011 0010 xxxx xxx1 1111. Для дампера это наполнитель:
    //    сводим к Op::NOP, не терминатор. ──
    if ((raw & 0xFFFFF01Fu) == 0xD503201Fu) {
        in.op = Op::NOP;
        return in;
    }

    // ── PC-относительная адресация (C4.1.2): ADR / ADRP. Общий вид
    //    op immlo 10000 immhi Rd, где op[31] выбирает ADR(0)/ADRP(1).
    //    immhi[23:5] : immlo[30:29] — 21-битное знаковое смещение. ──
    if ((raw & 0x1F000000u) == 0x10000000u) {
        const u32 immlo = bitfield(raw, 29, 30);
        const u32 immhi = bitfield(raw, 5, 23);
        const s64 imm21 = sext((static_cast<u64>(immhi) << 2) | immlo, 21);
        in.rd = static_cast<u8>(bitfield(raw, 0, 4));
        if (raw & 0x80000000u) {                        // ADRP: страница
            in.op = Op::ADRP;
            in.imm = static_cast<s64>((pc & ~0xFFFull) + (static_cast<u64>(imm21) << 12));
        } else {                                        // ADR: байтовое смещение
            in.op = Op::ADR;
            in.imm = static_cast<s64>(pc + static_cast<u64>(imm21));
        }
        return in;
    }

    // ── Безусловный B / BL (C4.1.7): op 00101 imm26. op[31]: 0=B, 1=BL.
    //    imm26 — знаковое, шаг 4 байта. imm → целевой VA. ──
    if ((raw & 0x7C000000u) == 0x14000000u) {
        const s64 off = sext(bitfield(raw, 0, 25), 26) * 4;
        in.op = (raw & 0x80000000u) ? Op::BL : Op::B;
        in.imm = static_cast<s64>(pc + static_cast<u64>(off));
        return in;
    }

    // ── Условное B.cond (C4.1.7): 0101 0100 imm19 0 cond. imm19 знаковое,
    //    шаг 4. cond[3:0]. ──
    if ((raw & 0xFF000010u) == 0x54000000u) {
        const s64 off = sext(bitfield(raw, 5, 23), 19) * 4;
        in.op = Op::B_cond;
        in.cond = static_cast<u8>(bitfield(raw, 0, 3));
        in.imm = static_cast<s64>(pc + static_cast<u64>(off));
        return in;
    }

    // ── Compare&branch CBZ/CBNZ (C4.1.7): sf 011010 op imm19 Rt.
    //    op[24]: 0=CBZ, 1=CBNZ. sf[31]: 32/64-бит. imm19 знаковое, шаг 4. ──
    if ((raw & 0x7E000000u) == 0x34000000u) {
        const s64 off = sext(bitfield(raw, 5, 23), 19) * 4;
        in.op = (raw & 0x01000000u) ? Op::CBNZ : Op::CBZ;
        in.sf = (raw & 0x80000000u) != 0;
        in.rd = static_cast<u8>(bitfield(raw, 0, 4));   // Rt в поле rd
        in.imm = static_cast<s64>(pc + static_cast<u64>(off));
        return in;
    }

    // ── Test&branch TBZ/TBNZ (C4.1.7): b5 011011 op b40 imm14 Rt.
    //    Тестируемый бит = (b5<<5)|b40. op[24]: 0=TBZ,1=TBNZ. imm14 знаковое. ──
    if ((raw & 0x7E000000u) == 0x36000000u) {
        const s64 off = sext(bitfield(raw, 5, 18), 14) * 4;
        const u32 b40 = bitfield(raw, 19, 23);
        const u32 b5 = bitfield(raw, 31, 31);
        in.op = (raw & 0x01000000u) ? Op::TBNZ : Op::TBZ;
        in.bit = static_cast<u8>((b5 << 5) | b40);
        in.rd = static_cast<u8>(bitfield(raw, 0, 4));   // Rt в поле rd
        in.imm = static_cast<s64>(pc + static_cast<u64>(off));
        return in;
    }

    // ── Загрузки с литералом (C4.1.4, Load register (literal)):
    //    opc 011 V 00 imm19 Rt. Нас интересуют невекторные (V=0):
    //      opc=00 → LDR Wt (32),  opc=01 → LDR Xt (64),
    //      opc=10 → LDRSW Xt,     opc=11 → PRFM.
    //    Маска 0x3B000000==0x18000000 выделяет всю группу. imm19*4 знаковое. ──
    if ((raw & 0x3B000000u) == 0x18000000u) {
        const s64 off = sext(bitfield(raw, 5, 23), 19) * 4;
        const u32 opc = bitfield(raw, 30, 31);
        in.rd = static_cast<u8>(bitfield(raw, 0, 4));   // Rt в поле rd
        in.imm = static_cast<s64>(pc + static_cast<u64>(off));
        switch (opc) {
            case 0b00: in.op = Op::LDR_lit;   in.sf = false; break; // LDR Wt
            case 0b01: in.op = Op::LDR_lit;   in.sf = true;  break; // LDR Xt
            case 0b10: in.op = Op::LDRSW_lit; in.sf = true;  break; // LDRSW Xt
            default:   in.op = Op::PRFM_lit;                 break; // PRFM
        }
        return in;
    }

    // ── ADD (immediate), 64-бит (C6.2.4): 1 00 100010 sh imm12 Rn Rd.
    //    Маска 0xFF800000==0x91000000. sh[22] масштабирует imm12<<12.
    //    Отдельно ловим алиас MOV Xd, SP (ADD Xd,SP,#0). ──
    if ((raw & 0xFF800000u) == 0x91000000u) {
        const u32 sh = bitfield(raw, 22, 22);
        const u32 imm12 = bitfield(raw, 10, 21);
        in.op = Op::ADD_imm;
        in.rd = static_cast<u8>(bitfield(raw, 0, 4));
        in.rn = static_cast<u8>(bitfield(raw, 5, 9));
        in.imm = static_cast<s64>(sh ? (static_cast<u64>(imm12) << 12) : imm12);
        return in;
    }

    // ── MOV (register) = алиас ORR Xd, XZR, Xm (C6.2.204):
    //    sf 01 01010 00 0 Rm 000000 11111 Rd. Rn зафиксирован в XZR(31),
    //    shift=0. Проверяем сигнатуру, кроме Rm[20:16] и Rd[4:0]. Ловим обе
    //    ширины: 64-бит (0xAA..., sf=1) и 32-бит (0x2A..., sf=0). Только
    //    64-битная форма переносит «страничность» в extract_xrefs. ──
    if ((raw & 0xFFE0FFE0u) == 0xAA0003E0u) {
        in.op = Op::MOV_reg;
        in.rd = static_cast<u8>(bitfield(raw, 0, 4));
        in.rm = static_cast<u8>(bitfield(raw, 16, 20));
        in.sf = true;
        return in;
    }
    if ((raw & 0xFFE0FFE0u) == 0x2A0003E0u) {
        in.op = Op::MOV_reg;
        in.rd = static_cast<u8>(bitfield(raw, 0, 4));
        in.rm = static_cast<u8>(bitfield(raw, 16, 20));
        in.sf = false;
        return in;
    }

    // ── LDR (immediate), невекторные, размер 64 и 32 (C6.2.131).
    //    Общий префикс size 111 0 00 ... . Ловим три под-формы 64-бит:
    //      unsigned offset : 11 111 0 01 01 imm12 Rn Rt  (0xF9400000)
    //      post-index      : 11 111 0 00 01 0 imm9 01 Rn Rt (0xF8400400)
    //      pre-index       : 11 111 0 00 01 0 imm9 11 Rn Rt (0xF8400C00)
    //    и их 32-битные аналоги (size=10, префикс 0xB8/0xB9). Для наших целей
    //    (пара с ADRP) значим только unsigned-offset 64-бит: он даёт адрес
    //    слота. Остальные формы декодируем ради полноты и корректной остановки. ──
    // unsigned offset, 64-бит:
    if ((raw & 0xFFC00000u) == 0xF9400000u) {
        in.op = Op::LDR_imm;
        in.sf = true;
        in.rd = static_cast<u8>(bitfield(raw, 0, 4));   // Rt
        in.rn = static_cast<u8>(bitfield(raw, 5, 9));
        in.imm = static_cast<s64>(bitfield(raw, 10, 21)) * 8; // scaled ×8
        return in;
    }
    // unsigned offset, 32-бит:
    if ((raw & 0xFFC00000u) == 0xB9400000u) {
        in.op = Op::LDR_imm;
        in.sf = false;
        in.rd = static_cast<u8>(bitfield(raw, 0, 4));
        in.rn = static_cast<u8>(bitfield(raw, 5, 9));
        in.imm = static_cast<s64>(bitfield(raw, 10, 21)) * 4; // scaled ×4
        return in;
    }
    // pre/post-index, 64-бит (imm9 знаковое, без масштаба):
    if ((raw & 0xFFE00400u) == 0xF8400400u) {
        in.op = Op::LDR_imm;
        in.sf = true;
        in.rd = static_cast<u8>(bitfield(raw, 0, 4));
        in.rn = static_cast<u8>(bitfield(raw, 5, 9));
        in.imm = sext(bitfield(raw, 12, 20), 9);
        in.writeback = true;
        in.post_index = (bitfield(raw, 10, 11) == 0b01);
        return in;
    }
    // pre/post-index, 32-бит:
    if ((raw & 0xFFE00400u) == 0xB8400400u) {
        in.op = Op::LDR_imm;
        in.sf = false;
        in.rd = static_cast<u8>(bitfield(raw, 0, 4));
        in.rn = static_cast<u8>(bitfield(raw, 5, 9));
        in.imm = sext(bitfield(raw, 12, 20), 9);
        in.writeback = true;
        in.post_index = (bitfield(raw, 10, 11) == 0b01);
        return in;
    }

    // Всё прочее дамперу неинтересно.
    return in;
}

std::vector<Insn> decode_function(const u8* code, std::size_t max_bytes,
                                  u64 base_pc) {
    std::vector<Insn> out;
    if (!code) return out;

    // Потолок безопасности: не более 4096 байт (~1024 инструкции), даже если
    // вызывающий попросил больше. Кратно 4.
    std::size_t cap = std::min<std::size_t>(max_bytes, 4096);
    cap &= ~std::size_t{3};

    // Детектор наполнителя между функциями: несколько NOP/BTI подряд после
    // хотя бы одного реального терминатора-соседа означает «выравнивающий зазор»
    // — тело закончилось. Считаем подряд идущие hint-инструкции.
    std::size_t nop_run = 0;

    for (std::size_t off = 0; off + 4 <= cap; off += 4) {
        u32 raw;
        std::memcpy(&raw, code + off, 4);
        const u64 pc = base_pc + off;
        Insn in = decode(raw, pc);
        out.push_back(in);

        if (in.op == Op::NOP) {
            // Полоса из ≥4 наполнителей — почти наверняка выравнивание между
            // функциями. Останавливаемся (сами наполнители остаются в выводе).
            if (++nop_run >= 4) break;
        } else {
            nop_run = 0;
        }

        if (in.is_terminator()) {
            // RET и BR — безусловный конец. Безусловный B: конец, если цель
            // ведёт ВПЕРЁД за пределы текущей функции. Мы не знаем границ, но
            // хвост-переход за пределы 4-КБ страницы почти всегда tail-call к
            // другой функции — считаем это концом. B назад/близко (в пределах
            // страницы) может быть циклом: не останавливаемся на первой же.
            if (in.op == Op::RET || in.op == Op::BR) break;
            if (in.op == Op::B) {
                const u64 page = pc & ~0xFFFull;
                const u64 tgt = static_cast<u64>(in.imm);
                if ((tgt & ~0xFFFull) != page) break;   // за пределы страницы → tail-call
                // иначе — вероятно локальный переход/цикл, продолжаем.
            }
        }
    }
    return out;
}

std::vector<u64> extract_xrefs(const u8* code, std::size_t bytes, u64 base_pc) {
    std::vector<u64> out;
    if (!code) return out;

    // Значение ADRP по каждому регистру: держим последнюю страницу, пока
    // регистр не перезаписан. reg_page[r] валиден только при reg_has[r].
    u64 reg_page[32];
    bool reg_has[32];
    std::memset(reg_has, 0, sizeof(reg_has));

    const std::size_t n = bytes & ~std::size_t{3};
    for (std::size_t off = 0; off + 4 <= n; off += 4) {
        u32 raw;
        std::memcpy(&raw, code + off, 4);
        const u64 pc = base_pc + off;
        const Insn in = decode(raw, pc);

        switch (in.op) {
            case Op::ADRP: {
                // Начало адресной пары: запоминаем страницу в целевом регистре.
                reg_page[in.rd] = static_cast<u64>(in.imm);
                reg_has[in.rd] = true;
                break;
            }
            case Op::ADD_imm: {
                // ADRP+ADD → прямой адрес (строка/данные в rodata). Требуем,
                // чтобы источник нёс страницу от предыдущего ADRP.
                if (reg_has[in.rn]) {
                    out.push_back(reg_page[in.rn] + static_cast<u64>(in.imm));
                }
                // Результат ADD — уже адрес, не страница: регистр «потрачен».
                reg_has[in.rd] = false;
                break;
            }
            case Op::LDR_imm: {
                // ADRP+LDR(unsigned off) → адрес слота данных (в нём указатель).
                // Значим только 64-битный unsigned-offset поверх ADRP-регистра.
                if (in.sf && !in.writeback && reg_has[in.rn]) {
                    out.push_back(reg_page[in.rn] + static_cast<u64>(in.imm));
                }
                // Rt перезаписан загруженным значением.
                reg_has[in.rd] = false;
                break;
            }
            case Op::ADR: {
                // Одиночный ADR несёт готовый VA.
                out.push_back(static_cast<u64>(in.imm));
                reg_has[in.rd] = false;   // Rd теперь адрес, не страница
                break;
            }
            case Op::LDR_lit:
            case Op::LDRSW_lit:
            case Op::PRFM_lit: {
                // PC-литерал: адрес самого литерала в образе.
                out.push_back(static_cast<u64>(in.imm));
                reg_has[in.rd] = false;
                break;
            }
            case Op::MOV_reg: {
                // Перенос регистра переносит и «страничность»: MOV Xd, Xm.
                // Только 64-битная форма: 32-битная обнулила бы старшие биты
                // адреса, «страница» через неё не проходит.
                if (in.sf && reg_has[in.rm]) {
                    reg_page[in.rd] = reg_page[in.rm];
                    reg_has[in.rd] = true;
                } else {
                    reg_has[in.rd] = false;
                }
                break;
            }
            default: {
                // Инструкция, пишущая в Rd, но нам не интересная, могла
                // перезаписать регистр. Мы не отслеживаем произвольные записи
                // (это заведомо неполно), но известные writeback-формы гасим.
                if (in.op == Op::LDR_imm && in.writeback) reg_has[in.rd] = false;
                break;
            }
        }
    }

    // Уникализируем и сортируем: контракт — «множество целевых VA».
    std::sort(out.begin(), out.end());
    out.erase(std::unique(out.begin(), out.end()), out.end());
    return out;
}

} // namespace oxdump::arm64
