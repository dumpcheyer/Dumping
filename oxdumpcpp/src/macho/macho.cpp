// oxdump/macho/macho.cpp — реализация разбора Mach-O 64 и таблицы rebase.
//
// Форма и пороги find_metadata_registration / find_field_offsets / packing_check
// калькированы с elf64.cpp: единственное отличие форматов — способ доставки
// указателей (rebase-байткод вместо RELA), сам поиск таблиц IL2CPP идентичен.
// Пороги и «послабления» перенесены вместе с причинами — иначе при «чистке»
// кода они вернутся как баги на реальных библиотеках.
#include "oxdump/macho/macho.h"
#include <algorithm>

namespace oxdump::macho {

namespace {

// Магии Mach-O и FAT. LE-порядок как он лежит в файле (первые 4 байта).
constexpr u32 MH_MAGIC_64    = 0xFEEDFACF;  // 64-бит, тот же порядок байт
constexpr u32 MH_MAGIC_32    = 0xFEEDFACE;  // 32-бит
constexpr u32 MH_CIGAM_64    = 0xCFFAEDFE;  // 64-бит, обратный порядок (BE-хост)
constexpr u32 MH_CIGAM_32    = 0xCEFAEDFE;  // 32-бит, обратный порядок
constexpr u32 FAT_MAGIC      = 0xCAFEBABE;  // FAT, поля big-endian
constexpr u32 FAT_CIGAM      = 0xBEBAFECA;  // FAT, поля little-endian

// cputype: нам интересны только эти два (и бит 64 у arm64/x86_64).
constexpr u32 CPU_TYPE_ARM64  = 0x0100000C;
constexpr u32 CPU_TYPE_X86_64 = 0x01000007;

// Команды загрузки, которые мы разбираем.
constexpr u32 LC_SEGMENT_64          = 0x19;
constexpr u32 LC_DYLD_INFO           = 0x22;
constexpr u32 LC_DYLD_INFO_ONLY      = 0x80000022;
constexpr u32 LC_DYLD_CHAINED_FIXUPS = 0x80000034;

// Опкоды rebase-байткода (верхний ниббл байта; нижний — immediate).
constexpr u8 REBASE_OPCODE_MASK                               = 0xF0;
constexpr u8 REBASE_IMMEDIATE_MASK                           = 0x0F;
constexpr u8 REBASE_OPCODE_DONE                              = 0x00;
constexpr u8 REBASE_OPCODE_SET_TYPE_IMM                      = 0x10;
constexpr u8 REBASE_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB       = 0x20;
constexpr u8 REBASE_OPCODE_ADD_ADDR_ULEB                     = 0x30;
constexpr u8 REBASE_OPCODE_ADD_ADDR_IMM_SCALED              = 0x40;
constexpr u8 REBASE_OPCODE_DO_REBASE_IMM_TIMES              = 0x50;
constexpr u8 REBASE_OPCODE_DO_REBASE_ULEB_TIMES            = 0x60;
constexpr u8 REBASE_OPCODE_DO_REBASE_ADD_ADDR_ULEB        = 0x70;
constexpr u8 REBASE_OPCODE_DO_REBASE_ULEB_TIMES_SKIPPING_ULEB = 0x80;

constexpr u64 PTR_SIZE = 8;

// Текущая версия заголовка chained-fixups (dyld_chained_fixups_header.
// fixups_version). Всё, что не 0, мы не понимаем.
constexpr u32 CHAINED_FIXUPS_VERSION = 0;

// Байтовое чтение magic без учёта размера — вызывающий уже проверил size>=4.
u32 read_magic(ByteView d) noexcept { return d.read_u32(0); }

// FAT-поля big-endian; на LE-хосте читаем через byteswap.
u32 be32(ByteView d, std::size_t off) noexcept {
    return __builtin_bswap32(d.read_u32(off));
}

// Вырезать битовое поле [lo, lo+width) из 64-битного слова. width<=64.
inline u64 bits(u64 v, unsigned lo, unsigned width) noexcept {
    if (width == 0) return 0;
    if (width >= 64) return v >> lo;
    return (v >> lo) & ((u64{1} << width) - 1);
}

} // namespace

// ── распаковка звена цепочки (тестируемая чистая функция) ─────────────────────
//
// Раскладки битов взяты из <mach-o/fixup-chains.h> (Apple XNU). Комментарии у
// каждой ветви повторяют имена и ширины полей структур dyld_chained_ptr_*.
// next — шаг до следующего звена в единицах по 4 байта; наружу отдаём его уже в
// БАЙТАХ (×4). next==0 → конец цепочки.
namespace detail {

ChainEntry unpack_chain_entry(u64 raw, u16 pointer_format, u64 image_base) noexcept {
    ChainEntry e;
    switch (pointer_format) {
        case DYLD_CHAINED_PTR_ARM64E:
        case DYLD_CHAINED_PTR_ARM64E_USERLAND:
        case DYLD_CHAINED_PTR_ARM64E_USERLAND24:
        case DYLD_CHAINED_PTR_ARM64E_KERNEL:
        case DYLD_CHAINED_PTR_ARM64E_FIRMWARE: {
            // Общие для всех arm64e-вариантов (<mach-o/fixup-chains.h>):
            //   ...target/high8..., next:11, bind:1, auth:1
            // То есть bit63=auth, bit62=bind, next — 11 бит на [51,62). Шаг next
            // домножаем на 4.
            const bool auth = bits(raw, 63, 1) != 0;
            const bool bind = bits(raw, 62, 1) != 0;
            const u32  next = static_cast<u32>(bits(raw, 51, 11));
            e.is_bind = bind;
            e.next_delta = next * 4;

            // Ширина ordinal у USERLAND24 — 24 бита, у прочих arm64e — 16.
            const unsigned ord_bits =
                (pointer_format == DYLD_CHAINED_PTR_ARM64E_USERLAND24) ? 24u : 16u;

            if (bind) {
                // bind / auth-bind: младшие ord_bits — порядковый номер импорта.
                // target для bind не осмыслен (импорт резолвит загрузчик).
                e.import_ordinal = static_cast<u32>(bits(raw, 0, ord_bits));
            } else if (auth) {
                // auth-rebase: target:32 — смещение ОТ БАЗЫ образа (не абсолют).
                //   dyld_chained_ptr_arm64e_auth_rebase {
                //     target:32, diversity:16, addrDiv:1, key:2, next:11,
                //     bind:1(=0), auth:1(=1) }
                const u64 target_off = bits(raw, 0, 32);
                e.target = image_base + target_off;
            } else {
                // plain rebase:
                //   dyld_chained_ptr_arm64e_rebase {
                //     target:43, high8:8, next:11, bind:1(=0), auth:1(=0) }
                // Полный указатель = high8<<56 | target. У USERLAND/USERLAND24
                // target трактуется как смещение от базы; у классического ARM64E
                // и KERNEL/FIRMWARE — как есть (плюс high8 сверху).
                const u64 target = bits(raw, 0, 43);
                const u64 high8  = bits(raw, 43, 8);
                const u64 full   = (high8 << 56) | target;
                const bool userland =
                    (pointer_format == DYLD_CHAINED_PTR_ARM64E_USERLAND ||
                     pointer_format == DYLD_CHAINED_PTR_ARM64E_USERLAND24);
                e.target = userland ? (image_base + full) : full;
            }
            return e;
        }

        case DYLD_CHAINED_PTR_64:
        case DYLD_CHAINED_PTR_64_OFFSET: {
            // 64-битный «plain» указатель. bit63=bind, next в битах [51:52+12) =
            // [51,63). Шаг next домножаем на 4.
            const bool bind = bits(raw, 63, 1) != 0;
            const u32  next = static_cast<u32>(bits(raw, 51, 12));
            e.is_bind = bind;
            e.next_delta = next * 4;

            if (bind) {
                // dyld_chained_ptr_64_bind {
                //   ordinal:24, addend:8, reserved:19, next:12, bind:1(=1) }
                e.import_ordinal = static_cast<u32>(bits(raw, 0, 24));
            } else {
                // dyld_chained_ptr_64_rebase {
                //   target:36, high8:8, reserved:7, next:12, bind:1(=0) }
                const u64 target = bits(raw, 0, 36);
                const u64 high8  = bits(raw, 36, 8);
                if (pointer_format == DYLD_CHAINED_PTR_64_OFFSET) {
                    // target — смещение от базы образа; high8 всё равно сверху.
                    e.target = image_base + ((high8 << 56) | target);
                } else {
                    // target — абсолютный runtime-адрес (в файле лежит с учётом
                    // предпочтительной базы). high8 — верхний байт указателя.
                    e.target = (high8 << 56) | target;
                }
            }
            return e;
        }

        default:
            // Неизвестный/неподдержанный формат — вернуть пустую запись, чтобы
            // вызывающий остановил цепочку (next_delta==0).
            return e;
    }
}

} // namespace detail

Macho::Macho(ByteView data) {
    if (!data.valid() || data.size < 4) {
        throw BinaryError("не Mach-O файл (пустой ввод)");
    }
    // Разворачиваем FAT (если это он) и выбираем срез нужной архитектуры.
    v_ = select_slice(data);

    if (v_.size < 32) {
        throw BinaryError("Mach-O заголовок обрезан");
    }
    const u32 magic = read_magic(v_);
    if (magic == MH_MAGIC_32 || magic == MH_CIGAM_32) {
        // 32-битные Mach-O у IL2CPP-игр давно не встречаются (все iOS-цели
        // 64-битные с iOS 11). Разбор 32-бит не даст ничего полезного — таблицы
        // всё равно лежат по 64-битным указателям.
        throw BinaryError("32-битный Mach-O не поддерживается — нужен arm64/x86_64");
    }
    if (magic != MH_MAGIC_64 && magic != MH_CIGAM_64) {
        throw BinaryError("не Mach-O 64-бит (неверная магия)");
    }
    // mach_header_64: magic, cputype, cpusubtype, filetype, ncmds, sizeofcmds,
    // flags, reserved. cputype на смещении 4.
    cpu_type_ = v_.read_u32(4);

    parse_load_commands();
}

ByteView Macho::select_slice(ByteView data) {
    const u32 magic = read_magic(data);
    if (magic != FAT_MAGIC && magic != FAT_CIGAM) {
        return data;  // обычный Mach-O — срез это весь файл
    }
    // fat_header { uint32 magic; uint32 nfat_arch } — поля big-endian.
    // fat_arch { cputype, cpusubtype, offset, size, align } — тоже big-endian.
    const bool be = (magic == FAT_MAGIC);
    auto rd = [&](std::size_t off) -> u32 {
        return be ? be32(data, off) : data.read_u32(off);
    };
    const u32 nfat = rd(4);
    if (nfat == 0 || nfat > 32) {
        throw BinaryError("FAT Mach-O: неправдоподобное число срезов");
    }
    // Ищем срез по приоритету: сперва arm64, затем x86_64, иначе первый годный.
    u64 chosen_off = 0, chosen_size = 0;
    u32 chosen_cpu = 0;
    int best_rank = 99;
    for (u32 i = 0; i < nfat; ++i) {
        const std::size_t a = 8 + static_cast<std::size_t>(i) * 20;
        if (a + 20 > data.size) break;
        const u32 cputype = rd(a);
        const u32 off = rd(a + 8);
        const u32 size = rd(a + 12);
        if (static_cast<u64>(off) + size > data.size) continue;
        int rank = (cputype == CPU_TYPE_ARM64)  ? 0
                 : (cputype == CPU_TYPE_X86_64) ? 1
                                                : 2;
        if (rank < best_rank) {
            best_rank = rank;
            chosen_off = off;
            chosen_size = size;
            chosen_cpu = cputype;
        }
    }
    if (chosen_size == 0) {
        throw BinaryError("FAT Mach-O: не найден пригодный срез (нет arm64/x86_64)");
    }
    // reloc_source_ пока не заполнен parse-ом — фиксируем выбор среза, чтобы это
    // попало в отчёт (parse_rebase допишет источник релокаций после двоеточия).
    reloc_source_ = std::string("FAT срез ") +
        (chosen_cpu == CPU_TYPE_ARM64  ? "arm64"  :
         chosen_cpu == CPU_TYPE_X86_64 ? "x86_64" : "?") + "; ";
    return data.slice(chosen_off, chosen_size);
}

void Macho::parse_load_commands() {
    // mach_header_64: 32 байта. ncmds на +16, sizeofcmds на +20. Команды идут
    // сразу за заголовком и обходятся линейно по cmdsize.
    const u32 ncmds = v_.read_u32(16);
    const u32 sizeofcmds = v_.read_u32(20);

    u64 rebase_off = 0, rebase_size = 0;
    bool has_dyld_info = false;
    bool has_chained = false;
    u64 chained_cmd_off = 0;   // смещение LC_DYLD_CHAINED_FIXUPS в v_

    u64 o = 32;
    const u64 cmds_end = std::min<u64>(32 + sizeofcmds, v_.size);
    for (u32 i = 0; i < ncmds; ++i) {
        if (o + 8 > v_.size || o + 8 > cmds_end) break;
        const u32 cmd = v_.read_u32(o);
        const u32 cmdsize = v_.read_u32(o + 4);
        if (cmdsize < 8) break;  // защита от зацикливания на битой команде

        if (cmd == LC_SEGMENT_64) {
            // segment_command_64: cmd, cmdsize, segname[16], vmaddr, vmsize,
            // fileoff, filesize, maxprot, initprot, nsects, flags.
            if (o + 72 <= v_.size) {
                std::string name = v_.cstr(o + 8, 0, 16);
                const u64 vmaddr   = v_.read_u64(o + 24);
                const u64 vmsize   = v_.read_u64(o + 32);
                const u64 fileoff  = v_.read_u64(o + 40);
                const u64 filesize = v_.read_u64(o + 48);
                segments_.push_back({vmaddr, fileoff, filesize, vmsize, name});
                // Конец образа — по vmsize (как memsz у ELF): часть указателей
                // ведёт в «хвост» сегмента сверх filesize.
                if (vmaddr + vmsize > mem_end_) mem_end_ = vmaddr + vmsize;
            }
        } else if (cmd == LC_DYLD_INFO || cmd == LC_DYLD_INFO_ONLY) {
            // dyld_info_command: cmd, cmdsize, rebase_off, rebase_size,
            // bind_off, bind_size, weak_bind_off/size, lazy_bind_off/size,
            // export_off/size. rebase_off на +8, rebase_size на +12.
            if (o + 16 <= v_.size) {
                rebase_off = v_.read_u32(o + 8);
                rebase_size = v_.read_u32(o + 12);
                has_dyld_info = true;
            }
        } else if (cmd == LC_DYLD_CHAINED_FIXUPS) {
            has_chained = true;
            chained_cmd_off = o;
        }

        o += cmdsize;
    }

    // Сортировка по vaddr — va2fo и подсчёт границ полагаются на порядок.
    std::sort(segments_.begin(), segments_.end(),
              [](const Segment& a, const Segment& b) {
                  return a.vaddr < b.vaddr;
              });
    if (segments_.empty()) {
        throw BinaryError("не найдено ни одного LC_SEGMENT_64");
    }

    // ── источник релокаций ──────────────────────────────────────────────
    // Приоритет у цепочек фиксапов: если в образе есть и LC_DYLD_INFO, и
    // LC_DYLD_CHAINED_FIXUPS (редкие переходные сборки), разрешённые указатели
    // даёт именно цепочечный формат — по нему и работаем.
    if (has_chained) {
        parse_chained_fixups(chained_cmd_off);
        // Если разбор цепочек ничего не дал (битый/неподдержанный формат), а
        // LC_DYLD_INFO присутствует — откатываемся на rebase-байткод.
        if (reloc_.empty() && has_dyld_info && rebase_size > 0) {
            reloc_source_ += "; fallback ";
            parse_rebase(rebase_off, rebase_size);
        }
    } else if (has_dyld_info && rebase_size > 0) {
        parse_rebase(rebase_off, rebase_size);
    } else {
        reloc_source_ += "none";
    }
}

// ── uleb128 ─────────────────────────────────────────────────────────────────

namespace {
// Стандартный ULEB128: 7 бит на байт, старший бит — «есть продолжение».
// Возвращает значение, продвигает pos. Защита от выхода за буфер и от
// переполнения сдвига (после 63 бит новые биты игнорируем — битый байткод не
// должен ронять разбор).
u64 read_uleb(ByteView v, std::size_t& pos, std::size_t end) noexcept {
    u64 result = 0;
    int shift = 0;
    while (pos < end) {
        const u8 b = v.data[pos++];
        if (shift < 64) result |= static_cast<u64>(b & 0x7F) << shift;
        shift += 7;
        if (!(b & 0x80)) break;
    }
    return result;
}
} // namespace

void Macho::parse_rebase(u64 rebase_off, u64 rebase_size) {
    // Байткод rebase описывает: тип, текущий сегмент+смещение, и сколько раз
    // применить, продвигая адрес. Итог — список vaddr'ов, по которым загрузчик
    // проставит указатель. В отличие от ELF, значение уже лежит в файле по
    // этому vaddr (разрешённый указатель без slide) — его и запоминаем.
    reloc_source_ += "LC_DYLD_INFO rebase";

    if (rebase_off >= v_.size) return;
    const std::size_t end = std::min<std::size_t>(rebase_off + rebase_size, v_.size);
    std::size_t pos = rebase_off;

    u32 seg_index = 0;
    u64 seg_offset = 0;   // смещение внутри текущего сегмента

    // Применить одну rebase-запись: вычислить vaddr, прочитать значение из файла.
    auto apply = [&](u64 count) {
        for (u64 k = 0; k < count; ++k) {
            if (seg_index < segments_.size()) {
                const u64 vaddr = segments_[seg_index].vaddr + seg_offset;
                const auto fo = va2fo(vaddr);
                if (fo && *fo + 8 <= v_.size) {
                    reloc_[vaddr] = v_.read_u64(*fo);
                }
            }
            seg_offset += PTR_SIZE;
        }
    };

    while (pos < end) {
        const u8 byte = v_.data[pos++];
        const u8 opcode = byte & REBASE_OPCODE_MASK;
        const u8 imm = byte & REBASE_IMMEDIATE_MASK;

        switch (opcode) {
            case REBASE_OPCODE_DONE:
                return;
            case REBASE_OPCODE_SET_TYPE_IMM:
                // Тип rebase (POINTER=1 и т.п.) — для нас все типы это чтение
                // 8-байтного слова, различать их не нужно.
                break;
            case REBASE_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB:
                seg_index = imm;
                seg_offset = read_uleb(v_, pos, end);
                break;
            case REBASE_OPCODE_ADD_ADDR_ULEB:
                seg_offset += read_uleb(v_, pos, end);
                break;
            case REBASE_OPCODE_ADD_ADDR_IMM_SCALED:
                seg_offset += static_cast<u64>(imm) * PTR_SIZE;
                break;
            case REBASE_OPCODE_DO_REBASE_IMM_TIMES:
                apply(imm);
                break;
            case REBASE_OPCODE_DO_REBASE_ULEB_TIMES:
                apply(read_uleb(v_, pos, end));
                break;
            case REBASE_OPCODE_DO_REBASE_ADD_ADDR_ULEB:
                apply(1);
                seg_offset += read_uleb(v_, pos, end);
                break;
            case REBASE_OPCODE_DO_REBASE_ULEB_TIMES_SKIPPING_ULEB: {
                const u64 count = read_uleb(v_, pos, end);
                const u64 skip = read_uleb(v_, pos, end);
                for (u64 k = 0; k < count; ++k) {
                    if (seg_index < segments_.size()) {
                        const u64 vaddr = segments_[seg_index].vaddr + seg_offset;
                        const auto fo = va2fo(vaddr);
                        if (fo && *fo + 8 <= v_.size) {
                            reloc_[vaddr] = v_.read_u64(*fo);
                        }
                    }
                    seg_offset += PTR_SIZE + skip;
                }
                break;
            }
            default:
                // Неизвестный опкод — байткод битый, дальше идти нельзя.
                return;
        }
    }
}

// ── LC_DYLD_CHAINED_FIXUPS (iOS 15+/arm64e) ──────────────────────────────────
//
// Структуры из <mach-o/fixup-chains.h>:
//   linkedit_data_command { cmd, cmdsize, dataoff, datasize } — dataoff ведёт к
//     dyld_chained_fixups_header (в __LINKEDIT).
//   dyld_chained_fixups_header {
//     fixups_version, starts_offset, imports_offset, symbols_offset,
//     imports_count, imports_format, symbols_format } — все u32.
//   dyld_chained_starts_in_image { seg_count; seg_info_offset[seg_count] } —
//     смещения (от header) на dyld_chained_starts_in_segment, 0 = пропуск.
//   dyld_chained_starts_in_segment {
//     size u32; page_size u16; pointer_format u16; segment_offset u64;
//     max_valid_pointer u32; page_count u16; page_start[page_count] u16 }.
//
// Цепочка каждой страницы — односвязный список: page_start[i] — смещение внутри
// страницы до первого звена (0xFFFF = страница без фиксапов). Каждое звено —
// 8-байтное слово по адресу базы_фиксапов; unpack_chain_entry даёт target и шаг
// next_delta (в байтах) до следующего звена. Нам нужны только rebase-цели —
// bind'ы логируем по ordinal и пропускаем.
void Macho::parse_chained_fixups(u64 cmd_off) {
    reloc_source_ += "LC_DYLD_CHAINED_FIXUPS (arm64e)";

    // linkedit_data_command: dataoff на +8, datasize на +12.
    if (cmd_off + 16 > v_.size) return;
    const u64 data_off  = v_.read_u32(cmd_off + 8);
    const u64 data_size = v_.read_u32(cmd_off + 12);
    if (data_off == 0 || data_off + 24 > v_.size) return;
    const u64 data_end = std::min<u64>(data_off + data_size, v_.size);

    // dyld_chained_fixups_header.
    const u32 version       = v_.read_u32(data_off + 0);
    const u32 starts_offset = v_.read_u32(data_off + 4);
    // imports_offset(+8), symbols_offset(+12) нам не нужны для rebase.
    const u32 imports_count  = v_.read_u32(data_off + 16);
    const u32 imports_format = v_.read_u32(data_off + 20);
    if (version != CHAINED_FIXUPS_VERSION) {
        // Незнакомая версия формата — не рискуем разбирать. reloc_ пуст: при
        // наличии LC_DYLD_INFO вызывающий откатится на rebase.
        reloc_source_ += " [версия " + std::to_string(version) + " не поддержана]";
        return;
    }
    // Логируем масштаб импортов (сами bind'ы для дампа не резолвим).
    (void)imports_count;
    (void)imports_format;

    // База образа — vmaddr самого нижнего сегмента (после сортировки — первый,
    // обычно __TEXT). От неё считаются target-смещения у *_OFFSET/USERLAND.
    const u64 image_base = segments_.empty() ? 0 : segments_.front().vaddr;

    // dyld_chained_starts_in_image.
    const u64 starts_img = data_off + starts_offset;
    if (starts_offset == 0 || starts_img + 4 > data_end) return;
    const u32 seg_count = v_.read_u32(starts_img);
    // Разумный потолок на число сегментов (защита от битого поля).
    if (seg_count == 0 || seg_count > 256) return;

    std::size_t bind_skipped = 0;

    for (u32 si = 0; si < seg_count; ++si) {
        const u64 off_pos = starts_img + 4 + static_cast<u64>(si) * 4;
        if (off_pos + 4 > data_end) break;
        const u32 seg_info_off = v_.read_u32(off_pos);
        if (seg_info_off == 0) continue;  // сегмент без фиксапов

        const u64 sis = starts_img + seg_info_off;  // dyld_chained_starts_in_segment
        if (sis + 22 > data_end) continue;

        const u16 page_size      = v_.read_u16(sis + 4);
        const u16 pointer_format = v_.read_u16(sis + 6);
        const u64 segment_offset = v_.read_u64(sis + 8);
        // max_valid_pointer на +16 (u32) — для userland не используется.
        const u16 page_count     = v_.read_u16(sis + 20);
        // page_count — u16 (макс 65535), верхнюю границу навязывает сам тип.
        if (page_size == 0 || page_count == 0) continue;

        // page_start[] идёт сразу за фиксированной частью (22 байта).
        const u64 page_start_base = sis + 22;

        for (u16 pi = 0; pi < page_count; ++pi) {
            const u64 ps_pos = page_start_base + static_cast<u64>(pi) * 2;
            if (ps_pos + 2 > data_end) break;
            const u16 page_start = v_.read_u16(ps_pos);
            constexpr u16 CHAIN_NONE = 0xFFFF;  // DYLD_CHAINED_PTR_START_NONE
            if (page_start == CHAIN_NONE) continue;

            // Начало цепочки: файловое смещение первого звена страницы.
            u64 chain_fo = segment_offset +
                           static_cast<u64>(pi) * page_size + page_start;

            // Идём по звеньям, пока next_delta != 0 и не вышли за буфер/страницу.
            // Ограничитель шагов на страницу — защита от циклической битой цепи.
            const u64 page_lo = segment_offset + static_cast<u64>(pi) * page_size;
            const u64 page_hi = page_lo + page_size;
            std::size_t guard = 0;
            const std::size_t guard_max =
                static_cast<std::size_t>(page_size / 4) + 4;

            while (true) {
                if (++guard > guard_max) break;               // защита от цикла
                if (chain_fo + 8 > v_.size) break;            // вышли за файл
                if (chain_fo < page_lo || chain_fo >= page_hi) break;  // вне страницы

                const u64 raw = v_.read_u64(chain_fo);
                const auto e = detail::unpack_chain_entry(raw, pointer_format, image_base);

                if (e.is_bind) {
                    // Импорт: для дампа IL2CPP не нужен — только считаем.
                    ++bind_skipped;
                } else if (e.target != 0) {
                    // Rebase: VA слота = где лежит звено (через va2fo обратно).
                    // chain_fo — файловое смещение; переведём в VA по сегменту.
                    // Слот заведомо в этом сегменте, но найдём VA обобщённо.
                    u64 slot_va = 0;
                    for (const auto& s : segments_) {
                        if (chain_fo >= s.offset && chain_fo < s.offset + s.filesz) {
                            slot_va = s.vaddr + (chain_fo - s.offset);
                            break;
                        }
                    }
                    if (slot_va != 0) reloc_[slot_va] = e.target;
                }

                if (e.next_delta == 0) break;  // конец цепочки
                chain_fo += e.next_delta;
            }
        }
    }

    if (bind_skipped) {
        reloc_source_ += " [+" + std::to_string(bind_skipped) + " bind пропущено]";
    }
}

// ── доступ по адресам (калька с Elf64) ──────────────────────────────────────

std::optional<u64> Macho::va2fo(u64 va) const noexcept {
    for (const auto& s : segments_) {
        if (va >= s.vaddr && va < s.vaddr + s.filesz) {
            return s.offset + (va - s.vaddr);
        }
    }
    return std::nullopt;
}

u64 Macho::raw_u64(u64 va) const noexcept {
    const auto fo = va2fo(va);
    if (!fo || *fo + 8 > v_.size) return 0;
    return v_.read_u64(*fo);
}

u64 Macho::ptr(u64 va) const noexcept {
    // Сначала карта rebase: там разрешённый указатель (в Mach-O он совпадает со
    // значением в файле, но карта отсеивает не-указательные слова). Иначе —
    // сырые байты (для не-релоцируемых полей, например count).
    const auto it = reloc_.find(va);
    if (it != reloc_.end()) return it->second;
    return raw_u64(va);
}

bool Macho::is_valid_va(u64 va) const noexcept {
    return va != 0 && va2fo(va).has_value();
}

std::vector<u64> Macho::reloc_values() const {
    // Значения из карты rebase, ведущие внутрь образа — кандидаты на «roots»
    // для поиска codeGenModules. Порядок по возрастанию vaddr (std::map),
    // дубликаты значений оставляем: их отсеет проверка формы у вызывающего.
    std::vector<u64> vals;
    vals.reserve(reloc_.size());
    for (const auto& kv : reloc_) {
        if (kv.second != 0 && va2fo(kv.second)) vals.push_back(kv.second);
    }
    return vals;
}

// ── проверка упаковки ────────────────────────────────────────────────────────

Macho::PackingResult Macho::packing_check(std::size_t sample) const {
    // У Mach-O с LC_DYLD_INFO значение по слоту rebase лежит в файле УЖЕ
    // разрешённым (не ноль) — в отличие от ELF-PIE, где там нули. Поэтому
    // «доля нулей» тут не диагностирует упаковку так же прямо. Проверяем иначе:
    // сколько значений в слотах rebase — правдоподобные указатели внутрь
    // образа. У нормального dylib это подавляющее большинство; если по слотам
    // мусор (образ зашифрован упаковщиком), доля валидных резко падает.
    if (reloc_.empty()) {
        return {false, 1.0, "нет таблицы rebase (chained fixups или none)"};
    }

    std::size_t valid = 0, total = 0, seen = 0;
    for (const auto& kv : reloc_) {
        if (seen++ >= sample) break;
        ++total;
        // Значение уже прочитано в parse_rebase; правдоподобный указатель ведёт
        // внутрь образа. 0 тоже допустим (нулевые указатели бывают), но их не
        // считаем «валидными» — важна доля именно ведущих в образ.
        if (kv.second != 0 && va2fo(kv.second)) ++valid;
    }
    if (total == 0) {
        return {false, 1.0, "нет читаемых слотов rebase"};
    }

    const double ratio = static_cast<double>(valid) / static_cast<double>(total);
    const int pct = static_cast<int>(ratio * 100.0 + 0.5);
    // zeros_ratio держим ради совместимости формы с ELF: тут это доля валидных
    // указателей. Порог с запасом: у нормального образа 90%+, у подменённого —
    // единицы процентов.
    if (ratio < 0.5) {
        return {true, ratio,
                "слоты rebase ведут в мусор (" + std::to_string(pct) +
                "% валидных указателей) — образ подменён упаковщиком"};
    }
    return {false, ratio,
            "слоты rebase указывают внутрь образа (" + std::to_string(pct) +
            "% валидных)"};
}

// ── поиск MetadataRegistration / fieldOffsets (калька с Elf64) ───────────────

std::optional<Macho::MetadataRegistrationCandidate>
Macho::find_metadata_registration(u64 typedef_count) const {
    // Якорь — typesCount: перебираем все места, где лежит число из диапазона
    // [typedef_count, typedef_count*8], и проверяем форму структуры вокруг.
    std::optional<MetadataRegistrationCandidate> best;
    const u64 lo = typedef_count;
    const u64 hi = typedef_count * 8;

    for (const auto& s : segments_) {
        const u64 end = std::min(s.offset + s.filesz, static_cast<u64>(v_.size));
        if (end < 8) continue;
        for (u64 pos = s.offset; pos + 8 <= end; pos += 8) {
            const u64 cnt = v_.read_u64(pos);
            if (cnt < lo || cnt > hi) continue;
            const u64 va = s.vaddr + (pos - s.offset);
            auto cand = probe_metadata_registration(va, cnt);
            if (cand && (!best || cand->score > best->score)) {
                best = cand;
            }
        }
    }
    return best;
}

std::optional<Macho::MetadataRegistrationCandidate>
Macho::probe_metadata_registration(u64 types_count_va, u64 cnt) const {
    // typesCount по смещению 0x30 => начало структуры на 0x30 раньше.
    const u64 base = types_count_va - 0x30;
    if (!is_valid_va(base)) return std::nullopt;
    const u64 types_ptr = ptr(types_count_va + 8);
    if (!is_valid_va(types_ptr)) return std::nullopt;

    int score = 0;
    // Форма: пары (count, ptr). Считаем, сколько пар выглядят корректно.
    for (int i = 0; i < 7; ++i) {
        const u64 c_va = base + static_cast<u64>(i) * 0x10;
        const u64 p_va = c_va + 8;
        const u64 c = reloc_.count(c_va) ? ptr(c_va) : raw_u64(c_va);
        const u64 p = ptr(p_va);
        if (c == 0 && p == 0) {
            score += 1;
            continue;
        }
        if (c > 0 && c < 10000000 && is_valid_va(p)) {
            score += 3;
        }
    }

    // Проверка содержимого: первые элементы types[] обязаны быть валидными
    // указателями на Il2CppType.
    int good_types = 0;
    const u64 lim = std::min<u64>(cnt, 64);
    for (u64 i = 0; i < lim; ++i) {
        const u64 tp = ptr(types_ptr + i * 8);
        if (is_valid_va(tp)) ++good_types;
    }
    if (good_types < 32) return std::nullopt;
    score += good_types;

    return MetadataRegistrationCandidate{base, types_ptr, cnt, score};
}

u64 Macho::find_field_offsets(u64 mr_base, u64 typedef_count) const {
    // fieldOffsets — массив указателей, по одному на тип, дальше в той же
    // структуре MetadataRegistration. Ищем пару (count ≈ typedef_count,
    // валидный указатель) с ДОПУСКОМ — как на ELF.
    const u64 tol = std::max<u64>(64, typedef_count / 200);
    u64 best = 0;
    bool have_best = false;
    u64 best_d = 0;

    for (int i = 4; i < 14; ++i) {
        const u64 c_va = mr_base + static_cast<u64>(i) * 0x10;
        const u64 p_va = c_va + 8;
        const u64 c = raw_u64(c_va);
        const u64 p = ptr(p_va);
        if (!is_valid_va(p)) continue;
        const u64 d = (c > typedef_count) ? (c - typedef_count)
                                          : (typedef_count - c);
        if (d <= tol && (!have_best || d < best_d)) {
            best_d = d;
            best = p;
            have_best = true;
        }
    }
    return best;
}

} // namespace oxdump::macho
