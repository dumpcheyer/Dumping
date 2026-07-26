// oxdump/elf/elf64.cpp — реализация разбора ELF64 и релокаций.
//
// Логика калькирована с эталонного питоновского дампера (binary.py). Все
// неочевидные пороги и «послабления» перенесены вместе с причинами, по
// которым они появились — иначе при первой же «чистке» кода они вернутся
// как баги на реальных библиотеках.
#include "oxdump/elf/elf64.h"
#include <algorithm>

namespace oxdump::elf {

namespace {
// Типы program headers и тегов PT_DYNAMIC — держим локально, чтобы не
// засорять общий заголовок константами, нужными только здесь.
constexpr u32 PT_LOAD = 1;
constexpr u32 PT_DYNAMIC = 2;
constexpr s64 DT_NULL = 0;
constexpr s64 DT_RELA = 7;
constexpr s64 DT_RELASZ = 8;
constexpr s64 DT_RELAENT = 9;

// Тип релокации «прибавить базу загрузки» — свой у каждой архитектуры.
// Жёсткая привязка к одному значению ломала разбор чужих сборок: релокаций
// находилось ноль, а без них указатели в данных читаются как нули.
std::optional<u32> r_relative_for(u16 machine) noexcept {
    switch (machine) {
        case 0xB7: return 1027;  // EM_AARCH64 -> R_AARCH64_RELATIVE
        case 0x3E: return 8;     // EM_X86_64  -> R_X86_64_RELATIVE
        case 0x28: return 23;    // EM_ARM     -> R_ARM_RELATIVE
        case 0x03: return 8;     // EM_386     -> R_386_RELATIVE
        default:   return std::nullopt;
    }
}
} // namespace

Elf64::Elf64(ByteView view) : v_(view) {
    // Минимальная валидация: заголовок ELF и класс ELFCLASS64. Дальше без
    // этого читать нечего.
    if (!v_.valid() || v_.size < 0x40 ||
        v_.data[0] != 0x7F || v_.data[1] != 'E' ||
        v_.data[2] != 'L' || v_.data[3] != 'F') {
        throw BinaryError("не ELF-файл");
    }
    if (v_.data[4] != 2) {
        throw BinaryError("нужен 64-битный ELF");
    }

    // e_machine на смещении 0x12 — по нему выбираем тип релокации.
    machine_ = v_.read_u16(0x12);
    r_relative_ = r_relative_for(machine_);

    parse_program_headers();
    parse_relocations();
}

void Elf64::parse_program_headers() {
    const u64 e_phoff = v_.read_u64(0x20);
    const u16 e_phentsize = v_.read_u16(0x36);
    const u16 e_phnum = v_.read_u16(0x38);

    for (u16 i = 0; i < e_phnum; ++i) {
        const u64 o = e_phoff + static_cast<u64>(i) * e_phentsize;
        if (o + 56 > v_.size) break;

        const u32 p_type = v_.read_u32(o);
        const u64 p_offset = v_.read_u64(o + 8);
        const u64 p_vaddr = v_.read_u64(o + 16);
        const u64 p_filesz = v_.read_u64(o + 32);
        const u64 p_memsz = v_.read_u64(o + 40);

        if (p_type == PT_LOAD) {
            // Имя у ELF-сегмента отсутствует — оставляем пустым (поле name есть
            // в общем binary::Segment ради Mach-O/PE, где сегменты именованы).
            segments_.push_back({p_vaddr, p_offset, p_filesz, p_memsz, {}});
            // Конец образа считаем по memsz, а не filesz: разница — .bss.
            // Указатели на .bss встречаются среди релокаций, и без учёта
            // memsz верхняя граница addend'ов оказывалась заниженной.
            if (p_vaddr + p_memsz > mem_end_) {
                mem_end_ = p_vaddr + p_memsz;
            }
        } else if (p_type == PT_DYNAMIC) {
            dyn_off_ = p_offset;
        }
    }

    // Сортировка по vaddr — va2fo полагается на предсказуемый порядок, да и
    // границы образа считать проще.
    std::sort(segments_.begin(), segments_.end(),
              [](const Segment& a, const Segment& b) {
                  return a.vaddr < b.vaddr;
              });
    if (segments_.empty()) {
        throw BinaryError("не найдено ни одного PT_LOAD сегмента");
    }
}

std::optional<u64> Elf64::va2fo(u64 va) const noexcept {
    for (const auto& s : segments_) {
        if (va >= s.vaddr && va < s.vaddr + s.filesz) {
            return s.offset + (va - s.vaddr);
        }
    }
    return std::nullopt;
}

u64 Elf64::raw_u64(u64 va) const noexcept {
    const auto fo = va2fo(va);
    if (!fo || *fo + 8 > v_.size) return 0;
    return v_.read_u64(*fo);
}

u64 Elf64::ptr(u64 va) const noexcept {
    // Сначала карта релокаций: в PIE именно там лежит настоящее значение.
    const auto it = reloc_.find(va);
    if (it != reloc_.end()) return it->second;
    // Иначе — сырые байты файла (для не-релоцируемых полей, например count).
    return raw_u64(va);
}

bool Elf64::is_valid_va(u64 va) const noexcept {
    return va != 0 && va2fo(va).has_value();
}

std::vector<u64> Elf64::reloc_values() const {
    // Значения (addend'ы) RELATIVE-релокаций, ведущие внутрь образа. Это
    // единственный дешёвый список кандидатов на «roots» для поиска
    // codeGenModules. Разбираем DT_RELA заново (а не берём карту reloc_):
    // здесь нужны сами addend'ы, а не пары offset→addend, и порядок важен —
    // как в исходном codegen.cpp.
    std::vector<u64> vals;
    if (!dyn_off_ || !r_relative_) return vals;

    u64 rela_va = 0, rela_sz = 0, rela_ent = 24;
    u64 o = *dyn_off_;
    while (o + 16 <= v_.size) {
        const s64 tag = v_.read_s64(o);
        const u64 val = v_.read_u64(o + 8);
        o += 16;
        if (tag == DT_NULL) break;
        else if (tag == DT_RELA)    rela_va = val;
        else if (tag == DT_RELASZ)  rela_sz = val;
        else if (tag == DT_RELAENT) rela_ent = val;
    }
    if (!rela_va || !rela_sz) return vals;
    const auto rela_fo = va2fo(rela_va);
    if (!rela_fo) return vals;
    if (rela_ent == 0) rela_ent = 24;

    const u64 cnt = rela_sz / rela_ent;
    vals.reserve(cnt);
    for (u64 k = 0; k < cnt; ++k) {
        const u64 base = *rela_fo + k * rela_ent;
        if (base + 24 > v_.size) break;
        const u64 r_info = v_.read_u64(base + 8);
        const s64 r_add = v_.read_s64(base + 16);
        if ((r_info & 0xFFFFFFFF) != *r_relative_) continue;
        if (r_add != 0 && va2fo(static_cast<u64>(r_add)))
            vals.push_back(static_cast<u64>(r_add));
    }
    return vals;
}

void Elf64::parse_relocations() {
    // Обычный путь — DT_RELA из PT_DYNAMIC. Packer'ы этот тег убирают, потому
    // что применяют релокации в своём загрузчике; таблица при этом остаётся
    // в файле, но указателя на неё нет. На такой случай — scan_relocations().
    u64 rela_va = 0, rela_sz = 0;
    u64 rela_ent = 24;  // размер Elf64_Rela по умолчанию

    if (dyn_off_) {
        u64 o = *dyn_off_;
        while (o + 16 <= v_.size) {
            const s64 tag = v_.read_s64(o);
            const u64 val = v_.read_u64(o + 8);
            o += 16;
            if (tag == DT_NULL) break;
            if (tag == DT_RELA)         rela_va = val;
            else if (tag == DT_RELASZ)  rela_sz = val;
            else if (tag == DT_RELAENT) rela_ent = val;
        }
    }

    reloc_source_ = "DT_RELA";
    if (rela_va == 0 || rela_sz == 0) {
        scan_relocations();
        return;
    }
    const auto rela_fo = va2fo(rela_va);
    if (!rela_fo) {
        scan_relocations();
        return;
    }
    if (rela_ent == 0) rela_ent = 24;  // защита от деления на ноль в битом теге

    const u64 cnt = rela_sz / rela_ent;
    for (u64 k = 0; k < cnt; ++k) {
        const u64 base = *rela_fo + k * rela_ent;
        if (base + 24 > v_.size) break;
        const u64 r_off  = v_.read_u64(base);
        const u64 r_info = v_.read_u64(base + 8);
        const s64 r_add  = v_.read_s64(base + 16);
        const u32 rtype  = static_cast<u32>(r_info & 0xFFFFFFFF);

        if (r_relative_) {
            if (rtype == *r_relative_) reloc_[r_off] = static_cast<u64>(r_add);
        } else {
            // Неизвестная архитектура: берём записи с addend'ом, ведущим
            // внутрь образа. RELATIVE-релокации выглядят именно так.
            if (r_add != 0 && va2fo(static_cast<u64>(r_add))) {
                reloc_[r_off] = static_cast<u64>(r_add);
            }
        }
    }

    // Тег был, но записей не набралось — таблица вырезана или подменена.
    if (reloc_.empty()) scan_relocations();
}

void Elf64::scan_relocations() {
    // Поиск таблицы RELA линейным сканом, когда DT_RELA недоступна.
    // Признаки записи Elf64_Rela: { r_offset(8), r_info(8), r_addend(8) }.
    // У RELATIVE-релокаций r_info равен константе архитектуры, r_offset
    // строго возрастает, addend ведёт внутрь образа. Ищем самую длинную
    // непрерывную цепочку по r_info и монотонности r_offset.
    if (!r_relative_ || segments_.empty()) {
        reloc_source_ = "не найдена";
        return;
    }

    u64 lo = segments_.front().vaddr;
    for (const auto& s : segments_) lo = std::min(lo, s.vaddr);
    // Верхняя граница — по memsz, а не filesz: разница .bss, куда указывает
    // часть addend'ов. С границей по filesz цепочка обрывалась на трети.
    u64 hi = mem_end_;
    for (const auto& s : segments_) hi = std::max(hi, s.vaddr + s.filesz);

    const u64 want = *r_relative_;
    const u64 n = v_.size;
    // Дальше первых 64 МБ таблицу не кладут — она в начале образа, сразу за
    // заголовками. Ограничение экономит время на 200-мегабайтном файле.
    const u64 limit = std::min<u64>(n, 64ull << 20);

    u64 best_start = 0, best_len = 0;
    u64 i = 0;
    while (i + 24 <= limit) {
        if (v_.read_u64(i + 8) != want) {
            i += 8;
            continue;
        }
        // Границу цепочки держим на ДВУХ признаках: тип релокации и строгий
        // рост r_offset. Проверку «addend внутри образа» сюда НЕ ставим:
        // часть addend'ов зашифрована (в референсе — 23 записи с общим
        // ciphertext-префиксом), и строгая проверка рвала цепочку на 740k
        // из 1.23M. Негодные addend'ы отсеиваются ниже, поштучно.
        u64 j = i, cnt = 0;
        s64 prev = -1;  // r_offset строго растёт; -1 гарантированно меньше 0
        while (j + 24 <= n) {
            const u64 r_off  = v_.read_u64(j);
            const u64 r_inf  = v_.read_u64(j + 8);
            if (r_inf != want || static_cast<s64>(r_off) <= prev) break;
            prev = static_cast<s64>(r_off);
            ++cnt;
            j += 24;
        }
        if (cnt > best_len) { best_len = cnt; best_start = i; }
        i = std::max<u64>(j, i + 8);
    }

    // Короткая цепочка — совпадение, а не таблица. У настоящей их сотни тысяч.
    if (best_len < 1000) {
        reloc_source_ = "не найдена";
        return;
    }

    // Записи с негодным addend'ом пропускаем: зашифрованное значение всё
    // равно не восстановить, а класть мусор хуже, чем не класть ничего —
    // тогда ptr() прочитает значение прямо из файла.
    u64 taken = 0, skipped = 0;
    for (u64 k = 0; k < best_len; ++k) {
        const u64 base = best_start + k * 24;
        const s64 r_add = v_.read_s64(base + 16);
        if (!(static_cast<s64>(lo) <= r_add && r_add < static_cast<s64>(hi))) {
            ++skipped;
            continue;
        }
        reloc_[v_.read_u64(base)] = static_cast<u64>(r_add);
        ++taken;
    }
    reloc_source_ = "scanned @" + hex(best_start) + " (" +
                    std::to_string(taken) + " records";
    if (skipped) reloc_source_ += ", " + std::to_string(skipped) + " skipped";
    reloc_source_ += ")";
}

Elf64::PackingResult Elf64::packing_check(std::size_t sample) const {
    // Признак упаковки прямой и не зависит от версии игры. В PIE там, где в
    // памяти будет указатель, в ФАЙЛЕ лежат нули — значение проставит
    // загрузчик по релокациям. Значит по любому адресу из таблицы в файле
    // обязан быть ноль. Если вместо нулей плотные данные — сегмент подменён.
    if (reloc_.empty()) {
        return {false, 1.0, "no reloc table"};
    }

    std::size_t zeros = 0, total = 0, seen = 0;
    for (const auto& kv : reloc_) {
        if (seen++ >= sample) break;
        const u64 va = kv.first;
        const auto fo = va2fo(va);
        if (!fo || *fo + 8 > v_.size) continue;
        ++total;
        if (v_.read_u64(*fo) == 0) ++zeros;
    }
    if (total == 0) {
        return {false, 1.0, "нет читаемых слотов релокаций"};
    }

    const double ratio = static_cast<double>(zeros) / static_cast<double>(total);
    const int pct = static_cast<int>(ratio * 100.0 + 0.5);
    // Порог с большим запасом: реальные значения — 100% против 0%.
    if (ratio < 0.5) {
        return {true, ratio,
                "слоты релокаций заняты данными (" + std::to_string(pct) +
                "% нулей вместо 100%) — сегмент подменён упаковщиком"};
    }
    return {false, ratio,
            "слоты релокаций чисты (" + std::to_string(pct) + "% нулей)"};
}

std::optional<Elf64::MetadataRegistrationCandidate>
Elf64::find_metadata_registration(u64 typedef_count) const {
    // Якорь — typesCount: перебираем все места, где лежит число из диапазона
    // [typedef_count, typedef_count*8], и проверяем форму структуры вокруг.
    // Один проход по данным вместо скана на каждое возможное значение.
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

std::optional<Elf64::MetadataRegistrationCandidate>
Elf64::probe_metadata_registration(u64 types_count_va, u64 cnt) const {
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
        // count берём сырым (релокациям не подлежит), кроме случая, когда он
        // почему-то оказался в карте релокаций — тогда доверяем ей.
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

u64 Elf64::find_field_offsets(u64 mr_base, u64 typedef_count) const {
    // fieldOffsets — массив указателей, по одному на тип, дальше в той же
    // структуре MetadataRegistration. Ищем пару (count ≈ typedef_count,
    // валидный указатель). Сравнение с ДОПУСКОМ: без заголовка число типов
    // определяется приблизительно, точное равенство не срабатывало.
    const u64 tol = std::max<u64>(64, typedef_count / 200);  // 0.5% или 64
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

} // namespace oxdump::elf
