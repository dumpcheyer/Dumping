// oxdump/pe/pe.cpp — реализация разбора PE64 и релокаций.
//
// Форма конвейера скопирована с elf64.cpp — те же имена методов, та же
// защита от битых полей, тот же RVA-мир (аналог VA у ELF). Отличия помечены в
// комментариях там, где формат PE диктует иное поведение (релокации хранят
// готовое значение, а не addend; проверка упаковки работает по эвристике, а не
// по нулям в слотах).
#include "oxdump/pe/pe.h"
#include <algorithm>

namespace oxdump::pe {

namespace {
// Смещения и константы формата PE — держим локально, чтобы не тащить их в
// общий заголовок. Всё по спецификации PE/COFF.
constexpr std::size_t DOS_MAGIC_OFF   = 0x00;   // 'MZ'
constexpr std::size_t E_LFANEW_OFF    = 0x3C;   // u32: file offset of NT headers
constexpr u16 DOS_MAGIC               = 0x5A4D; // 'M','Z' little-endian
constexpr u32 NT_SIGNATURE            = 0x00004550; // 'P','E',0,0 little-endian
constexpr u16 OPT_MAGIC_PE32PLUS      = 0x020B;

// IMAGE_FILE_HEADER (COFF) — 20 байт, идёт сразу за сигнатурой NT.
constexpr std::size_t FH_MACHINE_OFF      = 0;   // u16
constexpr std::size_t FH_NUMSECTIONS_OFF  = 2;   // u16
constexpr std::size_t FH_OPTHDRSIZE_OFF   = 16;  // u16 SizeOfOptionalHeader
constexpr std::size_t FILE_HEADER_SIZE    = 20;

// IMAGE_OPTIONAL_HEADER64 — интересующие поля (смещения от начала opt header).
constexpr std::size_t OPT_MAGIC_OFF       = 0;   // u16
constexpr std::size_t OPT_IMAGEBASE_OFF   = 24;  // u64 ImageBase
constexpr std::size_t OPT_NUMDIRS_OFF     = 108; // u32 NumberOfRvaAndSizes
constexpr std::size_t OPT_DATADIR_OFF     = 112; // IMAGE_DATA_DIRECTORY[16]

// DataDirectory[5] = base relocation table.
constexpr u32 DIR_BASERELOC               = 5;

// IMAGE_SECTION_HEADER — 40 байт.
constexpr std::size_t SEC_NAME_OFF        = 0;   // 8 bytes
constexpr std::size_t SEC_VIRTSIZE_OFF    = 8;   // u32 VirtualSize
constexpr std::size_t SEC_VIRTADDR_OFF    = 12;  // u32 VirtualAddress (RVA)
constexpr std::size_t SEC_RAWSIZE_OFF     = 16;  // u32 SizeOfRawData
constexpr std::size_t SEC_RAWPTR_OFF      = 20;  // u32 PointerToRawData
constexpr std::size_t SEC_CHARS_OFF       = 36;  // u32 Characteristics
constexpr std::size_t SECTION_HEADER_SIZE = 40;

// Флаги секций (Characteristics).
constexpr u32 SCN_MEM_EXECUTE = 0x20000000;
constexpr u32 SCN_MEM_WRITE   = 0x80000000;

// Тип базовой релокации: DIR64 (64-битный указатель). Только он нам нужен.
constexpr u16 REL_BASED_DIR64 = 10;
} // namespace

PE::PE(ByteView data) : v_(data) {
    // Минимальная валидация: DOS-сигнатура 'MZ'. Дальше без неё читать нечего.
    if (!v_.valid() || v_.size < 0x40 ||
        v_.read_u16(DOS_MAGIC_OFF) != DOS_MAGIC) {
        throw BinaryError("не PE-файл (нет сигнатуры MZ)");
    }
    parse_headers();
}

void PE::parse_headers() {
    // e_lfanew -> file offset заголовков NT.
    const u64 nt = v_.read_u32(E_LFANEW_OFF);
    if (nt + 4 + FILE_HEADER_SIZE > v_.size) {
        throw BinaryError("битый e_lfanew: заголовок NT за границей файла");
    }
    if (v_.read_u32(nt) != NT_SIGNATURE) {
        throw BinaryError("нет сигнатуры PE\\0\\0");
    }

    // IMAGE_FILE_HEADER сразу за сигнатурой (4 байта).
    const u64 fh = nt + 4;
    machine_ = v_.read_u16(fh + FH_MACHINE_OFF);
    const u16 num_sections = v_.read_u16(fh + FH_NUMSECTIONS_OFF);
    const u16 opt_size     = v_.read_u16(fh + FH_OPTHDRSIZE_OFF);

    // IMAGE_OPTIONAL_HEADER64 сразу за FILE_HEADER.
    const u64 opt = fh + FILE_HEADER_SIZE;
    if (opt + OPT_DATADIR_OFF > v_.size) {
        throw BinaryError("optional header за границей файла");
    }
    if (v_.read_u16(opt + OPT_MAGIC_OFF) != OPT_MAGIC_PE32PLUS) {
        throw BinaryError("нужен 64-битный PE (PE32+)");
    }
    image_base_ = v_.read_u64(opt + OPT_IMAGEBASE_OFF);

    // DataDirectory[5] — таблица базовых релокаций. NumberOfRvaAndSizes может
    // быть меньше 16 у экзотических линкеров; проверяем и то, что каталог
    // физически влезает в optional header (opt_size).
    const u32 num_dirs = v_.read_u32(opt + OPT_NUMDIRS_OFF);
    u32 reloc_rva = 0, reloc_size = 0;
    if (num_dirs > DIR_BASERELOC) {
        const u64 dd = opt + OPT_DATADIR_OFF + DIR_BASERELOC * 8ull;
        if (dd + 8 <= v_.size &&
            OPT_DATADIR_OFF + (DIR_BASERELOC + 1) * 8ull <= opt_size) {
            reloc_rva  = v_.read_u32(dd);
            reloc_size = v_.read_u32(dd + 4);
        }
    }

    // Секции идут сразу за optional header (opt + opt_size).
    const u64 sec_base = opt + opt_size;
    for (u16 i = 0; i < num_sections; ++i) {
        const u64 o = sec_base + static_cast<u64>(i) * SECTION_HEADER_SIZE;
        if (o + SECTION_HEADER_SIZE > v_.size) break;

        const u32 virt_size = v_.read_u32(o + SEC_VIRTSIZE_OFF);
        const u32 virt_addr = v_.read_u32(o + SEC_VIRTADDR_OFF);
        const u32 raw_size  = v_.read_u32(o + SEC_RAWSIZE_OFF);
        const u32 raw_ptr   = v_.read_u32(o + SEC_RAWPTR_OFF);
        const u32 chars     = v_.read_u32(o + SEC_CHARS_OFF);

        // Имя — до 8 байт, обрезаем по нулю (Name не гарантирует терминатор).
        std::string name;
        for (std::size_t k = 0; k < 8; ++k) {
            const u8 c = v_.read_u8(o + SEC_NAME_OFF + k);
            if (c == 0) break;
            name += static_cast<char>(c);
        }

        segments_.push_back({static_cast<u64>(virt_addr),
                             static_cast<u64>(raw_ptr),
                             static_cast<u64>(raw_size),
                             static_cast<u64>(virt_size),
                             name});
        section_flags_.push_back(chars);

        // Конец образа считаем по VirtualSize: у .bss-подобных секций raw_size
        // равен нулю, но адресное пространство они занимают. Это верхняя
        // граница для проверки указателей.
        const u64 end = static_cast<u64>(virt_addr) + virt_size;
        if (end > mem_end_) mem_end_ = end;
    }

    if (segments_.empty()) {
        throw BinaryError("не найдено ни одной секции");
    }

    // Сортировка по vaddr (RVA) — va2fo и границы образа полагаются на
    // предсказуемый порядок. Держим section_flags_ синхронно с segments_.
    // Индексы сортируем вместе, чтобы флаги не разъехались с секциями.
    std::vector<std::size_t> idx(segments_.size());
    for (std::size_t i = 0; i < idx.size(); ++i) idx[i] = i;
    std::sort(idx.begin(), idx.end(), [&](std::size_t a, std::size_t b) {
        return segments_[a].vaddr < segments_[b].vaddr;
    });
    std::vector<Segment> seg_sorted;
    std::vector<u32> flags_sorted;
    seg_sorted.reserve(segments_.size());
    flags_sorted.reserve(section_flags_.size());
    for (std::size_t i : idx) {
        seg_sorted.push_back(segments_[i]);
        flags_sorted.push_back(section_flags_[i]);
    }
    segments_.swap(seg_sorted);
    section_flags_.swap(flags_sorted);

    parse_relocations(reloc_rva, reloc_size);
}

std::optional<u64> PE::va2fo(u64 va) const noexcept {
    // va — RVA. Отображается только в пределах сырых данных секции (filesz).
    for (const auto& s : segments_) {
        if (va >= s.vaddr && va < s.vaddr + s.filesz) {
            return s.offset + (va - s.vaddr);
        }
    }
    return std::nullopt;
}

u64 PE::raw_u64(u64 va) const noexcept {
    const auto fo = va2fo(va);
    if (!fo || *fo + 8 > v_.size) return 0;
    return v_.read_u64(*fo);
}

u64 PE::ptr(u64 va) const noexcept {
    // Сначала карта релокаций: для DIR64-слотов там уже лежит linker-relative
    // значение из файла. Иначе — сырые байты (для не-релоцируемых полей count).
    const auto it = reloc_.find(va);
    if (it != reloc_.end()) return it->second;
    return raw_u64(va);
}

bool PE::is_valid_va(u64 va) const noexcept {
    return va != 0 && va2fo(va).has_value();
}

std::vector<u64> PE::reloc_values() const {
    // Значения из карты релокаций, ведущие внутрь образа — кандидаты на «roots»
    // для поиска codeGenModules. Значения уже в RVA-мире (ImageBase вычтен при
    // разборе). Порядок по возрастанию RVA (std::map); дубликаты оставляем —
    // их отсеет проверка формы у вызывающего.
    std::vector<u64> vals;
    vals.reserve(reloc_.size());
    for (const auto& kv : reloc_) {
        if (kv.second != 0 && va2fo(kv.second)) vals.push_back(kv.second);
    }
    return vals;
}

void PE::parse_relocations(u32 reloc_rva, u32 reloc_size) {
    // Таблица .reloc — поток блоков IMAGE_BASE_RELOCATION:
    //   { u32 VirtualAddress; u32 SizeOfBlock; } header;
    //   u16 entries[(SizeOfBlock - 8) / 2];  // (type << 12) | offset_in_page
    // Нам нужны только записи типа 10 (DIR64): для каждой читаем u64 из файла
    // по target_rva = block.VirtualAddress + (entry & 0xFFF) и кладём в карту.
    reloc_source_ = "IMAGE_DIRECTORY_ENTRY_BASERELOC";
    if (reloc_rva == 0 || reloc_size == 0) {
        reloc_source_ = "не найдена (нет .reloc)";
        return;
    }
    const auto base_fo = va2fo(reloc_rva);
    if (!base_fo) {
        reloc_source_ = "не найдена (.reloc вне секций)";
        return;
    }

    const u64 start = *base_fo;
    const u64 end = std::min<u64>(start + reloc_size, v_.size);
    u64 o = start;
    std::size_t dir64 = 0, other = 0;
    while (o + 8 <= end) {
        const u32 block_rva = v_.read_u32(o);
        const u32 block_sz  = v_.read_u32(o + 4);
        // SizeOfBlock учитывает 8-байтный заголовок. Блок нулевой длины или
        // меньше заголовка означает конец/битую таблицу — выходим.
        if (block_sz < 8) break;
        const u64 entries_off = o + 8;
        const u64 entries_end = std::min<u64>(o + block_sz, end);
        for (u64 e = entries_off; e + 2 <= entries_end; e += 2) {
            const u16 entry = v_.read_u16(e);
            const u16 type = static_cast<u16>(entry >> 12);
            const u16 off  = static_cast<u16>(entry & 0x0FFF);
            if (type == REL_BASED_DIR64) {
                const u64 target_rva = static_cast<u64>(block_rva) + off;
                // Значение в файле по этому RVA — «предпочтительный» абсолютный
                // адрес (ImageBase + RVA цели). Приводим в RVA-мир, вычитая
                // ImageBase, чтобы ptr() отдавал валидный va в том же
                // пространстве, что и vaddr сегментов (контракт BinaryImage).
                // Если значение почему-то ниже ImageBase (внешняя ссылка,
                // импортируемый символ) — оставляем как есть: is_valid_va его
                // всё равно отсеет, а «занулять» осмысленное число хуже.
                const auto tfo = va2fo(target_rva);
                if (tfo && *tfo + 8 <= v_.size) {
                    const u64 abs_val = v_.read_u64(*tfo);
                    const u64 rva_val = (abs_val >= image_base_)
                                        ? abs_val - image_base_ : abs_val;
                    reloc_[target_rva] = rva_val;
                    ++dir64;
                }
            } else if (type != 0) {
                // type 0 = ABSOLUTE (паддинг, игнор). Остальные (HIGHLOW и т.п.)
                // считаем, но не применяем — в 64-битных образах их почти нет.
                ++other;
            }
        }
        o += block_sz;
    }

    if (reloc_.empty()) {
        reloc_source_ = "не найдена (нет DIR64-записей)";
        return;
    }
    reloc_source_ = "IMAGE_DIRECTORY_ENTRY_BASERELOC (" +
                    std::to_string(dir64) + " DIR64";
    if (other) reloc_source_ += ", " + std::to_string(other) + " прочих";
    reloc_source_ += ")";
}

PE::PackingResult PE::packing_check(std::size_t sample) const {
    // В PE признак упаковки не такой прямой, как в ELF (там слоты релокаций
    // обязаны быть нулями). Здесь значения предзаполнены. Поэтому смотрим на
    // структурные признаки упаковщика И на правдоподобие самих указателей.

    // (1) Структурный сигнал: .text помечена одновременно WRITE и EXECUTE —
    // классический признак распаковщика в рантайме. Аналогично — любая
    // executable-секция, которую сделали writable.
    for (std::size_t i = 0; i < segments_.size(); ++i) {
        const u32 f = section_flags_[i];
        if ((f & SCN_MEM_EXECUTE) && (f & SCN_MEM_WRITE)) {
            return {true, 0.0,
                    "секция '" + segments_[i].name +
                    "' одновременно исполняемая и записываемая — "
                    "признак распаковщика в рантайме"};
        }
    }

    // (2) Структурный сигнал: секция, чей VirtualSize КРАТНО больше
    // SizeOfRawData (сжатый образ, распаковываемый загрузчиком). BSS-подобные
    // (raw==0) — норма, их не считаем. Порог ×8 с запасом от легального .bss.
    for (std::size_t i = 0; i < segments_.size(); ++i) {
        const auto& s = segments_[i];
        if (s.filesz == 0) continue;  // .bss-подобная — норма
        if (s.memsz > s.filesz * 8 && s.memsz - s.filesz > (1u << 20)) {
            return {true, 0.0,
                    "секция '" + s.name + "' раздута в памяти (VirtualSize " +
                    thousands(s.memsz) + " ≫ SizeOfRawData " +
                    thousands(s.filesz) + ") — вероятно сжата упаковщиком"};
        }
    }

    // (3) Правдоподобие указателей: берём до sample слотов релокаций и
    // проверяем, что RVA-значение попадает внутрь образа [1, mem_end). У
    // честного образа так выглядит почти всё; у зашифрованного упаковщиком —
    // значения превращаются в мусор и в основном вылетают за границы.
    if (reloc_.empty()) {
        // Нет релокаций и структурных признаков — судить не по чему. Честно
        // сообщаем, что образ выглядит обычным (не блокируем конвейер).
        return {false, 1.0, "нет таблицы релокаций и явных признаков упаковки"};
    }

    std::size_t good = 0, total = 0, seen = 0;
    for (const auto& kv : reloc_) {
        if (seen++ >= sample) break;
        const u64 val = kv.second;
        ++total;
        // Плотный сигнал: значение — правдоподобный указатель внутрь образа.
        if (val != 0 && val < mem_end_) ++good;
    }
    if (total == 0) {
        return {false, 1.0, "нет читаемых слотов релокаций"};
    }

    const double ratio = static_cast<double>(good) / static_cast<double>(total);
    const int pct = static_cast<int>(ratio * 100.0 + 0.5);
    if (ratio < 0.5) {
        return {true, ratio,
                "слоты релокаций ведут в основном ВНЕ образа (" +
                std::to_string(pct) + "% годных) — значения подменены упаковщиком"};
    }
    return {false, ratio,
            "слоты релокаций правдоподобны (" + std::to_string(pct) +
            "% указывают внутрь образа)"};
}

std::optional<PE::MetadataRegistrationCandidate>
PE::find_metadata_registration(u64 typedef_count) const {
    // Якорь — typesCount: перебираем все места, где лежит число из диапазона
    // [typedef_count, typedef_count*8], и проверяем форму структуры вокруг.
    // Идентично логике ELF: один проход по данным всех секций.
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

std::optional<PE::MetadataRegistrationCandidate>
PE::probe_metadata_registration(u64 types_count_va, u64 cnt) const {
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

u64 PE::find_field_offsets(u64 mr_base, u64 typedef_count) const {
    // fieldOffsets — массив указателей, по одному на тип, дальше в той же
    // структуре MetadataRegistration. Ищем пару (count ≈ typedef_count,
    // валидный указатель) с допуском — как в ELF.
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

} // namespace oxdump::pe
