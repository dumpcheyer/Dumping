// oxdump/macho/macho.h — разбор Mach-O 64 (UnityFramework) и восстановление
// указателей.
//
// iOS-сборки Unity IL2CPP поставляют UnityFramework.framework/UnityFramework —
// 64-битный Mach-O dylib с теми же таблицами, что и libil2cpp.so: types[],
// MetadataRegistration, codeGenModules, fieldOffsets, указатели методов.
// Отличается только упаковка. Задача модуля та же, что у elf::Elf64: дать
// остальному дамперу читать указатели по виртуальным адресам так, как их увидит
// загрузчик.
//
// Природа релокаций у Mach-O:
//   • pre-iOS-15 (обычный случай) — таблица REBASE внутри LC_DYLD_INFO(_ONLY).
//     Это байткод, описывающий сегмент+смещение+итерацию. В отличие от ELF, в
//     файле по месту указателя лежит НЕ ноль, а уже разрешённое значение —
//     загрузчик лишь прибавляет slide. Поэтому карта релокаций хранит
//     vaddr → значение_в_файле, а ptr() отдаёт его как есть.
//   • iOS-15+/arm64e — LC_DYLD_CHAINED_FIXUPS (цепочки фиксапов). Разбирается
//     parse_chained_fixups(): заголовок dyld_chained_fixups_header ведёт к
//     dyld_chained_starts_in_image → dyld_chained_starts_in_segment → цепочкам
//     постраничных указателей. Каждый указатель — упакованное слово, чей формат
//     задаёт pointer_format сегмента; для дампа IL2CPP нам нужны только REBASE-
//     цели (bind'ы ссылаются на импорты — их пропускаем). Результат кладём в ту
//     же карту reloc_ (vaddr → разрешённый target VA), а reloc_source() ==
//     "LC_DYLD_CHAINED_FIXUPS (arm64e)". Если в образе есть и LC_DYLD_INFO, и
//     цепочки (переходные сборки) — предпочитаем цепочки.
//
// Публичная форма API калькирована с elf::Elf64 — Mach-O это drop-in замена для
// того же конвейера через общий интерфейс binary::BinaryImage.
#pragma once
#include "oxdump/common.h"
#include "oxdump/binary/image.h"
#include <optional>
#include <map>
#include <vector>
#include <string>

namespace oxdump::macho {

// ── форматы указателей chained-fixups (<mach-o/fixup-chains.h>) ───────────────
// Значение pointer_format в dyld_chained_starts_in_segment. Перечислены только
// используемые здесь + пара соседних для полноты. Обрабатываются: ARM64E(1),
// PTR_64(2), PTR_64_OFFSET(8), ARM64E_USERLAND24(12).
enum : u16 {
    DYLD_CHAINED_PTR_ARM64E            = 1,   // bity auth/bind, шаг ×4
    DYLD_CHAINED_PTR_64               = 2,   // target абсолютный, high8, шаг ×4
    DYLD_CHAINED_PTR_32               = 3,
    DYLD_CHAINED_PTR_32_CACHE         = 4,
    DYLD_CHAINED_PTR_32_FIRMWARE      = 5,
    DYLD_CHAINED_PTR_64_KERNEL_CACHE  = 6,
    DYLD_CHAINED_PTR_ARM64E_KERNEL    = 7,
    DYLD_CHAINED_PTR_64_OFFSET        = 8,   // как PTR_64, но target = offset от базы
    DYLD_CHAINED_PTR_ARM64E_USERLAND  = 9,
    DYLD_CHAINED_PTR_ARM64E_FIRMWARE  = 10,
    DYLD_CHAINED_PTR_X86_64_KERNEL_CACHE = 11,
    DYLD_CHAINED_PTR_ARM64E_USERLAND24 = 12, // как ARM64E, но ordinal 24-битный
};

// Форматы импортов (dyld_chained_fixups_header.imports_format). Нужны, только
// чтобы залогировать; сами импорты (bind'ы) для дампа не резолвим.
enum : u32 {
    DYLD_CHAINED_IMPORT           = 1,
    DYLD_CHAINED_IMPORT_ADDEND    = 2,
    DYLD_CHAINED_IMPORT_ADDEND64  = 3,
};

// Ключи подписи указателей arm64e (для auth-rebase; влияют только на отчёт,
// target остаётся смещением от базы образа).
namespace detail {

// Результат распаковки одного слова цепочки. target — уже готовый VA для
// rebase (у *_OFFSET/ARM64E прибавлена база образа). next_delta — шаг до
// следующего звена в БАЙТАХ (в файле хранится в единицах по 4 байта — здесь уже
// домножен). next_delta==0 означает конец цепочки. Для bind'ов is_bind=true и
// import_ordinal заполнен, target не осмыслен (импорт резолвит загрузчик).
struct ChainEntry {
    u64 target = 0;
    u32 next_delta = 0;
    bool is_bind = false;
    u32 import_ordinal = 0;
};

// Распаковать сырое 64-битное слово цепочки по формату pointer_format.
// image_base — vmaddr первого (обычно __TEXT) сегмента: для форматов, где target
// хранится как смещение от базы, он прибавляется. Чистая функция, тестируется
// по каждому формату отдельно. Неизвестный формат → {0,0,false,0}.
ChainEntry unpack_chain_entry(u64 raw, u16 pointer_format, u64 image_base) noexcept;

} // namespace detail

class Macho : public binary::BinaryImage {
public:
    // Сегмент, результат проверки упаковки и кандидат в MR — общие типы из
    // binary/*. Псевдонимы дают привычные имена Macho::Segment и т.п.
    using Segment = binary::Segment;
    using PackingResult = binary::PackingResult;
    using MetadataRegistrationCandidate = binary::MetadataRegistrationCandidate;

    // data — mmap-нутый файл. Копий не делаем, время жизни буфера на вызывающем.
    // Бросает BinaryError на невалидном Mach-O. Прозрачно разворачивает FAT:
    // выбирает срез arm64 (или x86_64) и разбирает его.
    explicit Macho(ByteView data);

    // ── доступ к разобранным данным ──────────────────────────────────────
    const std::vector<Segment>& segments() const noexcept override { return segments_; }
    u64 mem_end() const noexcept override { return mem_end_; }
    // cputype для отчёта: arm64=0x0100000C, x86_64=0x01000007.
    u32 cpu_type() const noexcept { return cpu_type_; }
    std::size_t reloc_count() const noexcept override { return reloc_.size(); }
    const std::string& reloc_source() const noexcept override { return reloc_source_; }

    // Все значения из карты rebase, ведущие внутрь образа (для codeGenModules).
    std::vector<u64> reloc_values() const override;

    // Виртуальный адрес -> смещение в файле, если попадает в загружаемый сегмент.
    std::optional<u64> va2fo(u64 va) const noexcept override;

    // Указатель по VA: сперва карта rebase, иначе сырые байты файла.
    u64 ptr(u64 va) const noexcept override;

    // Указывает ли VA внутрь загружаемого образа (ненулевой и отображаемый).
    bool is_valid_va(u64 va) const noexcept override;

    // Похоже ли, что сегменты подменены упаковщиком (см. .cpp).
    PackingResult packing_check(std::size_t sample = 3000) const override;

    // Поиск Il2CppMetadataRegistration по якорю typesCount.
    std::optional<MetadataRegistrationCandidate>
    find_metadata_registration(u64 typedef_count) const override;

    // Поиск массива fieldOffsets внутри MetadataRegistration.
    u64 find_field_offsets(u64 mr_base, u64 typedef_count) const override;

private:
    // Сырое чтение u64 по VA, без учёта релокаций — для полей count, которые в
    // файле лежат как есть.
    u64 raw_u64(u64 va) const noexcept;

    // Выбирает срез из FAT-образа и возвращает view на него; для обычного
    // Mach-O — исходный view без изменений. offset_ учитывается при чтении.
    ByteView select_slice(ByteView data);

    void parse_load_commands();
    void parse_rebase(u64 rebase_off, u64 rebase_size);

    // Разбор LC_DYLD_CHAINED_FIXUPS (iOS 15+/arm64e). cmd_off — смещение команды
    // в v_. Заполняет reloc_ REBASE-целями и выставляет reloc_source_. Bind'ы
    // (импорты) пропускает. Устойчив к битым смещениям/форматам: не бросает,
    // просто останавливает разбор битой цепочки/сегмента.
    void parse_chained_fixups(u64 cmd_off);

    // Проверка формы структуры вокруг предполагаемого typesCount.
    std::optional<MetadataRegistrationCandidate>
    probe_metadata_registration(u64 types_count_va, u64 cnt) const;

    ByteView v_;                 // view на выбранный Mach-O срез (для FAT — подрезан)
    u32 cpu_type_ = 0;
    std::vector<Segment> segments_;
    u64 mem_end_ = 0;
    // vaddr → разрешённый указатель. Для LC_DYLD_INFO это значение_в_файле по
    // слоту rebase; для LC_DYLD_CHAINED_FIXUPS — вычисленный target VA звена.
    std::map<u64, u64> reloc_;
    std::string reloc_source_;
};

} // namespace oxdump::macho
