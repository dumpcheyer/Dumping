// oxdump/binary/image.h — абстрактный образ бинарника (ELF или Mach-O).
//
// Остальному дамперу безразлично, откуда взялись таблицы IL2CPP: из ELF
// (Android) или из Mach-O (iOS UnityFramework). Всё, что ему нужно, — читать
// указатели по виртуальным адресам так, как их увидит загрузчик, и находить
// MetadataRegistration/fieldOffsets. Этот интерфейс и есть общий контракт;
// Elf64 и Macho его реализуют, а pairing/tdlayout/model/codegen работают через
// ссылку на базу и ничего не знают о формате.
//
// Форма методов калькирована с исходного Elf64 один-в-один — Mach-O должен быть
// drop-in заменой в CLI.
#pragma once
#include "oxdump/common.h"
#include "oxdump/binary/mr_candidate.h"
#include <optional>
#include <vector>
#include <string>

namespace oxdump::binary {

// Один загружаемый сегмент. memsz хранится отдельно от filesz: разница — это
// та часть адресного пространства, которой нет в файле (.bss на ELF, «хвост»
// vmsize сверх filesize на Mach-O). name — имя сегмента (у ELF пустое, у
// Mach-O «__TEXT»/«__DATA» и т.п.) для отчёта.
struct Segment {
    u64 vaddr;
    u64 offset;
    u64 filesz;
    u64 memsz;
    std::string name;
};

// Результат проверки на упаковку. why — человекочитаемое пояснение для отчёта,
// чтобы не гадать, почему дампер решил так, а не иначе.
struct PackingResult {
    bool packed;
    double zeros_ratio;
    std::string why;
};

// Общий кандидат в MetadataRegistration — псевдоним на тип из mr_candidate.h,
// чтобы код, ссылающийся на BinaryImage::MetadataRegistrationCandidate, читался
// как раньше.
using MetadataRegistrationCandidate = binary::MetadataRegistrationCandidate;

// Абстрактный бинарный образ. Все методы — const и noexcept там, где это было у
// Elf64: интерфейс не должен провоцировать копий или бросков в горячем пути.
class BinaryImage {
public:
    virtual ~BinaryImage() = default;

    // ── доступ к разобранным данным ──────────────────────────────────────
    virtual const std::vector<Segment>& segments() const noexcept = 0;
    virtual u64 mem_end() const noexcept = 0;
    virtual std::size_t reloc_count() const noexcept = 0;
    virtual const std::string& reloc_source() const noexcept = 0;

    // Все значения релокаций (addend'ы), ведущие внутрь образа. Единственный
    // дешёвый список кандидатов на «roots» для поиска codeGenModules. У ELF —
    // addend'ы RELATIVE-релокаций, у Mach-O — значения из карты rebase.
    virtual std::vector<u64> reloc_values() const = 0;

    // Виртуальный адрес -> смещение в файле, если попадает в загружаемый сегмент.
    virtual std::optional<u64> va2fo(u64 va) const noexcept = 0;

    // Указатель по VA: сперва карта релокаций, иначе сырые байты файла.
    virtual u64 ptr(u64 va) const noexcept = 0;

    // Указывает ли VA внутрь загружаемого образа (ненулевой и отображаемый).
    virtual bool is_valid_va(u64 va) const noexcept = 0;

    // Похоже ли, что сегменты подменены упаковщиком.
    virtual PackingResult packing_check(std::size_t sample = 3000) const = 0;

    // Поиск Il2CppMetadataRegistration по якорю typesCount.
    virtual std::optional<MetadataRegistrationCandidate>
    find_metadata_registration(u64 typedef_count) const = 0;

    // Поиск массива fieldOffsets внутри MetadataRegistration.
    virtual u64 find_field_offsets(u64 mr_base, u64 typedef_count) const = 0;

    // Дочитать расширенные поля MetadataRegistration (генерики, methodSpecs) по
    // фиксированным смещениям от base. Раскладка v27+ (см. mr_candidate.h /
    // generics.h): пары (count, ptr) идут по 0x10; генерик-классы на +0x00,
    // генерик-инсты на +0x10, methodSpecs на +0x40. Реализация не виртуальная
    // и формат-независимая — читает через ptr()/is_valid_va(), поэтому работает
    // одинаково для ELF/Mach-O/PE и не требует правок в их парсерах. Счётчики
    // берём через ptr() тоже: они не релоцируются, и ptr() отдаст сырое слово.
    // Явно проверенные диапазоны отсекают мусор, если base указан неверно.
    MetadataRegistrationExtended read_mr_extended(u64 base) const {
        MetadataRegistrationExtended e;
        if (!is_valid_va(base)) return e;

        auto pair = [&](u64 off, u64& count, u64& ptr_out) {
            const u64 c = ptr(base + off);
            const u64 p = ptr(base + off + 8);
            // count разумно ограничен, ptr обязан вести внутрь образа.
            if (c > 0 && c < 20000000 && is_valid_va(p)) {
                count = c;
                ptr_out = p;
            }
        };

        pair(0x00, e.generic_classes_count, e.generic_classes);
        pair(0x10, e.generic_insts_count,   e.generic_insts);
        pair(0x40, e.method_specs_count,    e.method_specs);
        return e;
    }
};

} // namespace oxdump::binary
