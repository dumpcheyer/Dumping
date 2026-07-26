// oxdump/pe/pe.h — разбор PE64 (GameAssembly.dll) и восстановление указателей.
//
// Windows-сборки Unity IL2CPP поставляют GameAssembly.dll — 64-битную PE
// динамическую библиотеку с теми же таблицами, что и libil2cpp.so. Задача
// модуля та же, что у elf::Elf64 и macho::Macho: дать остальному дамперу читать
// указатели по адресам так, как их увидит загрузчик, и находить
// MetadataRegistration/fieldOffsets. PE реализует общий интерфейс
// binary::BinaryImage — pairing/tdlayout/model/codegen работают через него и
// ничего не знают о формате.
//
// Адресная модель: работаем в RVA-пространстве (адреса БЕЗ ImageBase), где
// segment.vaddr == RVA секции. Это согласуется с базовыми релокациями PE,
// которые задаются как RVA. Природа релокаций отличается от ELF: в файле по
// месту указателя лежит НЕ ноль, а «предпочтительный» абсолютный адрес
// (ImageBase + RVA цели). Мы приводим его в RVA-мир, вычитая ImageBase, чтобы
// значение из ptr() само было валидным va в том же пространстве, что и vaddr
// сегментов — как того требует контракт BinaryImage (ELF/Mach-O ведут себя так
// же: возвращаемый указатель лежит в vaddr-пространстве образа).
//
// Карта релокаций (.reloc, Directory[5]) хранит RVA → RVA_значение для
// 64-битных записей (IMAGE_REL_BASED_DIR64).
#pragma once
#include "oxdump/common.h"
#include "oxdump/binary/image.h"
#include <optional>
#include <map>
#include <vector>
#include <string>

namespace oxdump::pe {

class PE : public binary::BinaryImage {
public:
    // Сегмент, результат проверки упаковки и кандидат в MR — общие типы из
    // binary/*. Псевдонимы дают привычные имена PE::Segment и т.п.
    using Segment = binary::Segment;
    using PackingResult = binary::PackingResult;
    using MetadataRegistrationCandidate = binary::MetadataRegistrationCandidate;

    // data — mmap-нутый файл. Копий не делаем, время жизни буфера на вызывающем.
    // Бросает BinaryError на невалидном PE (нет MZ/PE-сигнатуры, не 64-бит).
    explicit PE(ByteView data);

    // ── доступ к разобранным данным ──────────────────────────────────────
    const std::vector<Segment>& segments() const noexcept override { return segments_; }
    u64 mem_end() const noexcept override { return mem_end_; }
    // machine для отчёта: AMD64=0x8664, ARM64=0xAA64.
    u16 machine() const noexcept { return machine_; }
    u64 image_base() const noexcept { return image_base_; }
    std::size_t reloc_count() const noexcept override { return reloc_.size(); }
    const std::string& reloc_source() const noexcept override { return reloc_source_; }

    // Все значения из карты релокаций, ведущие внутрь образа (для codeGenModules).
    std::vector<u64> reloc_values() const override;

    // RVA -> смещение в файле, если попадает в секцию с сырыми данными.
    std::optional<u64> va2fo(u64 va) const noexcept override;

    // Указатель по RVA: сперва карта релокаций (RVA-значение), иначе сырые байты.
    u64 ptr(u64 va) const noexcept override;

    // Указывает ли RVA внутрь образа (ненулевой и отображаемый).
    bool is_valid_va(u64 va) const noexcept override;

    // Похоже ли, что образ обработан упаковщиком (см. .cpp — эвристика).
    PackingResult packing_check(std::size_t sample = 3000) const override;

    // Поиск Il2CppMetadataRegistration по якорю typesCount.
    std::optional<MetadataRegistrationCandidate>
    find_metadata_registration(u64 typedef_count) const override;

    // Поиск массива fieldOffsets внутри MetadataRegistration.
    u64 find_field_offsets(u64 mr_base, u64 typedef_count) const override;

private:
    // Сырое чтение u64 по RVA, без учёта релокаций — для полей count, которые
    // в файле лежат как есть (релокациям не подлежат).
    u64 raw_u64(u64 va) const noexcept;

    void parse_headers();
    void parse_relocations(u32 reloc_rva, u32 reloc_size);

    // Проверка формы структуры вокруг предполагаемого typesCount.
    std::optional<MetadataRegistrationCandidate>
    probe_metadata_registration(u64 types_count_va, u64 cnt) const;

    ByteView v_;
    u16 machine_ = 0;
    u64 image_base_ = 0;
    std::vector<Segment> segments_;
    u64 mem_end_ = 0;
    // RVA → RVA_значение (для 64-битных релокаций DIR64; ImageBase уже вычтен).
    std::map<u64, u64> reloc_;
    std::string reloc_source_;

    // Флаги секций — для packing-эвристики (writable+executable .text,
    // раздутый VirtualSize и т.п.). Индекс совпадает с segments_.
    std::vector<u32> section_flags_;
};

} // namespace oxdump::pe
