// oxdump/elf/elf64.h — разбор ELF64 и восстановление релокаций.
//
// Модуль решает одну задачу: дать остальному дамперу читать указатели по
// виртуальным адресам так, как их увидит загрузчик. Библиотека собрана как
// PIE — в файле на месте указателей нули, реальные значения проставляет
// загрузчик из таблицы RELA. Поэтому ptr() читает не файл, а разобранную
// карту релокаций; без неё все адреса в данных были бы нулями.
//
// Секции и символы намеренно НЕ разбираются: у реальных IL2CPP-библиотек их
// обычно вырезают. Всё, что нужно, берётся из program headers и PT_DYNAMIC.
//
// Elf64 реализует общий интерфейс binary::BinaryImage — благодаря этому CLI и
// конвейер работают одинаково с ELF (Android) и Mach-O (iOS). Специфичные для
// ELF геттеры (machine, r_relative, dynamic_offset) остаются на конкретном
// классе: они нужны только внутри elf/*.
#pragma once
#include "oxdump/common.h"
#include "oxdump/binary/image.h"
#include <optional>
#include <map>
#include <vector>
#include <string>

namespace oxdump::elf {

class Elf64 : public binary::BinaryImage {
public:
    // Сегмент и кандидат в MR теперь общие для всех форматов. Псевдонимы
    // сохраняют прежние имена Elf64::Segment / Elf64::MetadataRegistrationCandidate,
    // чтобы существующий код не переписывать.
    using Segment = binary::Segment;
    using PackingResult = binary::PackingResult;
    using MetadataRegistrationCandidate = binary::MetadataRegistrationCandidate;

    // view — mmap-нутый файл. Копий не делаем, время жизни буфера на вызывающем.
    explicit Elf64(ByteView view);

    // ── доступ к разобранным данным ──────────────────────────────────────
    u16 machine() const noexcept { return machine_; }
    const std::vector<Segment>& segments() const noexcept override { return segments_; }
    u64 mem_end() const noexcept override { return mem_end_; }
    std::optional<u64> dynamic_offset() const noexcept { return dyn_off_; }
    std::optional<u32> r_relative() const noexcept { return r_relative_; }
    std::size_t reloc_count() const noexcept override { return reloc_.size(); }
    const std::string& reloc_source() const noexcept override { return reloc_source_; }

    // Все addend'ы RELATIVE-релокаций, ведущие внутрь образа (для codeGenModules).
    std::vector<u64> reloc_values() const override;

    // Виртуальный адрес -> смещение в файле, если попадает в PT_LOAD.
    std::optional<u64> va2fo(u64 va) const noexcept override;

    // Указатель по VA: сперва карта релокаций, иначе сырые байты файла.
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
    // Сырое чтение u64 по VA, без учёта релокаций — нужно для полей count,
    // которые в файле лежат как есть (релокациям не подлежат).
    u64 raw_u64(u64 va) const noexcept;

    void parse_program_headers();
    void parse_relocations();
    void scan_relocations();
    // Проверка формы структуры вокруг предполагаемого typesCount.
    std::optional<MetadataRegistrationCandidate>
    probe_metadata_registration(u64 types_count_va, u64 cnt) const;

    ByteView v_;
    u16 machine_ = 0;
    std::optional<u32> r_relative_;
    std::vector<Segment> segments_;
    std::optional<u64> dyn_off_;
    u64 mem_end_ = 0;
    std::map<u64, u64> reloc_;
    std::string reloc_source_;
};

} // namespace oxdump::elf
