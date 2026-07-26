// oxdump/model/model.h — модель IL2CPP поверх сырых таблиц.
//
// Здесь живёт вся логика «прочитать запись и получить осмысленное имя»:
// раскрытие вложенных классов, generic-параметры, примитивы, массивы. Всё
// смещения полей берутся из TDLayout (выведенной из данных), а не из констант —
// на новой версии Unity ничего править не придётся.
//
// Калька с model.py. Отличие только в типах: Metadata/Layout/Elf64 — это C++
// классы из metadata/* и elf/*, а MetadataRegistration собирается здесь из
// найденного кандидата + адреса fieldOffsets (в Python это был dict).
#pragma once
#include "oxdump/common.h"
#include "oxdump/metadata/header.h"
#include "oxdump/metadata/layout.h"
#include "oxdump/metadata/tdlayout.h"
#include "oxdump/binary/image.h"
#include "oxdump/model/metadata_usage.h"
#include <string>
#include <vector>
#include <unordered_map>

namespace oxdump::model {

// Il2CppTypeEnum: теги, требующие рекурсивного разбора. Отдельными именами —
// чтобы type_name() читался как в спецификации формата, а не набором магических
// чисел.
constexpr u8 T_VOID = 0x01;
constexpr u8 T_STRING = 0x0E;
constexpr u8 T_PTR = 0x0F, T_BYREF = 0x10;
constexpr u8 T_VALUETYPE = 0x11, T_CLASS = 0x12;
constexpr u8 T_VAR = 0x13, T_ARRAY = 0x14, T_GENERICINST = 0x15;
constexpr u8 T_OBJECT = 0x1C, T_SZARRAY = 0x1D, T_MVAR = 0x1E;

// Il2CppMetadataRegistration в той части, что нужна модели. В Python это был
// dict {types, types_count, field_offsets, base}; здесь — явная структура.
// field_offsets заполняется отдельно (find_field_offsets), поэтому у него
// значение по умолчанию 0: без него смещения полей выйдут нулевыми, но дамп
// соберётся.
struct MetadataRegistration {
    u64 base = 0;
    u64 types = 0;
    u64 types_count = 0;
    u64 field_offsets = 0;

    // Расширенные поля MetadataRegistration (v27+), нужные для перечисления
    // generic-инстансов. Заполняются отдельно (BinaryImage::read_mr_extended):
    // без них модель соберётся, просто GenericInstanceTable останется пустой.
    // genericClasses[] — все Il2CppGenericClass (конкретные List<int> и т.п.);
    // genericInsts[] — массивы аргументов; methodSpecs[] — Il2CppMethodSpec.
    u64 generic_classes = 0;
    u64 generic_classes_count = 0;
    u64 generic_insts = 0;
    u64 generic_insts_count = 0;
    u64 method_specs = 0;
    u64 method_specs_count = 0;

    MetadataRegistration() = default;
    // Удобный конструктор из найденного кандидата (ELF или Mach-O — тип общий).
    explicit MetadataRegistration(
        const binary::MetadataRegistrationCandidate& c, u64 fo = 0)
        : base(c.base), types(c.types), types_count(c.types_count),
          field_offsets(fo) {}
};

// Одно поле типа: имя, человекочитаемое имя типа, смещение в объекте, статик.
struct Field {
    std::string name;
    std::string type_name;
    u32 offset = 0;
    bool is_static = false;
};

// Один метод типа. param_start/param_count индексируют таблицу параметров;
// token нужен для поиска RVA; rva — уже разрешённый адрес кода (0, если метод
// не из основной сборки).
struct Method {
    std::string name;
    std::string ret_type;
    s32 param_start = 0;
    u16 param_count = 0;
    u32 token = 0;
    u64 rva = 0;
};

// Один параметр метода: имя и человекочитаемое имя типа.
struct Param {
    std::string name;
    std::string type_name;
};

class Model {
public:
    // Все ссылки должны пережить Model: копий не делаем. mr и td передаются по
    // значению — они маленькие и модель ими владеет. b — любой образ (ELF/Mach-O)
    // через общий интерфейс BinaryImage.
    Model(metadata::Metadata& md, metadata::Layout& L, binary::BinaryImage& b,
          MetadataRegistration mr, metadata::TDLayout td);

    // ── доступ к разобранным данным (нужен генераторам и отчёту) ──────────
    metadata::Metadata& md() noexcept { return md_; }
    metadata::Layout& layout() noexcept { return L_; }
    binary::BinaryImage& bin() noexcept { return b_; }
    const MetadataRegistration& mr() const noexcept { return mr_; }
    const metadata::TDLayout& td_layout() const noexcept { return TD_; }
    u64 types_va() const noexcept { return mr_.types; }
    u64 types_count() const noexcept { return mr_.types_count; }

    // ── usage-таблицы (метод → ссылки на метадату) ───────────────────────
    // Опознаются в конструкторе. Если не опознаны (usages().usable()==false),
    // связь метод→литерал/тип берётся запасным путём (дизассемблер в analysis).
    const MetadataUsageTable& usages() const noexcept { return usages_; }

    // ── строки ───────────────────────────────────────────────────────────
    std::string s(u32 idx) const { return md_.cstr(L_.string_offset, idx); }

    // ── записи typedef ─────────────────────────────────────────────────────
    // База записи typedef #i. Имя td() совпадает с моделью из ТЗ.
    u64 td(u32 i) const {
        return static_cast<u64>(L_.typedef_offset) +
               static_cast<u64>(i) * TD_.rec_size;
    }
    u32 td_u32(u32 i, s32 off) const {
        return md_.u32_at(static_cast<u32>(td(i)) + static_cast<u32>(off));
    }
    s32 td_s32(u32 i, s32 off) const {
        return md_.s32_at(static_cast<u32>(td(i)) + static_cast<u32>(off));
    }
    u16 td_u16(u32 i, s32 off) const {
        return md_.u16_at(static_cast<u32>(td(i)) + static_cast<u32>(off));
    }
    std::string td_name(u32 i) const { return s(td_u32(i, TD_.name)); }
    std::string td_namespace(u32 i) const { return s(td_u32(i, TD_.namespace_off)); }

    // ── Il2CppType ─────────────────────────────────────────────────────────
    // VA записи Il2CppType по индексу в массиве types[].
    u64 type_va(s32 idx) const;
    // Тег типа (Il2CppTypeEnum) из байта (data+8)>>16.
    u8 type_tag(u64 va) const;
    // Поле data: индекс typedef либо указатель (учитывает релокацию).
    u64 type_data(u64 va) const;
    // types[idx] -> индекс typedef (для CLASS/VALUETYPE).
    s64 typedef_index_of(s32 type_idx) const;

    // ── имена ──────────────────────────────────────────────────────────────
    // Полное имя типа: namespace + раскрытие вложенности + обрезка арности.
    // Кэшируется: full_name зовётся многократно из script.json.
    std::string full_name(s32 i);
    // Человекочитаемое имя по Il2CppType (рекурсивно по тегам).
    std::string type_name(u64 va, int depth = 0);

    // ── поля ───────────────────────────────────────────────────────────────
    u32 field_count_of(u32 i) const;
    u16 method_count_of(u32 i) const;
    std::vector<Field> fields_of(u32 i);

    // ── методы ─────────────────────────────────────────────────────────────
    std::vector<Method> methods_of(u32 i);
    std::vector<Param> params_of(s32 start, u16 count);
    u64 method_rva(u32 token) const;
    void attach_method_pointers(u64 va, u32 count) {
        method_pointers_ = va;
        method_pointers_count_ = count;
    }

    // ── таблица параметров (определяется отложенно) ─────────────────────────
    void detect_params();

private:
    std::vector<std::string> generic_args(u64 gclass_va, int depth);
    std::vector<u32> field_offsets(u32 i, u32 count) const;
    u32 field_count_fallback(u32 i) const;

    metadata::Metadata& md_;
    metadata::Layout& L_;
    binary::BinaryImage& b_;
    MetadataRegistration mr_;
    metadata::TDLayout TD_;
    u64 method_pointers_ = 0;
    u32 method_pointers_count_ = 0;
    std::unordered_map<s32, std::string> name_cache_;
    // Таблицы Il2CppMetadataUsage: опознаются один раз в конструкторе.
    MetadataUsageTable usages_;
};

} // namespace oxdump::model
