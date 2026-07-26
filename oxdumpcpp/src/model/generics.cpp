// oxdump/model/generics.cpp — сборка таблицы generic-инстансов.
//
// Проходим MetadataRegistration.genericClasses[] и methodSpecs[]. Всё чтение
// указателей — через binary::BinaryImage::ptr() (в PIE настоящие значения там,
// в карте релокаций), счётчики (argc и т.п.) читаются тем же ptr() как сырые
// слова: они не релоцируются. Раскладка структур перечислена рядом с чтением;
// это v27+, совпадает с тем, что уже раскрывает model::type_name().
#include "oxdump/model/generics.h"
#include <algorithm>

namespace oxdump::model {

namespace {

// Прочитать один Il2CppGenericInst -> вектор индексов типов в types[].
//
//   Il2CppGenericInst { u32 type_argc; /*pad*/ Il2CppType** type_argv }
//   argc на +0x00 (сырое слово), argv на +0x08 (релоцируемый указатель).
//
// Каждый элемент argv — Il2CppType*; его индекс в types[] находим по карте
// va->idx (type_index). Если типа нет в карте (например generic-параметр T,
// у которого своя Il2CppType вне таблицы), кладём UINT32_MAX — вызывающий
// решит, что с ним делать (для имени такой аргумент всё равно печатается через
// type_name по самому указателю).
struct InstArgs {
    std::vector<u32> type_indices;   // индексы в types[] (или UINT32_MAX)
    std::vector<u64> type_vas;       // сами Il2CppType* (для построения имени)
};

InstArgs read_inst(const binary::BinaryImage& img, u64 inst_va,
                   const std::unordered_map<u64, u32>& type_index) {
    InstArgs out;
    if (!img.is_valid_va(inst_va)) return out;
    const u32 argc = static_cast<u32>(img.ptr(inst_va) & 0xFFFFFFFF);
    const u64 argv = img.ptr(inst_va + 8);
    // Разумный потолок: реальные инстансы имеют единицы аргументов; большое
    // число — признак того, что inst_va указывает не туда.
    if (argc == 0 || argc > 64 || !img.is_valid_va(argv)) return out;
    out.type_indices.reserve(argc);
    out.type_vas.reserve(argc);
    for (u32 k = 0; k < argc; ++k) {
        const u64 tva = img.ptr(argv + static_cast<u64>(k) * 8);
        out.type_vas.push_back(tva);
        const auto it = type_index.find(tva);
        out.type_indices.push_back(it != type_index.end() ? it->second
                                                          : 0xFFFFFFFFu);
    }
    return out;
}

} // namespace

GenericInstanceTable GenericInstanceTable::load(model::Model& m,
                                                const binary::BinaryImage& img) {
    GenericInstanceTable t;
    const MetadataRegistration& mr = m.mr();
    if (mr.generic_classes == 0 || mr.generic_classes_count == 0) return t;

    // Карта Il2CppType* -> индекс в types[]. Нужна, чтобы для каждого аргумента
    // и для базового типа инстанса получить индекс в таблице types[]. Строим
    // один раз; types_count здесь — верхняя граница из MR.
    std::unordered_map<u64, u32> type_index;
    const u64 tcount = mr.types_count;
    type_index.reserve(static_cast<std::size_t>(tcount));
    for (u64 i = 0; i < tcount; ++i) {
        const u64 va = m.type_va(static_cast<s32>(i));
        if (va) type_index.emplace(va, static_cast<u32>(i));
    }

    // ── methodSpecs[] ────────────────────────────────────────────────────────
    // Il2CppMethodSpec { s32 methodDefinitionIndex; s32 classIndexIndex;
    //                    s32 methodIndexIndex } — 12 байт на запись. Индексы
    // ведут в genericInsts[], -1 если не generic на этом уровне. Читаем сырыми
    // словами (не релоцируются).
    if (mr.method_specs && mr.method_specs_count &&
        mr.method_specs_count < 5000000) {
        t.method_specs_.reserve(static_cast<std::size_t>(mr.method_specs_count));
        for (u64 i = 0; i < mr.method_specs_count; ++i) {
            const u64 rec = mr.method_specs + i * 12;
            if (!img.va2fo(rec)) break;
            const u64 w0 = img.ptr(rec);            // methodDef | classIdx<<32
            const u64 w1 = img.ptr(rec + 8);        // methodIdx | (след. запись)
            MethodSpec ms;
            ms.method_def_index  = static_cast<s32>(w0 & 0xFFFFFFFF);
            ms.class_inst_index  = static_cast<s32>((w0 >> 32) & 0xFFFFFFFF);
            ms.method_inst_index = static_cast<s32>(w1 & 0xFFFFFFFF);
            t.method_specs_.push_back(ms);
        }
    }

    // ── genericClasses[] ─────────────────────────────────────────────────────
    // Массив указателей на Il2CppGenericClass.
    //   Il2CppGenericClass { Il2CppType* type; Il2CppGenericContext context }
    //   context: { Il2CppGenericInst* class_inst; Il2CppGenericInst* method_inst }
    // Значит: type* на +0x00, class_inst* на +0x08, method_inst* на +0x10.
    const u64 gcount = mr.generic_classes_count;
    t.items_.reserve(std::min<u64>(gcount, 200000));

    // Один и тот же Il2CppGenericClass встречается в genericClasses[] много раз
    // (на него ссылаются разные method-specs). VA инстанса уникален, поэтому
    // дедупим по нему: иначе таблица распухает дублями (на этой сборке ~40k
    // записей против ~26k уникальных), а instances_of() завышает счётчики.
    std::unordered_map<u64, char> seen_va;
    seen_va.reserve(std::min<u64>(gcount, 200000));

    for (u64 i = 0; i < gcount; ++i) {
        const u64 gc_va = img.ptr(mr.generic_classes + i * 8);
        if (!img.is_valid_va(gc_va)) continue;
        if (!seen_va.emplace(gc_va, 1).second) continue;   // уже видели этот VA

        const u64 base_type_va = img.ptr(gc_va);           // Il2CppType* (List<T>)
        if (!img.is_valid_va(base_type_va)) continue;
        const u64 class_inst = img.ptr(gc_va + 8);
        const u64 method_inst = img.ptr(gc_va + 16);

        GenericInstance gi;
        gi.va = gc_va;
        // base_type_idx — индекс в ТАБЛИЦЕ TYPEDEF определения (List`1), а не в
        // types[]: так его удобно сопоставлять с обходом типов в dump.cs и в
        // тесте. Базовый Il2CppType для generic-инстанса — это CLASS/VALUETYPE,
        // у которого data = индекс typedef. Достаём тег и, если это класс/
        // value-type, берём typedef-индекс; иначе оставляем «нет».
        gi.base_type_idx = 0xFFFFFFFFu;
        {
            const u8 tag = m.type_tag(base_type_va);
            if (tag == T_CLASS || tag == T_VALUETYPE) {
                const u64 tdi = m.type_data(base_type_va) & 0xFFFFFFFF;
                gi.base_type_idx = static_cast<u32>(tdi);
            }
        }

        // Аргументы class- и method-уровня.
        std::vector<u64> class_arg_vas, method_arg_vas;
        if (img.is_valid_va(class_inst)) {
            InstArgs a = read_inst(img, class_inst, type_index);
            gi.class_args = std::move(a.type_indices);
            class_arg_vas = std::move(a.type_vas);
        }
        if (img.is_valid_va(method_inst)) {
            InstArgs a = read_inst(img, method_inst, type_index);
            gi.method_args = std::move(a.type_indices);
            method_arg_vas = std::move(a.type_vas);
        }

        // Инстанс без аргументов вообще — не generic-класс, пропускаем: иначе
        // засорим таблицу мусором, если base указан неверно.
        if (class_arg_vas.empty() && method_arg_vas.empty()) continue;

        // ── человекочитаемое имя ───────────────────────────────────────────
        // База: type_name по base_type_va даёт уже обрезанное по арности имя
        // («List», «Dictionary»). Аргументы печатаем по их Il2CppType* — так
        // корректно раскрываются и примитивы, и вложенные generic-инстансы.
        std::string base = m.type_name(base_type_va);
        std::string joined;
        auto append = [&](const std::vector<u64>& vas) {
            for (u64 va : vas) {
                if (!joined.empty()) joined += ", ";
                joined += m.type_name(va);
            }
        };
        append(class_arg_vas);
        append(method_arg_vas);
        gi.display_name = base + "<" + joined + ">";

        t.items_.push_back(std::move(gi));
    }

    // Индексы. by_va — точный (VA уникален); by_base — многозначный (у одного
    // typedef много инстанциаций). Строим после наполнения items_, чтобы
    // индексы в items_ были стабильны.
    t.by_va_.reserve(t.items_.size());
    t.by_base_.reserve(t.items_.size());
    for (u32 k = 0; k < t.items_.size(); ++k) {
        const GenericInstance& gi = t.items_[k];
        t.by_va_.emplace(gi.va, k);
        if (gi.base_type_idx != 0xFFFFFFFFu)
            t.by_base_.emplace(gi.base_type_idx, k);
    }

    t.loaded_ = true;
    return t;
}

const GenericInstance* GenericInstanceTable::by_va(u64 va) const noexcept {
    const auto it = by_va_.find(va);
    if (it == by_va_.end()) return nullptr;
    return &items_[it->second];
}

std::vector<const GenericInstance*>
GenericInstanceTable::instances_of(u32 base_type_idx) const {
    std::vector<const GenericInstance*> out;
    auto range = by_base_.equal_range(base_type_idx);
    for (auto it = range.first; it != range.second; ++it)
        out.push_back(&items_[it->second]);
    return out;
}

} // namespace oxdump::model
