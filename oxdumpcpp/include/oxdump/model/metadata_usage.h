// oxdump/model/metadata_usage.h — таблицы Il2CppMetadataUsage.
//
// ЧТО ЭТО. В IL2CPP каждый метод, который ссылается на метадату (тип, строковый
// литерал, другой метод, поле), делает это через per-method usage-таблицу.
// Пара «usage» говорит: «слот назначения D соответствует закодированному токену
// метадаты E». Старшие 3 бита E задают ВИД токена, младшие 29 — индекс в
// соответствующей таблице (typeInfo/typeRef/methodDef/fieldInfo/stringLiteral/
// methodRef). Это то самое связующее звено «метод X использует литерал Y»,
// которого не хватало деобфускатору.
//
// РАСКЛАДКА (v27+). Таблицы лежат В МЕТАДАТЕ двумя секциями:
//   metadataUsageLists — Il2CppMetadataUsageList[]: {start u32, count u32},
//                        по одной записи на метод (8 байт/запись);
//   metadataUsagePairs — Il2CppMetadataUsagePair[]: {destinationIndex u32,
//                        encodedSourceIndex u32} (8 байт/запись).
// В v29+ массив metadataUsages (сами слоты назначения) переехал в бинарник
// (MetadataRegistration.metadataUsages), но ПАРЫ, инициализирующие эти слоты,
// оставались в метадате — поэтому детектор ищет их именно там.
//
// НИ ОДНОГО ХАРДКОДА СМЕЩЕНИЙ. Поля заголовка под эти секции у разных сборок
// разъезжаются, а на обфусцированных сборках секций может не быть вовсе. Поэтому
// detect() опознаёт секции ПО СОДЕРЖИМОМУ (сигнатуре записей), а не по позиции в
// заголовке, и честно отдаёт usable()==false, если уверенно опознать не удалось.
#pragma once
#include "oxdump/common.h"
#include "oxdump/metadata/header.h"
#include "oxdump/metadata/layout.h"
#include <string>
#include <vector>

namespace oxdump::model {

// Вид закодированного токена: старшие 3 бита encodedSourceIndex.
enum class MetadataUsageKind : u8 {
    Invalid = 0,
    TypeInfo = 1,       // RuntimeTypeHandle / Il2CppClass*
    Il2CppType = 2,     // Il2CppType* (typeof, generic args)
    MethodDef = 3,      // RuntimeMethodHandle / MethodInfo*
    FieldInfo = 4,      // RuntimeFieldHandle / FieldInfo*
    StringLiteral = 5,  // строковый литерал
    MethodRef = 6,      // generic MethodInfo* (методоспек)
};

// Одно usage: вид, слот назначения в глобальном массиве metadataUsages и индекс
// в целевой таблице (typeInfo/typeRef/methodDef/fieldInfo/stringLiteral).
struct MetadataUsage {
    MetadataUsageKind kind = MetadataUsageKind::Invalid;
    u32 destination_index = 0;  // слот в глобальном metadataUsages
    u32 target_index = 0;       // индекс в таблице своего вида
};

// Список usage'ей одного метода: срез в массиве пар [start, start+count).
struct MethodUsages {
    u32 start = 0;
    u32 count = 0;
};

// Таблица usage'ей всего образа. Детектится по содержимому; при неудаче
// usable()==false и все запросы возвращают пусто — вызывающий обязан иметь
// запасной путь (см. analysis::build_hints — дизассемблер).
class MetadataUsageTable {
public:
    MetadataUsageTable() = default;

    // Пытается опознать и разобрать usage-таблицы в метадате. Возвращает
    // непригодную таблицу (usable()==false), если секции не опознаны уверенно.
    // md/L обязаны пережить только сам вызов: detect копирует всё, что нужно.
    static MetadataUsageTable detect(const metadata::Metadata& md,
                                     const metadata::Layout& L);

    bool usable() const noexcept { return usable_; }

    // Все usage'и метода method_index (индекс в таблице MethodDefinition).
    // Пусто, если метод не ссылается на метадату или таблица непригодна.
    std::vector<MetadataUsage> for_method(u32 method_index) const;

    // Одно usage по индексу назначения (для обратных поисков). Invalid, если
    // индекс вне диапазона или таблица непригодна.
    MetadataUsage at(u32 dest_index) const;

    // ── статистика для отчёта ────────────────────────────────────────────
    u32 method_count() const noexcept { return list_count_; }
    u32 pair_count() const noexcept { return pair_count_; }

    // Пояснение к детекту: какие секции опознаны (или почему не опознаны).
    // Для REPORT.txt.
    const std::string& report() const noexcept { return report_; }

    // Смещения найденных секций (0, если не найдены) — тоже для отчёта/тестов.
    u32 lists_offset() const noexcept { return lists_offset_; }
    u32 pairs_offset() const noexcept { return pairs_offset_; }

    // Число usage'ей заданного вида (для отчёта/деобфускации). Пусто при
    // непригодной таблице.
    u32 kind_count(MetadataUsageKind k) const noexcept;

private:
    bool usable_ = false;

    u32 lists_offset_ = 0;
    u32 list_count_ = 0;    // == method_count
    u32 pairs_offset_ = 0;
    u32 pair_count_ = 0;

    // Разобранные пары, отсортированные по destination_index. Держим копию:
    // после detect Metadata может уйти, а таблица нужна генераторам дольше.
    std::vector<MetadataUsage> pairs_;
    // Per-method срезы: индекс — method_index. Размер == list_count_.
    std::vector<MethodUsages> lists_;

    std::string report_;
};

// Декод старших 3 бит encodedSourceIndex в вид. Открыто: пригодится тестам.
inline MetadataUsageKind usage_kind(u32 encoded) noexcept {
    const u32 k = encoded >> 29;
    return (k >= 1 && k <= 6) ? static_cast<MetadataUsageKind>(k)
                              : MetadataUsageKind::Invalid;
}

// Младшие 29 бит — индекс в таблице своего вида.
inline u32 usage_index(u32 encoded) noexcept { return encoded & 0x1FFFFFFFu; }

} // namespace oxdump::model
