// oxdump/model/generics.h — таблица generic-инстансов IL2CPP.
//
// Определение вроде List<T> в таблице typedef одно. Но каждое КОНКРЕТНОЕ
// использование — List<int>, List<string>, Dictionary<string,Player> — порождает
// в рантайме структуру Il2CppGenericClass. Они лежат в
// MetadataRegistration.genericClasses[]. Сам дампер их раньше не перечислял:
// model::type_name() умеет раскрывать generic-инстанс по указателю, но полного
// списка «какие инстансы вообще есть в игре» не было, а значит в дампах стояло
// List<T> вместо реальных List<int> / List<string> / ...
//
// Здесь мы проходим genericClasses[] и methodSpecs[], для каждого инстанса
// строим человекочитаемое имя (через model::type_name) и индексируем по VA
// (для кросс-поиска из script.json/анализа) и по базовому typedef (чтобы у
// класса можно было перечислить все его инстанциации).
//
// Раскладка структур — v27+; смещения перечислены в generics.cpp рядом с
// чтением. Всё чтение указателей — через binary::BinaryImage::ptr(), как и в
// остальной модели: в PIE настоящие значения приходят из карты релокаций.
#pragma once
#include "oxdump/common.h"
#include "oxdump/model/model.h"
#include "oxdump/binary/image.h"
#include <string>
#include <vector>
#include <unordered_map>

namespace oxdump::model {

// Один generic-инстанс: где лежит его Il2CppGenericClass, какой typedef он
// инстанцирует, какими типами (индексы в types[]) и как он читается человеком.
struct GenericInstance {
    u64 va = 0;                       // VA структуры Il2CppGenericClass
    u32 base_type_idx = 0;            // индекс в types[] — определение «List<T>»
    std::vector<u32> class_args;      // индексы типов для class-level аргументов
    std::vector<u32> method_args;     // индексы типов для method-level (обычно пусто)
    std::string display_name;         // «List<int>», «Dictionary<string, Player>»
};

// Одна запись Il2CppMethodSpec: определение метода + индексы в genericInsts[]
// для class- и method-уровня (или -1, если не generic на этом уровне).
struct MethodSpec {
    s32 method_def_index = -1;
    s32 class_inst_index = -1;
    s32 method_inst_index = -1;
};

// Таблица всех generic-инстансов, найденных в образе. Строится один раз через
// load(); дальше — только чтение. Копий модели/образа не держит.
class GenericInstanceTable {
public:
    // Пройти MetadataRegistration.genericClasses[] и methodSpecs[] и собрать
    // таблицу. Если mr.generic_classes == 0 (поля не нашлись) — вернёт пустую
    // таблицу с loaded() == false. m передаётся по не-const ссылке: построение
    // имён идёт через model::type_name(), которая кэширует full_name.
    static GenericInstanceTable load(model::Model& m,
                                     const binary::BinaryImage& img);

    bool loaded() const noexcept { return loaded_; }
    const std::vector<GenericInstance>& all() const noexcept { return items_; }
    u32 count() const noexcept { return static_cast<u32>(items_.size()); }

    const std::vector<MethodSpec>& method_specs() const noexcept {
        return method_specs_;
    }

    // Найти инстанс по VA его Il2CppGenericClass (для кросс-поиска).
    const GenericInstance* by_va(u64 va) const noexcept;

    // Для базового typedef — все его конкретные инстанциации.
    std::vector<const GenericInstance*> instances_of(u32 base_type_idx) const;

private:
    bool loaded_ = false;
    std::vector<GenericInstance> items_;
    std::vector<MethodSpec> method_specs_;
    std::unordered_map<u64, u32> by_va_;
    std::unordered_multimap<u32, u32> by_base_;
};

} // namespace oxdump::model
