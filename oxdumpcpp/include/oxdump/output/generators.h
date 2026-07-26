// oxdump/output/generators.h — генераторы выходных файлов.
//
// Каждый формат совместим с тем, что выдаёт Il2CppDumper — чтобы уже написанные
// инструменты и привычные грепы продолжали работать. Генераторы — свободные
// функции: у них нет своего состояния, всё нужное берётся из Model.
//
// Прогресс сообщается колбэком (cur, total). Колбэк зовётся не на каждой
// записи, а редко (примерно раз в 500-2000 типов): на 30k типов частый вызов
// заметно тормозил бы вывод.
#pragma once
#include "oxdump/common.h"
#include "oxdump/model/model.h"
#include "oxdump/model/generics.h"
#include "oxdump/metadata/header.h"
#include "oxdump/metadata/layout.h"
#include "oxdump/binary/image.h"
#include <string>
#include <functional>

namespace oxdump::output {

// Колбэк прогресса: текущий индекс и общее число. total==0 допустимо (тогда
// колбэк просто игнорируется вызывающим).
using progress_cb = std::function<void(u32 cur, u32 total)>;

// Сводка о разборе для REPORT.txt. Заполняется оркестратором/тестом по ходу
// работы; поля с настройкой по умолчанию просто не попадут в отчёт.
struct Summary {
    u32 typedef_count = 0;
    u64 bin_size = 0;        // размер libil2cpp.so в байтах (для отчёта)
    u64 reloc_count = 0;
    std::string reloc_source;
    // Заголовок не поддался расшифровке: раскладка восстановлена по
    // содержимому. Влияет на REPORT.txt (пояснение и оговорки о таблицах).
    bool headerless = false;
    bool packed = false;
    double packing_zeros = 1.0;
    std::string packing_why;
    double pair_ratio = 1.0;
    u64 methods_with_rva = 0;
    // Основная сборка (Assembly-CSharp): имя, число методов, адрес массива.
    std::string main_module;
    u32 main_module_methods = 0;
    u64 main_module_rva = 0;
};

// dump.cs — читаемое дерево классов с полями и методами. Если передан gt (не
// nullptr и loaded()), над каждым классом с generic-инстансами добавляется
// комментарий «// N instances: List<int>, List<string>, ...».
std::string gen_dump_cs(model::Model& m, const progress_cb& progress = {},
                        const model::GenericInstanceTable* gt = nullptr);

// il2cpp.h — C-структуры полей со смещениями, как у Il2CppDumper.
std::string gen_il2cpp_h(model::Model& m, const progress_cb& progress = {});

// script.json — соответствие адресов и имён, для IDA/Ghidra. Свой минимальный
// JSON-писатель, без внешних зависимостей.
std::string gen_script_json(model::Model& m, const progress_cb& progress = {});

// offsets.h — готовый заголовок для чита: TDI, type-index, поля целевых классов,
// плюс дружелюбные C++-структуры по классу со смещениями полей.
std::string gen_offsets_h(model::Model& m);

// offsets.cs — те же данные, но C#-константами (для тех, кто пишет чит/тулзу на
// C#: Mono.Cecil и т.п.). По классу — static class с TDI/TypeIdx и смещениями.
std::string gen_offsets_cs(model::Model& m);

// types.txt — плоский grep-friendly индекс: одна строка на класс с TDI, type-idx,
// числом полей и методов и полным именем. Отсортирован по полному имени.
std::string gen_types_txt(model::Model& m);

// generics.txt — одна строка на generic-инстанс (List<int>, Dictionary<...>),
// отсортировано по VA его Il2CppGenericClass. Формат:
//   List<int>                              @ 0x12345678
// Ограничено первыми 5000 записями (у крупной игры их 20-50k). Таблица строится
// из MetadataRegistration.genericClasses[]; если её не нашли — файл-заглушка.
std::string gen_generics_txt(model::Model& m,
                             const model::GenericInstanceTable& gt);

// REPORT.txt — что и как было определено. Первое, куда смотреть при подозрении.
std::string gen_report(metadata::Metadata& md, metadata::Layout& L,
                       binary::BinaryImage& b,
                       const model::MetadataRegistration& mr,
                       model::Model& m, const Summary& s);

// ida_script.py — самодостаточный скрипт для IDA Pro (7.x/8.x/9.x). Читает
// лежащий рядом script.json и переименовывает функции, ставит комментарии,
// заводит типы Il2CppObject. Тело скрипта — статический шаблон; из Model берём
// только счётчик методов и версию/дату для баннера.
std::string gen_ida_script(model::Model& m);

// ghidra_script.py — то же для Ghidra 11+ (Python 3 API). Читает script.json,
// переименовывает функции через FunctionManager, ставит plate-комментарии.
std::string gen_ghidra_script(model::Model& m);

// structs.h — обычный C-заголовок с определениями рантайм-структур IL2CPP
// (Il2CppObject/Il2CppClass/Il2CppString/Il2CppArray). Импортируется в
// IDA (Parse C header file) или Ghidra (Parse C source). Статический шаблон.
std::string gen_structs_h(model::Model& m);

} // namespace oxdump::output
