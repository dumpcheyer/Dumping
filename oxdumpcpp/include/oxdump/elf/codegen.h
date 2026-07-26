// oxdump/elf/codegen.h — поиск таблицы адресов методов внутри libil2cpp.
//
// codeGenModules — массив указателей на Il2CppCodeGenModule; у каждого
// первое поле — указатель на строку с именем ("Assembly-CSharp.dll" и т.д.),
// следующее u32 — число методов, за ним — сам массив адресов.
//
// Модуль находится через таблицу релокаций: те addend'ы, что ведут внутрь
// образа, — единственный дешёвый список кандидатов на roots. Правильный
// определяется по имени: если по адресу читается "*.dll", это модуль.
#pragma once
#include "oxdump/common.h"
#include "oxdump/binary/image.h"
#include <string>
#include <vector>

namespace oxdump::elf {

struct MethodPointers {
    u64 arr = 0;          // VA массива указателей методов
    u32 count = 0;         // число методов
    std::string module;    // имя основной сборки (обычно Assembly-CSharp.dll)
};

// Возвращает массив методов Assembly-CSharp.dll или пустой результат,
// если не нашли. image_count — сколько сборок примерно ожидаем (для
// раннего выхода из проверки массива модулей). Работает с любым образом
// (ELF/Mach-O) через общий интерфейс BinaryImage: список «roots» берётся из
// img.reloc_values() одинаково для обоих форматов.
MethodPointers find_method_pointers(ByteView bin, const binary::BinaryImage& img,
                                    u32 image_count);

} // namespace oxdump::elf
