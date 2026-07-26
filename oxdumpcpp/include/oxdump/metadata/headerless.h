// oxdump/metadata/headerless.h — восстановление таблиц БЕЗ заголовка.
//
// Заголовок global-metadata.dat — это карта секций. Если его зашифруют так,
// что ключ не выводится (AES/RC4), карта потеряна. Но тело файла не шифруется
// (расшифровка на старте стоила бы игре секунд загрузки) — проверено
// побайтово: различается только заголовок. Значит карту можно построить
// заново по содержимому:
//   1) строковая секция — по якорю "<Module>";
//   2) таблица типов — по индексу "<Module>" как 32-битному значению в файле;
//   3) точная граница — по замощению таблицы полей;
//   4) поля/методы — по метаданным-токенам .NET (0x04.., 0x06..).
#pragma once
#include "oxdump/common.h"
#include <string>

namespace oxdump::metadata::headerless {

struct HeaderlessResult {
    u32 string_offset = 0;
    u32 string_size = 0;
    u32 typedef_offset = 0;
    u32 typedef_count = 0;
    u32 rec_size = 0;
    u32 field_offset = 0;
    u32 field_count = 0;
    u32 method_offset = 0;
    u32 method_count = 0;
    std::string report;
};

// Полное восстановление раскладки без заголовка. Кидает MetadataError, если
// не за что зацепиться (зашифровано и тело).
HeaderlessResult recover(ByteView data);

} // namespace oxdump::metadata::headerless
