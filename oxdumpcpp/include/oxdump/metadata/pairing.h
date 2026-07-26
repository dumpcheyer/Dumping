// oxdump/metadata/pairing.h — проверка, что метадата и бинарник из ОДНОЙ сборки.
//
// Самая частая ошибка: взять global-metadata.dat от одной версии игры и
// libil2cpp.so от другой (или другой архитектуры). Дамп при этом СОБИРАЕТСЯ и
// выглядит правдоподобно, но типы полей едут: индексы типов — это позиции в
// массиве types[], который лежит В БИНАРНИКЕ, а хранятся индексы в метадате.
//
// Инвариант связности ДВУСТОРОННИЙ:
//     typedef[i].byvalTypeIndex → types[idx] → Il2CppType.data.klassIndex == i
// Петля сходится только если обе стороны из одной сборки. Замерено: совпадение
// 100%, несовпадение <5% — разделение абсолютное, порог 80% с запасом.
#pragma once
#include "oxdump/common.h"
#include "oxdump/metadata/header.h"
#include "oxdump/metadata/layout.h"
#include "oxdump/binary/image.h"
#include <string>

namespace oxdump::metadata {

// Ниже этой доли считаем, что файлы из разных сборок.
constexpr double MATCH_THRESHOLD = 0.80;

// Сколько типов проверять. 300 хватает: разделение видно на первых десятках.
constexpr u32 PAIR_SAMPLE_SIZE = 300;

// Смещение byvalType по умолчанию, если раскладка не передана.
constexpr u32 TD_BYVAL_TYPE_DEFAULT = 0x08;

struct PairCheck {
    u64 hits = 0;
    u64 total = 0;
    u64 oob = 0;       // индексов вне диапазона types[]
    u32 typedef_count = 0;
    u64 types_count = 0;

    double ratio() const noexcept {
        return total ? static_cast<double>(hits) / total : 0.0;
    }
    bool matched() const noexcept { return ratio() >= MATCH_THRESHOLD; }
    std::string report() const;
    // Человеческое объяснение, ЧТО пошло не так и что делать.
    std::string error_text() const;
};

// Замыкает петлю typedef → types[] → klassIndex и считает попадания.
// bin — сырые байты бинарника; td_byval_off — смещение byvalType в записи.
// Принимает любой образ (ELF/Mach-O) через общий интерфейс BinaryImage.
PairCheck check_pair(const Metadata& md, const Layout& layout,
                     const binary::BinaryImage& img, ByteView bin,
                     const binary::MetadataRegistrationCandidate& mr,
                     u32 td_rec_size, u32 td_byval_off = TD_BYVAL_TYPE_DEFAULT);

} // namespace oxdump::metadata
