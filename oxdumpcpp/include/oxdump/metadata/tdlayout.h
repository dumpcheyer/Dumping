// oxdump/metadata/tdlayout.h — раскладка Il2CppTypeDefinition ИЗ ДАННЫХ.
//
// Размер записи и смещения полей внутри Il2CppTypeDefinition зависят от версии
// Unity. Захардкоженная карта под v39 сломается на v40+ ТИХО: имена классов
// продолжат читаться (они в начале записи), а поля и методы поедут. Здесь всё
// выводится из данных по инвариантам, не зависящим от версии формата:
//   - размер записи: секция типов кратна ему, по началу каждой читается имя;
//   - byvalType: замкнутая петля typedef→types[]→klassIndex==i;
//   - пары (start,count) ЗАМОЩАЮТ свои таблицы (start[i]+count[i]==start[i+1]);
//   - каждая пара привязана к физической секции нужного размера.
#pragma once
#include "oxdump/common.h"
#include "oxdump/metadata/header.h"
#include "oxdump/metadata/layout.h"
#include "oxdump/binary/image.h"
#include <string>
#include <vector>

namespace oxdump::metadata {

// Правдоподобные размеры записи. Крайние значения с запасом: у v24 запись
// меньше, у гипотетических будущих версий — больше.
constexpr u32 TD_REC_MIN = 60;
constexpr u32 TD_REC_MAX = 160;

// Доля стыков, при которой считаем замощение состоявшимся. На реальных данных
// верная пара даёт 100.00%, ложные — заметно меньше.
constexpr double TD_TILE_THRESHOLD = 0.95;

// -1 означает «поле не определено» (аналог None в Python).
struct TDLayout {
    u32 rec_size = 0;
    s32 name = 0x00;         // индекс имени — всегда первое поле
    s32 namespace_off = 0x04;
    s32 byval_type = -1;
    s32 declaring = -1;
    s32 parent = -1;
    s32 flags = -1;
    s32 field_start = -1;
    s32 field_count = -1;
    s32 method_start = -1;
    s32 method_count = -1;
    bool derived = false;    // выведено из данных или взяты значения по умолчанию
    std::vector<std::string> notes;

    std::string report() const;
};

// Полное определение раскладки. mr — найденный Il2CppMetadataRegistration;
// bin — сырые байты бинарника (нужны для чтения Il2CppType). При неудаче
// отдельных шагов подставляет значения из fallback (может быть null) и
// помечает это в notes. Принимает любой образ (ELF/Mach-O) через BinaryImage.
TDLayout detect(const Metadata& md, const Layout& layout,
                const binary::BinaryImage& img, ByteView bin,
                const binary::MetadataRegistrationCandidate& mr,
                const TDLayout* fallback);

// Раскладка, проверенная на v39. Запасной вариант и точка сверки для
// автоопределения.
TDLayout default_v39();

} // namespace oxdump::metadata
