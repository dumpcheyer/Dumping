// oxdump/binary/mr_candidate.h — общий тип кандидата в Il2CppMetadataRegistration.
//
// Раньше жил как вложенный тип Elf64::MetadataRegistrationCandidate. С
// появлением второго формата (Mach-O) кандидат перестал быть «принадлежащим»
// одному парсеру: его отдаёт любой BinaryImage, а принимают pairing/tdlayout/
// model одинаково. Поэтому тип поднят в общий заголовок, а оба парсера лишь
// используют его.
#pragma once
#include "oxdump/common.h"

namespace oxdump::binary {

// Кандидат в Il2CppMetadataRegistration. score позволяет выбрать лучший из
// нескольких подходящих мест — форма структуры узнаётся не абсолютно.
struct MetadataRegistrationCandidate {
    u64 base;
    u64 types;
    u64 types_count;
    int score;
};

// Расширенные поля MetadataRegistration (v27+): счётчики и указатели таблиц,
// нужных сверх types[]/fieldOffsets. Читаются по фиксированным смещениям от
// base (BinaryImage::read_mr_extended). Тип живёт здесь (а не в model::), чтобы
// интерфейс BinaryImage не тянул зависимость на model. Поля с нулём означают
// «не прочитано / отсутствует».
struct MetadataRegistrationExtended {
    u64 generic_classes = 0;
    u64 generic_classes_count = 0;
    u64 generic_insts = 0;
    u64 generic_insts_count = 0;
    u64 method_specs = 0;
    u64 method_specs_count = 0;
};

} // namespace oxdump::binary
