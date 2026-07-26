// oxdump/metadata/pairing.cpp — сверка пары файлов по замкнутой петле.
//
// Калька с pairing.py. Порог 80% взят с большим запасом: между совпадением
// (100%) и несовпадением (<5%) промежуточных случаев на реальных файлах нет.
#include "oxdump/metadata/pairing.h"

namespace oxdump::metadata {

std::string PairCheck::report() const {
    const int pct = static_cast<int>(ratio() * 100 + 0.5);
    std::string s = "сверка пары файлов: " + std::to_string(pct) + "% (" +
                    std::to_string(hits) + " из " + std::to_string(total) + ")\n";
    s += matched() ? "  метаданные и бинарник из одной сборки"
                   : "  ФАЙЛЫ ИЗ РАЗНЫХ СБОРОК";
    return s;
}

std::string PairCheck::error_text() const {
    const int pct = static_cast<int>(ratio() * 100 + 0.5);
    std::string s;
    s += "метаданные и бинарник — из РАЗНЫХ сборок игры.\n\n";
    s += "  проверка связности: " + std::to_string(pct) +
         "% (у совпадающей пары — 100%)\n";
    s += "  типов в метаданных : " + thousands(typedef_count) + "\n";
    s += "  типов в бинарнике  : " + thousands(types_count) + "\n\n";
    s += "  Дамп бы собрался, но типы полей были бы неверными:\n";
    s += "  вместо UnityEngine.Transform написалось бы что-то\n";
    s += "  постороннее. Смещения при этом выглядели бы правильно,\n";
    s += "  поэтому подмену легко не заметить.\n\n";
    s += "  Что делать: достать ОБА файла из одного APK.\n";
    s += "  Обе части обязаны быть от ОДНОЙ версии игры.";
    return s;
}

PairCheck check_pair(const Metadata& md, const Layout& layout,
                     const binary::BinaryImage& img, ByteView bin,
                     const binary::MetadataRegistrationCandidate& mr,
                     u32 td_rec_size, u32 td_byval_off) {
    PairCheck pc;
    pc.typedef_count = layout.typedef_count;
    pc.types_count = mr.types_count;

    const u64 types_va = mr.types;
    const u64 types_count = mr.types_count;
    const u32 tdc = layout.typedef_count;

    u64 hits = 0, miss = 0, oob = 0;
    const u32 step = std::max<u32>(1, tdc / PAIR_SAMPLE_SIZE);

    for (u32 i = 0; i < tdc; i += step) {
        const u32 rec = layout.typedef_offset + i * td_rec_size + td_byval_off;
        if (rec + 4 > md.size()) break;
        const u32 tidx = md.u32_at(rec);
        if (tidx >= types_count) { ++oob; continue; }
        const u64 tva = img.ptr(types_va + tidx * 8);
        const auto fo = img.va2fo(tva);
        if (!fo || *fo + 8 > bin.size) { ++oob; continue; }
        // Il2CppType: первые 8 байт — union data. Для класса/структуры там
        // klassIndex (нижние 32 бита) — индекс обратно в typedef.
        const u64 klass = bin.read_u64(*fo) & 0xFFFFFFFF;
        if (klass == i) ++hits;
        else ++miss;
    }

    pc.hits = hits;
    pc.total = hits + miss + oob;
    pc.oob = oob;
    return pc;
}

} // namespace oxdump::metadata
