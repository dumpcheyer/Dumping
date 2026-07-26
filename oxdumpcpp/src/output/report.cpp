// oxdump/output/report.cpp — генерация REPORT.txt.
//
// Калька с dumper.py::_report. Первое, куда смотреть, если дамп выглядит
// подозрительно: здесь видно, как определился ключ, раскладка секций, раскладка
// записи типа, и прошли ли контрольные классы. Формат держим совместимым с
// эталоном — под него заточены глаза и грепы.
#include "oxdump/output/generators.h"
#include <sstream>

namespace oxdump::output {

namespace {

// Отступ каждой строки многострочного блока на два пробела — как ".replace(
// '\n', '\n  ')" в Python. Первую строку вызывающий уже отступил.
std::string indent2(const std::string& s) {
    std::string out;
    out.reserve(s.size() + 16);
    for (char c : s) {
        out += c;
        if (c == '\n') out += "  ";
    }
    return out;
}

} // namespace

std::string gen_report(metadata::Metadata& md, metadata::Layout& L,
                       binary::BinaryImage& b,
                       const model::MetadataRegistration& mr,
                       model::Model& m, const Summary& s) {
    std::string out;
    out.reserve(8 * 1024);

    out += "OxideDumper — отчёт о разборе\n";
    out += std::string(62, '=') + "\n\n";

    // Headerless-режим: заголовок не расшифровался, карта секций собрана по
    // содержимому. Предупреждаем сразу — часть вторичных таблиц отсутствует.
    if (s.headerless) {
        out += "РЕЖИМ БЕЗ ЗАГОЛОВКА\n";
        out += "  Заголовок метаданных не поддался расшифровке (вероятно\n";
        out += "  AES/RC4). Карта секций восстановлена сканированием\n";
        out += "  содержимого файла: строки, типы, поля и методы найдены по\n";
        out += "  якорям и метаданным-токенам .NET. Основной дамп (dump.cs,\n";
        out += "  il2cpp.h, offsets.h) полноценен.\n";
        out += "  ОГОВОРКА: часть вторичных таблиц в этом режиме не\n";
        out += "  восстанавливается — список образов (сборок) и имена\n";
        out += "  параметров методов. Параметры показываются сырыми индексами.\n\n";
    }

    out += "ВХОДНЫЕ ДАННЫЕ\n";
    out += "  версия метаданных : " + std::to_string(md.version()) + "\n";
    out += "  размер метаданных : " + thousands(md.size()) + " байт\n";
    out += "  размер бинарника  : " + thousands(s.bin_size) + " байт\n\n";

    out += "ШИФРОВАНИЕ\n";
    out += "  " + indent2(md.key_report()) + "\n\n";

    out += "ТАБЛИЦЫ МЕТАДАННЫХ (определены автоматически)\n";
    out += L.report() + "\n\n";

    out += "БИНАРНИК\n";
    out += "  сегментов PT_LOAD : " + std::to_string(b.segments().size()) + "\n";
    out += "  релокаций RELA    : " + thousands(s.reloc_count) +
           " (" + s.reloc_source + ")\n";
    out += "  types[]           : " + hex(mr.types) + " (" +
           thousands(mr.types_count) + " элементов)\n";
    out += "  fieldOffsets      : " + hex(mr.field_offsets) + "\n";
    // Проверка упаковки — почему дампер решил, что библиотека не упакована.
    out += "  проверка упаковки : " + s.packing_why + "\n\n";

    // Сверка пары файлов: у совпадающей пары 100%, у разных сборок <5%.
    {
        std::ostringstream ss;
        ss.setf(std::ios::fixed);
        ss.precision(1);
        ss << (s.pair_ratio * 100.0);
        out += "СВЕРКА ПАРЫ ФАЙЛОВ\n";
        out += "  связность метаданных с бинарником: " + ss.str() + "%\n";
        out += "  (у файлов из одной сборки — 100%, из разных — меньше 5%)\n\n";
    }

    // Раскладка Il2CppTypeDefinition — выведена из данных, а не захардкожена.
    out += "РАСКЛАДКА ЗАПИСИ ТИПА\n";
    out += "  " + indent2(m.td_layout().report()) + "\n\n";

    // Основная сборка и число методов с RVA.
    if (!s.main_module.empty()) {
        out += "ОСНОВНАЯ СБОРКА\n";
        out += "  " + s.main_module + ": методов " +
               thousands(s.main_module_methods) + " @ " +
               hex(s.main_module_rva) + "\n";
        out += "  методов с RVA в дампе: " + thousands(s.methods_with_rva) +
               "\n\n";
    }

    // ── usage-таблицы (метод → ссылки на метадату) ───────────────────────
    // Английский заголовок "USAGE TABLES" — под него завязан grep в тестах и
    // скриптах интеграции (см. ТЗ). Тело — пояснение детекта из модуля.
    {
        const model::MetadataUsageTable& u = m.usages();
        out += "USAGE TABLES (Il2CppMetadataUsage)\n";
        out += "  " + indent2(u.report()) + "\n";
        if (u.usable()) {
            out += "  методов с usage-списком : " + thousands(u.method_count()) + "\n";
            out += "  всего usage-пар         : " + thousands(u.pair_count()) + "\n";
            out += "  из них строковых литералов: " +
                   thousands(u.kind_count(model::MetadataUsageKind::StringLiteral)) +
                   ", методов: " +
                   thousands(u.kind_count(model::MetadataUsageKind::MethodDef)) +
                   ", типов: " +
                   thousands(u.kind_count(model::MetadataUsageKind::TypeInfo) +
                             u.kind_count(model::MetadataUsageKind::Il2CppType)) +
                   ", полей: " +
                   thousands(u.kind_count(model::MetadataUsageKind::FieldInfo)) + "\n";
        }
        out += "\n";
    }

    // ── контрольная проверка ─────────────────────────────────────────────
    out += "КОНТРОЛЬНАЯ ПРОВЕРКА\n";
    const char* probes[] = {"PlayerManager", "BuildingPiece", "MouseLook",
                            "KCC", "NetworkIdentity"};
    struct Hit { std::string name; s32 idx; bool ok; };
    std::vector<Hit> hits;
    for (const char* p : probes) hits.push_back({p, -1, false});
    for (u32 i = 0; i < L.typedef_count; ++i) {
        const std::string nm = m.td_name(i);
        for (auto& h : hits) {
            if (!h.ok && h.name == nm) { h.idx = static_cast<s32>(i); h.ok = true; }
        }
    }
    auto pad = [](std::string x, std::size_t w) {
        while (x.size() < w) x += " ";
        return x;
    };
    for (const auto& h : hits) {
        if (!h.ok) {
            out += "  " + pad(h.name, 18) + "НЕ НАЙДЕН\n";
            continue;
        }
        const u32 nf = static_cast<u32>(
            m.fields_of(static_cast<u32>(h.idx)).size());
        const u32 byval = m.td_u32(static_cast<u32>(h.idx), m.td_layout().byval_type);
        out += "  " + pad(h.name, 18) +
               "TDI=" + pad(std::to_string(h.idx), 6) +
               " type_idx=" + pad(std::to_string(byval), 7) +
               " полей=" + std::to_string(nf) + "\n";
    }
    out += "\n";
    out += "Если контрольные классы не найдены или у них ноль полей —\n";
    out += "дамп неверен. Перезапусти с --verbose и приложи вывод.\n";
    return out;
}

} // namespace oxdump::output
