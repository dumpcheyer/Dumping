// oxdump/output/generics_txt.cpp — генерация generics.txt.
//
// Одна строка на generic-инстанс: человекочитаемое имя и VA его
// Il2CppGenericClass, выровненные в колонку. Отсортировано по VA (стабильный,
// монотонный порядок — удобно диффать и искать по адресу). Данные берём из
// уже построенной GenericInstanceTable; сам обход genericClasses[] живёт в
// model/generics.cpp.
//
// Ограничение в 5000 записей: у крупной игры инстансов 20-50k, а файл задуман
// как быстрый обзорный индекс, а не полный дамп. Полное число всё равно
// сообщаем в шапке.
#include "oxdump/output/generators.h"
#include <algorithm>

namespace oxdump::output {

namespace {

// Первые сколько инстансов пишем (ТЗ: cap 5000).
constexpr std::size_t MAX_ROWS = 5000;

// Ширина колонки имени: имя дополняется пробелами до этой ширины, затем "@ VA".
// Длинные имена не режем — просто выйдут за колонку (как в примере ТЗ).
constexpr std::size_t NAME_COL = 38;

} // namespace

std::string gen_generics_txt(model::Model& m,
                             const model::GenericInstanceTable& gt) {
    std::string out;

    // Таблицу не удалось построить (не нашли genericClasses[] в MR) — честная
    // заглушка, чтобы файл в архиве был всегда и было понятно, почему пусто.
    if (!gt.loaded()) {
        out += "# oxdump generic instances — one line per Il2CppGenericClass.\n";
        out += "# MetadataRegistration.genericClasses[] not found in this build\n";
        out += "# (library may be patched, or the MR layout differs). Nothing to\n";
        out += "# list. dump.cs still shows generic instances inline where known.\n";
        return out;
    }

    // Сортируем указатели на записи по VA. Копий инстансов не делаем.
    std::vector<const model::GenericInstance*> rows;
    rows.reserve(gt.all().size());
    for (const auto& gi : gt.all()) rows.push_back(&gi);
    std::sort(rows.begin(), rows.end(),
              [](const model::GenericInstance* a,
                 const model::GenericInstance* b) { return a->va < b->va; });

    const std::size_t shown = std::min(rows.size(), MAX_ROWS);

    out.reserve(shown * (NAME_COL + 24) + 256);
    out += "# oxdump generic instances — one line per Il2CppGenericClass,\n";
    out += "# sorted by VA. Format:  <Name>   @ 0xVA\n";
    out += "# total instances: " + std::to_string(gt.count());
    if (rows.size() > MAX_ROWS)
        out += "  (showing first " + std::to_string(MAX_ROWS) + ")";
    out += "\n\n";

    for (std::size_t i = 0; i < shown; ++i) {
        const model::GenericInstance* gi = rows[i];
        std::string line = gi->display_name;
        // Дополняем пробелами до колонки; гарантируем хотя бы один пробел перед
        // '@' даже для очень длинных имён.
        if (line.size() < NAME_COL) line.append(NAME_COL - line.size(), ' ');
        else line += " ";
        line += "@ " + hex(gi->va);
        out += line;
        out += "\n";
    }
    return out;
}

} // namespace oxdump::output
