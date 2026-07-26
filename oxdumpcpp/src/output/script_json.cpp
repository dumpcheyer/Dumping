// oxdump/output/script_json.cpp — генерация script.json для IDA/Ghidra.
//
// Формат совместим с Il2CppDumper: массив ScriptMethod из пар (адрес, имя).
// Пишем свой минимальный JSON — внешних зависимостей у дампера нет. Адрес
// печатаем шестнадцатеричным литералом (0x…), как в эталонном формате: скрипты
// импорта Il2CppDumper это принимают, а глазами читать удобнее, чем decimal.
//
// Методы без RVA (не из основной сборки) пропускаем: адреса у них нет, класть
// нулевой смысла нет — так же поступает эталонный генератор.
#include "oxdump/output/generators.h"
#include "oxdump/model/metadata_usage.h"
#include <algorithm>
#include <memory>
#include <sstream>

namespace oxdump::output {

namespace {

// Резолвер строковых литералов для секции ScriptString. Il2CppStringLiteral —
// {u32 length; u32 dataIndex}, а сами байты лежат в отдельной секции
// stringLiteralData. Обе секции детекта в Layout нет (для dump.cs/il2cpp.h они
// не нужны), поэтому локализуем их здесь по сигнатуре — но ТОЛЬКО когда
// usage-таблицы опознаны (иначе ScriptString всё равно пуст). Детект строк в
// metadata/layout.cpp при этом не трогается: это локальная вспомогательная
// логика вывода.
class StringLiterals {
public:
    // md переживает вызов; копий данных не делаем — читаем по требованию.
    StringLiterals(const metadata::Metadata& md, u32 max_index) : md_(md) {
        // Таблица Il2CppStringLiteral: rec=8, count > max_index (индекс из
        // usage должен попадать внутрь). dataIndex монотонно растёт, length
        // маленькая. Секцию данных ищем как ASCII-блоб, куда dataIndex указывает
        // на печатные байты.
        find(max_index);
    }
    bool ok() const noexcept { return table_off_ && data_off_; }

    // Значение литерала по индексу в таблице stringLiteral.
    std::string value(u32 idx) const {
        if (!ok() || idx >= table_count_) return {};
        const u32 rec = table_off_ + idx * 8;
        const u32 len = md_.u32_at(rec);
        const u32 di  = md_.u32_at(rec + 4);
        if (len > 4096) return {};
        const ByteView bv = md_.bytes();
        if (data_off_ + di + len > bv.size) return {};
        return std::string(reinterpret_cast<const char*>(bv.data + data_off_ + di), len);
    }

private:
    void find(u32 max_index) {
        const ByteView bv = md_.bytes();
        std::vector<metadata::Section> secs = md_.sections();
        const u32 file_end = static_cast<u32>(md_.size());
        // Кандидаты в таблицу stringLiteral (rec=8) и в данные (ASCII-блоб).
        for (std::size_t i = 0; i < secs.size(); ++i) {
            const u32 next = (i + 1 < secs.size()) ? secs[i + 1].offset : file_end;
            const u32 real = std::min(secs[i].size, next - secs[i].offset);
            if (real % 8 != 0) continue;
            const u32 cnt = real / 8;
            if (cnt <= max_index || cnt < 16) continue;
            // Проверяем: length маленькая и dataIndex монотонно растёт.
            u32 n = std::min<u32>(cnt, 2000), ok_small = 0, mono = 0;
            s64 prev = -1;
            for (u32 k = 0; k < n; ++k) {
                const u32 len = bv.read_u32(secs[i].offset + k * 8);
                const u32 di  = bv.read_u32(secs[i].offset + k * 8 + 4);
                if (len <= 4096) ++ok_small;
                if (prev < 0 || static_cast<s64>(di) >= prev) ++mono;
                prev = di;
            }
            if (ok_small < n * 95 / 100 || mono < n * 95 / 100) continue;
            table_off_ = secs[i].offset;
            table_count_ = cnt;
            break;
        }
        if (!table_off_) return;
        // Данные: секция ASCII-блоба, на которую dataIndex[0..N] указывает
        // печатными байтами. Проверяем на первых записях таблицы.
        for (std::size_t i = 0; i < secs.size(); ++i) {
            const u32 next = (i + 1 < secs.size()) ? secs[i + 1].offset : file_end;
            const u32 real = std::min(secs[i].size, next - secs[i].offset);
            if (real < 64) continue;
            u32 hits = 0, tries = 0;
            for (u32 k = 0; k < std::min<u32>(table_count_, 64); ++k) {
                const u32 len = bv.read_u32(table_off_ + k * 8);
                const u32 di  = bv.read_u32(table_off_ + k * 8 + 4);
                if (len == 0 || len > 256) continue;
                if (di + len > real) continue;
                ++tries;
                std::size_t printable = 0;
                for (u32 j = 0; j < len; ++j) {
                    const u8 c = bv.data[secs[i].offset + di + j];
                    if (c >= 32 && c < 127) ++printable;
                }
                if (printable >= len * 9 / 10) ++hits;
            }
            if (tries >= 8 && hits >= tries * 9 / 10) {
                data_off_ = secs[i].offset;
                break;
            }
        }
    }

    const metadata::Metadata& md_;
    u32 table_off_ = 0;
    u32 table_count_ = 0;
    u32 data_off_ = 0;
};

// Экранирование строки по правилам JSON. Управляющие символы — через \uXXXX;
// кавычка и обратный слэш — через свои escape'ы. Без этого имена с '<', '>',
// '`' и кавычками (а они в generic-типах есть) ломали бы JSON.
void json_escape(std::string& out, const std::string& s) {
    static const char* hexd = "0123456789abcdef";
    out += '"';
    for (unsigned char c : s) {
        switch (c) {
            case '"':  out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\b': out += "\\b";  break;
            case '\f': out += "\\f";  break;
            case '\n': out += "\\n";  break;
            case '\r': out += "\\r";  break;
            case '\t': out += "\\t";  break;
            default:
                if (c < 0x20) {
                    out += "\\u00";
                    out += hexd[(c >> 4) & 0xF];
                    out += hexd[c & 0xF];
                } else {
                    out += static_cast<char>(c);
                }
        }
    }
    out += '"';
}

} // namespace

std::string gen_script_json(model::Model& m, const progress_cb& progress) {
    auto& L = m.layout();
    const u32 total = L.typedef_count;
    const s32 method_start_off = m.td_layout().method_start;

    std::string out;
    out.reserve(16u * 1024u * 1024u);
    out += "{\n \"ScriptMethod\": [\n";

    // ScriptString строим ПАРАЛЛЕЛЬНО обходу методов и дописываем отдельной
    // секцией в конце — так методы обходятся один раз. Заполняется, только если
    // usage-таблицы опознаны: каждая StringLiteral-usage метода → (значение
    // литерала, адрес метода). На сборках без usage-таблиц секция останется
    // пустой (но валидной): деобфускация тогда идёт запасным путём.
    std::string strings;
    bool str_first = true;
    const model::MetadataUsageTable& usages = m.usages();
    // Резолвер литералов: локализуем таблицу stringLiteral/данные один раз.
    // Верхнюю границу индекса берём с запасом — сам резолвер отсеет промахи.
    std::unique_ptr<StringLiterals> lits;
    if (usages.usable()) {
        lits = std::make_unique<StringLiterals>(m.md(), 1u << 20);
    }

    bool first = true;
    for (u32 i = 0; i < total; ++i) {
        if (progress && i % 2000 == 0) progress(i, total);
        const std::string tname = m.full_name(static_cast<s32>(i));
        // Глобальный индекс метода = methodStart типа + порядковый номер.
        const s32 mstart =
            (method_start_off >= 0) ? m.td_s32(i, method_start_off) : -1;
        u32 mi = 0;
        for (const auto& mo : m.methods_of(i)) {
            const u32 method_index =
                (mstart >= 0) ? static_cast<u32>(mstart) + mi : 0;
            ++mi;
            if (!mo.rva) continue;  // нет адреса — нет записи
            std::vector<model::Param> params =
                m.params_of(mo.param_start, mo.param_count);
            std::string args;
            for (std::size_t k = 0; k < params.size(); ++k) {
                if (k) args += ", ";
                args += params[k].type_name;
            }

            if (!first) out += ",\n";
            first = false;

            // Одна запись ScriptMethod. Address — hex-литерал; строки —
            // экранированы. Поля Name/Signature/TypeSignature как в эталоне.
            out += "  {\n   \"Address\": ";
            out += hex(mo.rva);
            out += ",\n   \"Name\": ";
            json_escape(out, tname + "$$" + mo.name);
            out += ",\n   \"Signature\": ";
            json_escape(out, mo.ret_type + " " + tname + "::" + mo.name +
                                 "(" + args + ")");
            out += ",\n   \"TypeSignature\": ";
            json_escape(out, tname);
            out += "\n  }";

            // ScriptString: строковые литералы, на которые ссылается метод.
            if (lits && mstart >= 0) {
                for (const model::MetadataUsage& u : usages.for_method(method_index)) {
                    if (u.kind != model::MetadataUsageKind::StringLiteral) continue;
                    const std::string v = lits->value(u.target_index);
                    if (v.empty()) continue;
                    if (!str_first) strings += ",\n";
                    str_first = false;
                    strings += "  {\n   \"Value\": ";
                    json_escape(strings, v);
                    strings += ",\n   \"Address\": ";
                    strings += hex(mo.rva);
                    strings += "\n  }";
                }
            }
        }
    }

    out += "\n ],\n \"ScriptString\": [\n";
    out += strings;
    out += "\n ]\n}\n";
    if (progress) progress(total, total);
    return out;
}

} // namespace oxdump::output
