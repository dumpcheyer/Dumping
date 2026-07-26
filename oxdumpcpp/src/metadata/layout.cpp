// oxdump/metadata/layout.cpp — определение назначений секций по содержимому.
//
// Калька с metadata.py::Layout. Пороги и «равномерная выборка вместо первых
// N записей» перенесены вместе с причинами: в начале таблиц лежат служебные
// записи компилятора, по которым настоящая таблица выглядит хуже подделки.
#include "oxdump/metadata/layout.h"
#include <algorithm>
#include <cstring>

namespace oxdump::metadata {

namespace {

// Те же якорные строки, что и при восстановлении ключа. Ищем с нуль-байтом.
const char* const ANCHOR_STRINGS[] = {
    "System", "Object", "Int32", "String",
    "Void", "Boolean", "Single", "UInt32",
};

bool blob_contains(const u8* hay, std::size_t hn,
                   const char* needle, std::size_t nn) noexcept {
    if (nn == 0 || nn > hn) return false;
    const u8* end = hay + (hn - nn) + 1;
    for (const u8* p = hay; p < end; ++p) {
        if (std::memcmp(p, needle, nn) == 0) return true;
    }
    return false;
}

// Имя типа: непустое, разумной длины, все символы печатные ASCII. Заменяет
// связку `nm and nm.isprintable() and 1 <= len(nm) <= 128` из Python.
bool is_good_name(const std::string& s) noexcept {
    if (s.empty() || s.size() > 128) return false;
    for (unsigned char c : s) {
        if (c < 32 || c >= 127) return false;
    }
    return true;
}

} // namespace

Layout::Layout(const Metadata& md) : md_(md) {
    detect();
}

Layout::Layout(direct_tag, const Metadata& md,
               const headerless::HeaderlessResult& hr)
    : md_(md), headerless_(true) {
    // Прямая раскладка из находок headerless::recover(). detect() не зовём:
    // он опирается на секции заголовка, которых в этом режиме нет.
    string_offset = hr.string_offset;
    string_size = hr.string_size;
    typedef_offset = hr.typedef_offset;
    typedef_count = hr.typedef_count;
    field_offset = hr.field_offset;
    field_count = hr.field_count;
    method_offset = hr.method_offset;
    method_count = hr.method_count;
    // Вторичные таблицы headerless не восстанавливает.
    image_offset = 0;
    image_count = 0;
    param_offset = 0;
    param_count = 0;
    prop_offset = 0;
    prop_count = 0;
}

Layout Layout::make_from_headerless(const Metadata& md,
                                    const headerless::HeaderlessResult& hr) {
    return Layout(direct_tag{}, md, hr);
}

std::vector<Section> Layout::ascii_sections() const {
    // Секция похожа на строки, если в пробе есть нули и доля печатных+нулей
    // не ниже 95%. Проба — первые 8 КБ, этого достаточно для отсева.
    std::vector<Section> out;
    for (const Section& sec : md_.sections()) {
        const std::size_t probe_n =
            std::min<std::size_t>(sec.size, 8192);
        if (probe_n == 0) continue;
        const ByteView bv = md_.bytes();
        if (sec.offset + probe_n > bv.size) continue;
        const u8* probe = bv.data + sec.offset;
        std::size_t zeros = 0, printable = 0;
        for (std::size_t i = 0; i < probe_n; ++i) {
            const u8 b = probe[i];
            if (b == 0) ++zeros;
            else if (b >= 32 && b < 127) ++printable;
        }
        if (zeros == 0) continue;  // нет нулей — не строковая секция
        const double ratio =
            static_cast<double>(printable + zeros) / static_cast<double>(probe_n);
        if (ratio < 0.95) continue;
        out.push_back(sec);
    }
    return out;
}

void Layout::detect_strings() {
    // Строк в метаданных НЕСКОЛЬКО секций (имена типов, литералы, GUID'ы), и
    // все выглядят как ASCII. Нужна та, на которую ссылаются индексы имён в
    // таблице типов. Решающий признак: первый тип любой .NET-сборки —
    // "<Module>". Если по индексу 0 читается он, секция найдена точно.
    std::vector<Section> cands = ascii_sections();
    if (cands.empty()) return;

    // Таблица типов уже нужна для проверки — находим её предварительно по
    // кратности размера записи (уточним позже в detect_typedefs).
    struct TdCand { u32 off; u32 cnt; };
    std::vector<TdCand> td_cands;
    for (const Section& sec : md_.sections()) {
        if (sec.size >= TYPEDEF_REC * 100 && sec.size % TYPEDEF_REC == 0) {
            td_cands.push_back({sec.offset, sec.size / TYPEDEF_REC});
        }
    }

    long best_score = -1;
    u32 b_soff = 0, b_ssize = 0, b_tdoff = 0, b_tdcnt = 0;
    for (const Section& s : cands) {
        for (const TdCand& td : td_cands) {
            long score = 0;
            // (1) первый тип — "<Module>"
            const std::string first = md_.cstr(s.offset, md_.u32_at(td.off));
            if (first == "<Module>") score += 1000;
            // (2) сколько имён читается осмысленно (первые 300 записей)
            long good = 0;
            const u32 lim = std::min<u32>(td.cnt, 300);
            for (u32 i = 0; i < lim; ++i) {
                const u32 ni = md_.u32_at(td.off + i * TYPEDEF_REC);
                if (ni >= s.size) continue;
                const std::string nm = md_.cstr(s.offset, ni);
                if (is_good_name(nm)) ++good;
            }
            score += good;
            // (3) якорные строки внутри секции (первые 512 КБ)
            const std::size_t blob_n =
                std::min<std::size_t>(s.size, 512u * 1024u);
            const ByteView bv = md_.bytes();
            if (s.offset + blob_n <= bv.size) {
                const u8* blob = bv.data + s.offset;
                for (const char* a : ANCHOR_STRINGS) {
                    if (blob_contains(blob, blob_n, a, std::strlen(a) + 1)) {
                        score += 50;
                    }
                }
            }
            if (score > best_score) {
                best_score = score;
                b_soff = s.offset; b_ssize = s.size;
                b_tdoff = td.off; b_tdcnt = td.cnt;
            }
        }
    }

    if (best_score >= 0) {
        string_offset = b_soff;
        string_size = b_ssize;
        have_td_hint_ = true;
        td_hint_off_ = b_tdoff;
        td_hint_cnt_ = b_tdcnt;
    }
}

void Layout::detect_typedefs() {
    // Il2CppTypeDefinition: первые два поля — индексы в строковую секцию.
    // Проверяем, что по ним читаются осмысленные имена классов.
    u32 best_off = 0, best_cnt = 0;
    long best_score = 0;
    for (const Section& sec : md_.sections()) {
        if (sec.size < TYPEDEF_REC * 100 || sec.size % TYPEDEF_REC != 0) continue;
        const u32 count = sec.size / TYPEDEF_REC;
        long good = 0;
        const u32 lim = std::min<u32>(count, 200);
        for (u32 i = 0; i < lim; ++i) {
            const u32 rec = sec.offset + i * TYPEDEF_REC;
            if (rec + 8 > md_.size()) break;
            const u32 name_idx = md_.u32_at(rec);
            const u32 ns_idx = md_.u32_at(rec + 4);
            if (name_idx >= string_size || ns_idx >= string_size) continue;
            const std::string nm = md_.cstr(string_offset, name_idx);
            if (is_good_name(nm)) ++good;
        }
        if (good > best_score) {
            best_score = good;
            best_off = sec.offset;
            best_cnt = count;
        }
    }
    // Не перетираем результат, полученный вместе со строковой секцией: он
    // подтверждён совпадением "<Module>", это сильнее подсчёта имён.
    if (best_off && !have_td_hint_) {
        typedef_offset = best_off;
        typedef_count = best_cnt;
    }
}

std::pair<u32, u32> Layout::detect_by_record(
    u32 rec_size, const std::function<bool(u32)>& validator) const {
    // Выборка РАВНОМЕРНАЯ по всей секции, а не первые N записей. Оценка
    // нормируется на размер выборки, иначе крупная секция побеждает числом.
    constexpr u32 SAMPLES = 400;
    u32 best_off = 0, best_cnt = 0;
    double best_ratio = 0.0;
    for (const Section& sec : md_.sections()) {
        if (sec.size < rec_size * 20 || sec.size % rec_size != 0) continue;
        if (sec.offset == typedef_offset || sec.offset == string_offset) continue;
        const u32 count = sec.size / rec_size;
        const u32 step = std::max<u32>(1, count / SAMPLES);
        u32 total = 0, good = 0;
        for (u32 i = 0; i < count && total < SAMPLES; i += step) {
            ++total;
            if (validator(sec.offset + i * rec_size)) ++good;
        }
        if (total == 0) continue;
        const double ratio = static_cast<double>(good) / total;
        // Порог отсекает случайные совпадения; при равном качестве —
        // предпочитаем БОЛЬШУЮ таблицу, настоящая всегда крупнее.
        if (ratio > 0.75 &&
            (ratio > best_ratio + 0.02 ||
             (std::abs(ratio - best_ratio) <= 0.02 && count > best_cnt))) {
            best_ratio = ratio;
            best_off = sec.offset;
            best_cnt = count;
        }
    }
    return {best_off, best_cnt};
}

void Layout::detect_images() {
    // Il2CppImage: 40 байт. nameIndex -> строка вида "*.dll".
    auto ends_with_dll = [this](u32 rec) -> bool {
        const std::string nm = md_.cstr(string_offset, md_.u32_at(rec));
        return nm.size() >= 4 && nm.compare(nm.size() - 4, 4, ".dll") == 0;
    };
    auto r = detect_by_record(40, ends_with_dll);
    if (!r.first) r = detect_by_record(36, ends_with_dll);
    image_offset = r.first;
    image_count = r.second;
}

s32 Layout::index_range(u32 field_off) const {
    // Максимальный индекс в поле записи typedef. Таблица, на которую поле
    // ссылается, обязана содержать хотя бы столько записей.
    s32 hi = -1;
    if (typedef_count == 0) return hi;
    const u32 step = std::max<u32>(1, typedef_count / 4000);
    for (u32 i = 0; i < typedef_count; i += step) {
        const u32 rec = typedef_offset + i * TYPEDEF_REC + field_off;
        if (rec + 4 > md_.size()) break;
        const s32 v = md_.s32_at(rec);
        if (v >= 0 && v < 50000000) hi = std::max(hi, v);
    }
    return hi;
}

std::pair<u32, u32> Layout::detect_by_index_range(u32 rec_size, s32 max_index) const {
    // Ищет таблицу по ЧИСЛУ ЗАПИСЕЙ, требуемому ссылками из typedef. Подбор по
    // «качеству записей» тут не работает: несколько секций выглядят одинаково
    // правдоподобно. А размер — жёсткое условие: настоящая лишь немного больше
    // максимального индекса.
    if (max_index <= 0) return {0, 0};
    u32 best_off = 0, best_cnt = 0;
    bool have = false;
    u32 best_slack = 0;
    const u32 mi = static_cast<u32>(max_index);
    for (const Section& sec : md_.sections()) {
        if (sec.size % rec_size != 0) continue;
        const u32 count = sec.size / rec_size;
        if (count <= mi) continue;
        const u32 slack = count - mi;
        if (!have || slack < best_slack) {
            have = true;
            best_slack = slack;
            best_off = sec.offset;
            best_cnt = count;
        }
    }
    return {best_off, best_cnt};
}

void Layout::detect_methods() {
    // Таблица методов: на неё ссылается typedef+0x1E (methodStart).
    const s32 hi = index_range(0x1E);
    auto r = detect_by_index_range(32, hi);
    if (!r.first) {
        // запасной путь — по содержимому
        auto ok = [this](u32 rec) -> bool {
            const std::string nm = md_.cstr(string_offset, md_.u32_at(rec));
            const s32 dt = md_.s32_at(rec + 4);
            return is_good_name(nm) && dt >= 0 &&
                   static_cast<u32>(dt) < typedef_count;
        };
        r = detect_by_record(32, ok);
    }
    method_offset = r.first;
    method_count = r.second;
}

void Layout::detect_fields() {
    // Таблица полей: на неё ссылается typedef+0x1A (fieldStart).
    const s32 hi = index_range(0x1A);
    auto r = detect_by_index_range(12, hi);
    if (!r.first) {
        auto ok = [this](u32 rec) -> bool {
            const std::string nm = md_.cstr(string_offset, md_.u32_at(rec));
            return is_good_name(nm);
        };
        r = detect_by_record(12, ok);
    }
    field_offset = r.first;
    field_count = r.second;
}

void Layout::detect() {
    detect_strings();
    if (have_td_hint_) {
        typedef_offset = td_hint_off_;
        typedef_count = td_hint_cnt_;
    }
    detect_typedefs();
    detect_images();
    detect_methods();
    detect_fields();
}

std::string Layout::report() const {
    std::string s;
    s += "  строки:  offset=" + hex(string_offset, 8) +
         " size=" + std::to_string(string_size) + "\n";
    s += "  типы:    offset=" + hex(typedef_offset, 8) +
         " count=" + std::to_string(typedef_count) + "\n";
    // Образы в headerless-режиме не восстанавливаются (нет карты секций).
    if (headerless_ && image_count == 0) {
        s += "  образы:  не восстановлены (headerless-режим)\n";
    } else {
        s += "  образы:  offset=" + hex(image_offset, 8) +
             " count=" + std::to_string(image_count) + "\n";
    }
    s += "  методы:  offset=" + hex(method_offset, 8) +
         " count=" + std::to_string(method_count) + "\n";
    s += "  поля:    offset=" + hex(field_offset, 8) +
         " count=" + std::to_string(field_count);
    // Параметры в headerless-режиме тоже могут не восстановиться.
    if (headerless_ && param_offset == 0) {
        s += "\n  параметры: не восстановлены (headerless-режим)";
    }
    return s;
}

bool Layout::ok() const noexcept {
    // Headerless-режим: образов нет, а вторичные таблицы могут не
    // восстановиться — достаточно типов и строк, dump.cs соберётся.
    if (headerless_) {
        return string_offset && typedef_offset && typedef_count > 100;
    }
    return string_offset && typedef_offset && typedef_count > 100 &&
           method_offset && field_offset;
}

} // namespace oxdump::metadata
