// oxdump/metadata/headerless.cpp — восстановление раскладки по содержимому.
//
// Калька с headerless.py. Пороги и «послабления» перенесены вместе с
// замеренными причинами: например, размер строковой секции отдаётся С ЗАПАСОМ,
// потому что расширение текстовой зоны обрывается на бинарных вставках (дало
// 1.6 МБ вместо 3.1 МБ), а завышение безопасно — годность строки проверяется
// её содержимым.
#include "oxdump/metadata/headerless.h"
#include <algorithm>
#include <cstring>
#include <vector>

namespace oxdump::metadata::headerless {

namespace {

constexpr std::size_t NPOS = static_cast<std::size_t>(-1);

// Первый тип любой .NET-сборки. Самый надёжный якорь, который существует.
const char MODULE_ANCHOR[] = {'<', 'M', 'o', 'd', 'u', 'l', 'e', '>', '\0'};
constexpr std::size_t MODULE_ANCHOR_LEN = 9;

// Строки, обязанные быть в метаданных любой Unity-игры.
const char* const ANCHORS[] = {
    "System", "Object", "Int32", "String", "Void", "Boolean",
};

// Правдоподобные размеры записи Il2CppTypeDefinition.
const u32 REC_SIZES[] = {82, 84, 88, 92, 96, 100, 104, 120, 128};

bool is_text_byte(u8 b) noexcept { return b == 0 || (b >= 32 && b < 127); }

// Поиск байтовой последовательности от позиции from. Тело содержит нули,
// поэтому строковый поиск не годится — сравниваем memcmp.
std::size_t find_bytes(const u8* data, std::size_t n, const char* needle,
                       std::size_t nn, std::size_t from) noexcept {
    if (nn == 0 || nn > n) return NPOS;
    for (std::size_t p = from; p + nn <= n; ++p) {
        if (std::memcmp(data + p, needle, nn) == 0) return p;
    }
    return NPOS;
}

bool blob_contains(const u8* hay, std::size_t hn, const char* needle,
                   std::size_t nn) noexcept {
    return find_bytes(hay, hn, needle, nn, 0) != NPOS;
}

// Строка по индексу, если она похожа на имя типа. false означает None:
// нуль-терминатора нет в окне 200 байт, либо строка пустая/длинная/непечатная.
bool name_at(const u8* data, std::size_t n, u32 str_off, u32 idx, u32 limit,
             std::string& out) {
    if (idx >= limit) return false;
    const std::size_t o = static_cast<std::size_t>(str_off) + idx;
    if (o >= n) return false;
    // Ищем нуль в окне [o, min(o+200, n)). Нет нуля — None (как find == -1).
    const std::size_t hi = std::min(o + 200, n);
    std::size_t e = o;
    while (e < hi && data[e] != 0) ++e;
    if (e >= hi) return false;  // нуль не найден в пределах окна
    const std::size_t len = e - o;
    if (len == 0 || len > 160) return false;
    for (std::size_t i = o; i < e; ++i) {
        const u8 c = data[i];
        if (c < 32 || c >= 127) return false;
    }
    out.assign(reinterpret_cast<const char*>(data + o), len);
    return true;
}

// Кандидаты в строковую секцию: (начало, размер).
std::vector<std::pair<u32, u32>> find_string_section(const u8* data, std::size_t n) {
    std::vector<std::pair<u32, u32>> out;
    std::size_t pos = 0;
    while (out.size() < 8) {
        const std::size_t p = find_bytes(data, n, MODULE_ANCHOR,
                                         MODULE_ANCHOR_LEN, pos);
        if (p == NPOS) break;
        pos = p + 1;

        // назад до конца текстовой зоны
        std::size_t s = p;
        while (s > 0x40 && is_text_byte(data[s - 1])) --s;

        // Вперёд — с перепрыгиванием коротких бинарных вставок. Наивное
        // расширение «пока байт печатный» обрывается рано: внутри секции
        // попадаются служебные бинарные блоки (замерено: терялось 77%).
        constexpr std::size_t GAP_MAX = 64;
        std::size_t e = p;
        while (e < n) {
            if (is_text_byte(data[e])) { ++e; continue; }
            // бинарный байт — смотрим, длинная ли вставка
            std::size_t g = e;
            while (g < n && g - e < GAP_MAX && !is_text_byte(data[g])) ++g;
            if (g - e >= GAP_MAX) break;
            // за вставкой обязан идти текст, иначе это уже не наша секция
            const std::size_t probe_hi = std::min(g + 32, n);
            std::size_t txt = 0, probe_len = probe_hi - g;
            for (std::size_t k = g; k < probe_hi; ++k) if (is_text_byte(data[k])) ++txt;
            if (probe_len == 0 || txt < 28) break;
            e = g;
        }

        if (e - s > 4096) {
            // Размер С ЗАПАСОМ: он используется только как верхняя граница
            // индекса, а измеренная длина занижена (секция разбита вставками).
            // Завышение безопасно — годность строки проверяется содержимым.
            const std::size_t measured = e - s;
            const std::size_t eight_mb = static_cast<std::size_t>(8) << 20;
            const std::size_t generous =
                std::min(n - s, std::max(measured * 3, measured + eight_mb));
            out.emplace_back(static_cast<u32>(s), static_cast<u32>(generous));
        }
    }
    return out;
}

// Найденная таблица типов.
struct TypedefTable {
    bool ok = false;
    u32 start = 0;
    u32 count = 0;
    u32 rec = 0;
    u32 str_base = 0;
    double mono = 0.0;
};

TypedefTable find_typedef_table(const u8* data, std::size_t n,
                                u32 str_off, u32 str_size) {
    TypedefTable best;

    // Индекс имени типа 0 — смещение "<Module>" ОТ НАЧАЛА строковой секции.
    // Ищем в файле места, где записано это 32-битное значение: одно из них —
    // начало таблицы типов. Надёжнее сканирования «плотных зон»: осмысленные
    // имена встречаются и в других таблицах.
    const std::size_t mod_pos = find_bytes(data, n, MODULE_ANCHOR,
                                           MODULE_ANCHOR_LEN, str_off);
    if (mod_pos == NPOS ||
        mod_pos >= static_cast<std::size_t>(str_off) + str_size) {
        return best;
    }

    // Начало секции известно приблизительно (промах на пару байт), поэтому
    // индекс считаем для нескольких баз вокруг оценки.
    struct Cand { std::size_t start; u32 base; };
    std::vector<Cand> candidates;
    // dedup по (start, base): база узкая, храним пары в векторе.
    auto seen = [&candidates](std::size_t p, u32 base) -> bool {
        for (const Cand& c : candidates) if (c.start == p && c.base == base) return true;
        return false;
    };

    for (int delta = -8; delta <= 8; ++delta) {
        const long base_l = static_cast<long>(str_off) + delta;
        if (base_l < 0 || static_cast<std::size_t>(base_l) > mod_pos) continue;
        const u32 base = static_cast<u32>(base_l);
        const u32 mod_idx = static_cast<u32>(mod_pos - base);
        char needle[4];
        std::memcpy(needle, &mod_idx, 4);
        std::size_t pos = 0;
        while (true) {
            const std::size_t p = find_bytes(data, n, needle, 4, pos);
            if (p == NPOS) break;
            pos = p + 1;
            if (p >= base && p < static_cast<std::size_t>(base) + str_size) {
                continue;  // внутри самих строк — не начало таблицы
            }
            if (seen(p, base)) continue;

            // Дешёвый отсев: вторая запись любого размера даёт читаемое имя с
            // индексом БОЛЬШЕ, чем у "<Module>".
            bool ok_rec = false;
            for (u32 rec : REC_SIZES) {
                const std::size_t q = p + rec;
                if (q + 4 > n) continue;
                u32 nxt;
                std::memcpy(&nxt, data + q, 4);
                std::string nm;
                if (nxt > mod_idx && name_at(data, n, base, nxt, str_size, nm)) {
                    ok_rec = true;
                    break;
                }
            }
            if (ok_rec) candidates.push_back({p, base});
        }
    }

    for (u32 rec : REC_SIZES) {
        for (const Cand& c : candidates) {
            const std::size_t start = c.start;
            const u32 str_base = c.base;
            // Быстрый отсев: если первые записи не дают имён — дальше не считаем.
            u32 quick = 0;
            for (u32 i = 0; i < 8; ++i) {
                const std::size_t p = start + i * rec;
                if (p + 4 > n) break;
                u32 idx;
                std::memcpy(&idx, data + p, 4);
                std::string nm;
                if (name_at(data, n, str_base, idx, str_size, nm)) ++quick;
            }
            if (quick < 7) continue;

            // Сколько записей подряд дают читаемые имена.
            long count = 0, bad = 0;
            std::string nm;
            while (start + (count + 1) * rec <= n) {
                u32 idx;
                std::memcpy(&idx, data + start + count * rec, 4);
                if (name_at(data, n, str_base, idx, str_size, nm)) {
                    bad = 0;
                } else {
                    ++bad;
                    // длинная череда пустых имён — уже конец таблицы
                    if (bad > 24) { count -= bad; break; }
                }
                ++count;
                if (count > 200000) break;
            }
            if (count <= 500) continue;

            // Качество: доля читаемых имён по ВСЕЙ длине. Без этого побеждала
            // ложная таблица — длинная, но с 32% имён.
            const long step = std::max<long>(1, count / 400);
            u32 good = 0, total = 0;
            std::vector<u32> idxs;
            for (long i = 0; i < count; i += step) {
                u32 idx;
                std::memcpy(&idx, data + start + i * rec, 4);
                ++total;
                idxs.push_back(idx);
                if (name_at(data, n, str_base, idx, str_size, nm)) ++good;
            }
            const double ratio = total ? static_cast<double>(good) / total : 0.0;
            if (ratio < 0.85) continue;

            // Монотонность: строки лежат в том же порядке, что и типы, поэтому
            // индексы имён преимущественно РАСТУТ. Отсекает сдвинутую базу, где
            // индексы попадают в середину чужих строк.
            double mono = 0.0;
            if (idxs.size() > 32) {
                u32 inc = 0;
                for (std::size_t i = 1; i < idxs.size(); ++i) {
                    if (idxs[i - 1] < idxs[i]) ++inc;
                }
                mono = static_cast<double>(inc) / (idxs.size() - 1);
                if (mono < 0.60) continue;
            }

            // Из прошедших пороги решает ДЛИНА: настоящая таблица содержит ВСЕ
            // типы сборки, любая ложная — только кусок.
            if (!best.ok || static_cast<u32>(count) > best.count) {
                best.ok = true;
                best.start = static_cast<u32>(start);
                best.count = static_cast<u32>(count);
                best.rec = rec;
                best.str_base = str_base;
                best.mono = mono;
            }
        }
        if (best.ok) break;
    }
    return best;
}

// Доля стыков таблицы полей при обрезке до cut записей.
double joins_ratio(const u8* data, std::size_t n, u32 td_off, u32 rec,
                   u32 start_off, u32 count_off, u32 cut) {
    std::vector<std::pair<s32, u16>> pairs;
    for (u32 i = 0; i < cut; ++i) {
        const std::size_t p = td_off + static_cast<std::size_t>(i) * rec;
        if (p + std::max(start_off, count_off) + 4 > n) break;
        s32 s;
        std::memcpy(&s, data + p + start_off, 4);
        if (s < 0) continue;
        u16 c;
        std::memcpy(&c, data + p + count_off, 2);
        pairs.emplace_back(s, c);
    }
    if (pairs.size() < 100) return 0.0;
    std::sort(pairs.begin(), pairs.end());
    u32 j = 0;
    for (std::size_t i = 1; i < pairs.size(); ++i) {
        if (pairs[i - 1].first + pairs[i - 1].second == pairs[i].first) ++j;
    }
    return static_cast<double>(j) / (pairs.size() - 1);
}

// Уточняет конец таблицы типов по замощению таблицы полей. Поиск по имени
// находит НАЧАЛО точно, а конец переоценивает (замерено: 33 545 вместо 29 366).
std::pair<u32, double> trim_by_tiling(const u8* data, std::size_t n, u32 td_off,
                                      u32 td_count, u32 rec,
                                      u32 start_off = 0x1A, u32 count_off = 0x3E) {
    if (joins_ratio(data, n, td_off, rec, start_off, count_off, td_count) >= 0.999) {
        return {td_count, 1.0};
    }
    // Двоичный поиск наибольшей длины с идеальным замощением.
    u32 lo = 100, hi = td_count;
    bool have = false;
    u32 best = 0;
    while (lo <= hi) {
        const u32 mid = lo + (hi - lo) / 2;
        if (joins_ratio(data, n, td_off, rec, start_off, count_off, mid) >= 0.999) {
            have = true;
            best = mid;
            lo = mid + 1;
        } else {
            if (mid == 0) break;
            hi = mid - 1;
        }
    }
    if (!have) {
        return {td_count,
                joins_ratio(data, n, td_off, rec, start_off, count_off, td_count)};
    }
    return {best, 1.0};
}

// Число записей в таблице = верхняя граница плотной части сумм start+count.
u32 total_for(const u8* data, std::size_t n, u32 td_off, u32 td_count, u32 rec,
              u32 start_off, u32 count_off, u32 entry_size) {
    const u32 cap = static_cast<u32>(n / entry_size);
    std::vector<u32> vals;
    for (u32 i = 0; i < td_count; ++i) {
        const std::size_t p = td_off + static_cast<std::size_t>(i) * rec;
        if (p + std::max(start_off, count_off) + 4 > n) break;
        s32 s;
        std::memcpy(&s, data + p + start_off, 4);
        if (s < 0 || static_cast<u32>(s) > cap) continue;
        u16 c;
        std::memcpy(&c, data + p + count_off, 2);
        const u32 sum = static_cast<u32>(s) + c;
        if (sum <= cap) vals.push_back(sum);
    }
    if (vals.empty()) return 0;
    std::sort(vals.begin(), vals.end());
    // С конца отбрасываем значения, оторванные от соседа >5% — выбросы из
    // чужих данных за краем таблицы типов.
    std::size_t i = vals.size() - 1;
    while (i > 0) {
        const u32 gap_lim = std::max<u32>(1024, vals[i - 1] / 20);
        if (vals[i] - vals[i - 1] > gap_lim) { --i; continue; }
        break;
    }
    return vals[i];
}

// Начало таблицы по МЕТАДАННЫМ-ТОКЕНАМ .NET. У каждой записи токен: старший
// байт — таблица CLI (0x04 поля, 0x06 методы), младшие 24 бита — номер с
// единицы по порядку. Признак жёстче «читаемых имён».
u32 find_by_token(const u8* data, std::size_t n, u32 entry_size,
                  u32 token_off, u32 tag) {
    u32 first = (tag << 24) | 1;
    char needle[4];
    std::memcpy(needle, &first, 4);
    std::size_t pos = 0;
    while (true) {
        const std::size_t p = find_bytes(data, n, needle, 4, pos);
        if (p == NPOS) return 0;
        pos = p + 1;
        if (p < token_off) continue;
        const std::size_t start = p - token_off;
        // Подтверждаем: следующие записи несут токены по возрастанию.
        bool ok = true;
        for (u32 k = 1; k < 32; ++k) {
            const std::size_t q = start + static_cast<std::size_t>(k) * entry_size + token_off;
            if (q + 4 > n) { ok = false; break; }
            u32 t;
            std::memcpy(&t, data + q, 4);
            if (t != ((tag << 24) | (k + 1))) { ok = false; break; }
        }
        if (ok) return static_cast<u32>(start);
    }
}

// Длина таблицы по токенам. Нумерация сбрасывается на границе следующей
// сборки, поэтому считаем не «пока по порядку», а «пока старший байт == tag».
u32 count_by_token(const u8* data, std::size_t n, u32 start, u32 entry_size,
                   u32 token_off, u32 tag) {
    long k = 0, bad = 0;
    while (true) {
        const std::size_t q = start + static_cast<std::size_t>(k) * entry_size + token_off;
        if (q + 4 > n) break;
        u32 t;
        std::memcpy(&t, data + q, 4);
        if ((t >> 24) == tag && (t & 0xFFFFFF) != 0) {
            bad = 0;
        } else {
            ++bad;
            if (bad > 8) { k -= bad; break; }
        }
        ++k;
    }
    return static_cast<u32>(k);
}

// Проверка находки на вменяемость. Возвращает (ok, текст).
std::pair<bool, std::string> verify(const u8* data, std::size_t n, u32 str_off,
                                    u32 str_size, u32 td_off, u32 td_count, u32 rec) {
    std::vector<std::pair<std::string, bool>> checks;

    u32 idx0;
    std::memcpy(&idx0, data + td_off, 4);
    std::string nm0;
    name_at(data, n, str_off, idx0, str_size, nm0);
    checks.push_back({"тип 0 = <Module>", nm0 == "<Module>"});

    const std::size_t blob_n = std::min<std::size_t>(str_size, 1u << 20);
    int found = 0;
    if (static_cast<std::size_t>(str_off) + blob_n <= n) {
        for (const char* a : ANCHORS) {
            if (blob_contains(data + str_off, blob_n, a, std::strlen(a) + 1)) ++found;
        }
    }
    checks.push_back({"якорных строк " + std::to_string(found) + "/6", found >= 4});

    u32 good = 0, total = 0;
    const u32 step = std::max<u32>(1, td_count / 300);
    std::string nm;
    for (u32 i = 0; i < td_count; i += step) {
        u32 idx;
        std::memcpy(&idx, data + td_off + static_cast<std::size_t>(i) * rec, 4);
        ++total;
        if (name_at(data, n, str_off, idx, str_size, nm)) ++good;
    }
    const double ratio = total ? static_cast<double>(good) / total : 0.0;
    const int pct = static_cast<int>(ratio * 100 + 0.5);
    checks.push_back({"читаемых имён " + std::to_string(pct) + "%", ratio > 0.85});

    bool ok = true;
    std::string text;
    for (const auto& c : checks) {
        if (!c.second) ok = false;
        text += std::string("    ") + (c.second ? "да  " : "НЕТ ") + c.first + "\n";
    }
    if (!text.empty()) text.pop_back();  // убрать хвостовой перевод строки
    return {ok, text};
}

// Таблицы полей и методов по токенам + суммам start+count. Пишет в res.
void locate_tables(const u8* data, std::size_t n, HeaderlessResult& res,
                   std::vector<std::string>& report) {
    // ── поля: 12 байт на запись, токен на +8 ─────────────────────────────
    const u32 f_off = find_by_token(data, n, 12, 8, 0x04);
    if (f_off) {
        const u32 by_token = count_by_token(data, n, f_off, 12, 8, 0x04);
        const u32 by_types = total_for(data, n, res.typedef_offset,
                                       res.typedef_count, res.rec_size,
                                       0x1A, 0x3E, 12);
        const u32 cnt = std::max(by_token, by_types);
        if (cnt > 100) {
            res.field_offset = f_off;
            res.field_count = cnt;
            report.push_back("  поля    @" + hex(f_off) + ", " +
                             thousands(cnt) + " записей");
        }
    }
    // ── методы: 32 байта на запись, токен на +20 ─────────────────────────
    const u32 m_off = find_by_token(data, n, 32, 20, 0x06);
    if (m_off) {
        const u32 by_token = count_by_token(data, n, m_off, 32, 20, 0x06);
        const u32 by_types = total_for(data, n, res.typedef_offset,
                                       res.typedef_count, res.rec_size,
                                       0x1E, 0x3A, 32);
        const u32 cnt = std::max(by_token, by_types);
        if (cnt > 100) {
            res.method_offset = m_off;
            res.method_count = cnt;
            report.push_back("  методы  @" + hex(m_off) + ", " +
                             thousands(cnt) + " записей");
        }
    }
}

} // namespace

HeaderlessResult recover(ByteView view) {
    const u8* data = view.data;
    const std::size_t n = view.size;

    std::vector<std::string> report;
    report.push_back("восстановление БЕЗ заголовка (заголовок не читается)");

    auto cands = find_string_section(data, n);
    if (cands.empty()) {
        throw MetadataError(
            "не найдена строка '<Module>' — без неё зацепиться не за что.\n"
            "  Похоже, зашифрован не только заголовок, но и тело файла.\n"
            "  Тогда нужен дамп ПАМЯТИ запущенной игры: там метаданные\n"
            "  лежат в готовом виде, иначе игра не смогла бы работать.");
    }

    for (const auto& sc : cands) {
        const u32 s_off = sc.first;
        const u32 s_size = sc.second;
        report.push_back("  строковая секция: " + hex(s_off) + ", " +
                         thousands(s_size) + " байт");
        TypedefTable found = find_typedef_table(data, n, s_off, s_size);
        if (!found.ok) continue;

        const u32 td_off = found.start;
        u32 td_count = found.count;
        const u32 rec = found.rec;
        const u32 str_base = found.str_base;
        report.push_back("  база строк уточнена: " + hex(str_base));
        report.push_back("  монотонность индексов: " +
                         std::to_string(static_cast<int>(found.mono * 100 + 0.5)) + "%");

        // Конец уточняем замощением: поиск по имени находит начало точно, а
        // конец переоценивает на десяток процентов.
        const u32 raw_count = td_count;
        auto trimmed = trim_by_tiling(data, n, td_off, td_count, rec);
        td_count = trimmed.first;
        if (td_count != raw_count) {
            report.push_back("  конец уточнён замощением: " + thousands(raw_count) +
                             " → " + thousands(td_count) + " (" +
                             std::to_string(static_cast<int>(trimmed.second * 1000 + 0.5) / 10.0) +
                             "% стыков)");
        }

        auto ver = verify(data, n, str_base, s_size, td_off, td_count, rec);
        report.push_back("  таблица типов:    " + hex(td_off) + ", " +
                         thousands(td_count) + " записей, " +
                         std::to_string(rec) + " байт/запись");
        report.push_back(ver.second);

        if (ver.first) {
            HeaderlessResult res;
            res.string_offset = str_base;
            res.string_size = s_size;
            res.typedef_offset = td_off;
            res.typedef_count = td_count;
            res.rec_size = rec;
            locate_tables(data, n, res, report);
            std::string joined;
            for (std::size_t i = 0; i < report.size(); ++i) {
                if (i) joined += "\n";
                joined += report[i];
            }
            res.report = joined;
            return res;
        }
    }

    std::string joined;
    for (const std::string& r : report) joined += r + "\n";
    throw MetadataError("строки найдены, но таблица типов не опознана.\n" + joined);
}

} // namespace oxdump::metadata::headerless
