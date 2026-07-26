// oxdump/metadata/header.cpp — восстановление ключа и разбор заголовка.
//
// Логика калькирована с эталонного metadata.py. Все пороги перенесены вместе
// с причинами: иначе при «чистке» кода они вернутся как баги на реальных
// файлах, перешифрованных другим способом.
#include "oxdump/metadata/header.h"
#include <cstring>  // до container.h: тот использует std::memcmp, но не включает <cstring>
#include "oxdump/crypto/container.h"
#include <algorithm>
#include <unordered_map>
#include <unordered_set>

namespace oxdump::metadata {

namespace {

// Строки, которые есть в метаданных ЛЮБОЙ игры на Unity. Проверяем с
// нуль-байтом на конце — так отсекаются обрывки внутри длинных имён.
const char* const ANCHOR_STRINGS[] = {
    "System", "Object", "Int32", "String",
    "Void", "Boolean", "Single", "UInt32",
};

// Поиск подстроки в бинарном блобе. std::search по указателям — блоб может
// содержать нули, поэтому строковый поиск не годится.
bool blob_contains(const u8* hay, std::size_t hn,
                   const char* needle, std::size_t nn) noexcept {
    if (nn == 0 || nn > hn) return false;
    const u8* end = hay + (hn - nn) + 1;
    for (const u8* p = hay; p < end; ++p) {
        if (std::memcmp(p, needle, nn) == 0) return true;
    }
    return false;
}

// Сколько якорных строк (со завершающим нулём) встречается в блобе.
int count_anchors(const u8* blob, std::size_t n) noexcept {
    int found = 0;
    for (const char* a : ANCHOR_STRINGS) {
        // needle = "System\0" — длина слова + завершающий нуль.
        const std::size_t len = std::strlen(a) + 1;
        if (blob_contains(blob, n, a, len)) ++found;
    }
    return found;
}

} // namespace

std::string Metadata::KeyCandidate::describe() const {
    const char* tn = transform ? transform->name() : "XOR32";
    std::string s = "key=" + hex(key, 8) + " [" + tn + "]";
    s += " score=" + std::to_string(score());
    s += " (joins=" + std::to_string(joins);
    s += " anchors=" + std::to_string(anchors) + "/8";
    s += " inrange=" + std::to_string(inrange);
    s += " zeros=" + std::to_string(zeros) + ")";
    return s;
}

Metadata::Metadata(ByteView view) : v_(view) {
    // Заголовок и первые секции должны хотя бы поместиться.
    if (!v_.valid() || v_.size < 0x200) {
        throw MetadataError("файл слишком мал: " +
                            std::to_string(v_.size) + " байт");
    }

    magic_ = v_.read_u32(0);
    version_ = v_.read_u32(4);
    if (magic_ != crypto::IL2CPP_MAGIC) {
        // Не просто «неверный magic»: разбираемся, ЧТО нам дали — сжатый
        // архив, зашифрованный целиком файл и посторонний требуют разных
        // действий от пользователя.
        auto c = crypto::detect_container(v_);
        throw MetadataError(
            "не global-metadata.dat: magic=" + hex(magic_, 8) +
            ", ожидался " + hex(crypto::IL2CPP_MAGIC, 8) + "\n  " + c.detail);
    }

    recover_key();
}

Metadata::Metadata(direct_tag, ByteView raw, u32 version,
                   const headerless::HeaderlessResult& hr)
    : v_(raw) {
    // Заголовок не расшифрован — карту секций уже восстановил headerless.
    // Магию тут НЕ проверяем: обычный путь Metadata(ByteView) её проверил и
    // отказал именно потому, что не смог с ключом, а не из-за магии.
    magic_ = v_.valid() ? v_.read_u32(0) : 0;
    (void)hr;  // поля секций живут в Layout; Metadata читает файл напрямую
    init_from_direct_values(version);
}

void Metadata::init_from_direct_values(u32 version) {
    // Быстрый путь без ключа: тело файла не шифровалось, поэтому field()
    // должен возвращать значения как есть. key=0 и transform=null делают
    // XOR32-ветку тождественной (v ^ 0 == v).
    version_ = version;
    key_ = 0;
    transform_ = nullptr;
    key_report_ =
        "заголовок не расшифрован — карта секций восстановлена по "
        "содержимому файла";
}

Metadata Metadata::make_from_headerless(ByteView raw, u32 version,
                                        const headerless::HeaderlessResult& hr) {
    return Metadata(direct_tag{}, raw, version, hr);
}

u32 Metadata::hdr_end() const noexcept {
    return static_cast<u32>(std::min<std::size_t>(HDR_END_MAX, v_.size));
}

std::vector<u32> Metadata::candidates() const {
    // Ключ обязан быть среди значений полей: хотя бы одна секция пуста.
    // Считаем частоты и отдаём по убыванию — верный ключ обычно самый частый.
    std::unordered_map<u32, int> freq;
    const u32 end = hdr_end();
    for (u32 off = HDR_START; off + 4 <= end && off + 4 <= v_.size; off += 4) {
        ++freq[v_.read_u32(off)];
    }
    std::vector<std::pair<u32, int>> pairs(freq.begin(), freq.end());
    std::sort(pairs.begin(), pairs.end(),
              [](const auto& a, const auto& b) { return a.second > b.second; });
    std::vector<u32> out;
    out.reserve(pairs.size() + 1);
    for (const auto& p : pairs) out.push_back(p.first);
    out.push_back(0);  // вариант «шифрование убрали»
    return out;
}

Metadata::KeyCandidate
Metadata::evaluate(u32 key, const crypto::Transform* t) const {
    KeyCandidate c;
    c.key = key;
    c.transform = t;

    // Пары (offset, size) для проверки стыковки. transform==nullptr — быстрый
    // путь XOR32: эта ветка исполняется десятки тысяч раз.
    std::vector<std::pair<u32, u32>> pairs;
    const u32 end = hdr_end();
    const u32 n = static_cast<u32>(v_.size);
    for (u32 off = HDR_START; off + 8 <= end && off + 8 <= v_.size; off += 8) {
        u32 o, s;
        if (t == nullptr) {
            o = v_.read_u32(off) ^ key;
            s = v_.read_u32(off + 4) ^ key;
        } else {
            o = t->decode(v_.read_u32(off), key, off);
            s = t->decode(v_.read_u32(off + 4), key, off + 4);
        }
        if (o == 0 && s == 0) {
            ++c.zeros;
            continue;
        }
        if (o >= 0x100 && o < n && s > 0 && s <= n - o) {
            ++c.inrange;
            pairs.emplace_back(o, s);
        }
    }

    // (2) стыковка секций — решающий критерий.
    std::sort(pairs.begin(), pairs.end());
    for (std::size_t i = 1; i < pairs.size(); ++i) {
        if (pairs[i - 1].first + pairs[i - 1].second == pairs[i].first) ++c.joins;
    }

    // (3) содержимое строковой секции: первое поле — (stringOffset, stringSize).
    u32 s_off, s_len;
    if (t == nullptr) {
        s_off = v_.read_u32(HDR_START) ^ key;
        s_len = v_.read_u32(HDR_START + 4) ^ key;
    } else {
        s_off = t->decode(v_.read_u32(HDR_START), key, HDR_START);
        s_len = t->decode(v_.read_u32(HDR_START + 4), key, HDR_START + 4);
    }
    if (s_off >= 0x100 && s_off < n && s_len > 0 && s_len <= n - s_off) {
        const std::size_t blob_n =
            std::min<std::size_t>(s_len, 512u * 1024u);
        c.anchors = count_anchors(v_.data + s_off, blob_n);
    }
    return c;
}

std::vector<u32> Metadata::bruteforce_key() const {
    // Полный перебор по ЯКОРЮ, когда кандидатов из заголовка не хватило.
    // stringOffset — первое поле (0x08). Значение неизвестно, но известно ЧТО
    // по нему лежит: "<Module>" — первый тип любой .NET-сборки. Каждое
    // найденное место даёт кандидата: key = зашифрованное_поле XOR смещение.
    const u32 enc = v_.read_u32(HDR_START);
    std::vector<u32> out;
    std::unordered_set<u32> seen;

    const char* needle = "<Module>\0";  // 9 байт вместе с нулём
    const std::size_t nn = 9;
    std::size_t pos = 0;
    int hits = 0;
    while (hits < 8 && pos + nn <= v_.size) {
        // Ручной поиск подстроки: тело может содержать нули.
        const u8* start = v_.data + pos;
        const u8* stop = v_.data + (v_.size - nn) + 1;
        const u8* found = nullptr;
        for (const u8* p = start; p < stop; ++p) {
            if (std::memcmp(p, needle, nn) == 0) { found = p; break; }
        }
        if (!found) break;
        const std::size_t fp = static_cast<std::size_t>(found - v_.data);
        ++hits;
        // "<Module>" не обязательно ПЕРВАЯ строка секции: на проверенном
        // файле она на 40 байт дальше начала. Перебираем окрестность.
        for (u32 back = 0; back < 256; ++back) {
            if (fp < back) break;
            const std::size_t base = fp - back;
            if (base < 0x100) break;
            const u32 cand = enc ^ static_cast<u32>(base);
            if (seen.insert(cand).second) out.push_back(cand);
        }
        pos = fp + 1;
    }
    return out;
}

bool Metadata::try_other_transforms(KeyCandidate& out) const {
    // Кандидаты в ключи получаются тем же приёмом: пустая секция (0,0) выдаёт
    // ключ через solve(). Для преобразований, где solve всегда что-то
    // возвращает (Add/Sub/XorIndexed), собираем до 400 значений.
    bool have = false;
    KeyCandidate best;
    const u32 end = hdr_end();

    for (const auto& tp : transforms_) {
        const crypto::Transform* t = tp.get();
        if (std::strcmp(t->name(), "XOR32") == 0) continue;  // отработан выше

        std::unordered_set<u32> cands;
        for (u32 off = HDR_START; off + 4 <= end && off + 4 <= v_.size; off += 4) {
            auto k = t->solve(v_.read_u32(off), 0, off);
            if (k) cands.insert(*k);
            if (cands.size() > 400) break;
        }
        int used = 0;
        for (u32 k : cands) {
            if (used++ >= 400) break;
            KeyCandidate c = evaluate(k, t);
            if (c.joins > 0 && (!have || c.score() > best.score())) {
                best = c;
                have = true;
            }
        }
    }
    if (have) out = best;
    return have;
}

void Metadata::recover_key() {
    transforms_ = crypto::make_all();

    // ── первый рубеж: кандидаты из заголовка, XOR32 ──────────────────────
    std::vector<KeyCandidate> ranked;
    for (u32 k : candidates()) ranked.push_back(evaluate(k));
    std::sort(ranked.begin(), ranked.end(),
              [](const KeyCandidate& a, const KeyCandidate& b) {
                  return a.score() > b.score();
              });
    KeyCandidate best = ranked.front();
    std::string method = best.joins ? "стыковка секций" : "якорные строки";
    int runner_up = ranked.size() > 1 ? ranked[1].score() : -1;

    // ── второй рубеж: перебор по строке <Module> ─────────────────────────
    // Запускается по нехватке СТЫКОВ, а не якорей: блоб строк большой, якоря
    // находятся почти при любом смещении. Слабая стыковка надёжно означает
    // неверный ключ.
    if (best.joins < MIN_CONFIDENT_JOINS) {
        std::vector<u32> extra = bruteforce_key();
        if (!extra.empty()) {
            std::vector<KeyCandidate> r2;
            for (u32 k : extra) r2.push_back(evaluate(k));
            std::sort(r2.begin(), r2.end(),
                      [](const KeyCandidate& a, const KeyCandidate& b) {
                          return a.score() > b.score();
                      });
            // Берём результат перебора, если он дал СТЫКИ — то, чего не смог
            // заголовочный путь.
            if (!r2.empty() &&
                (r2.front().joins > best.joins ||
                 (r2.front().joins && r2.front().score() > best.score()))) {
                best = r2.front();
                runner_up = r2.size() > 1 ? r2[1].score() : -1;
                method = "поиск по строке <Module>";
            }
        }
    }

    // ── третий рубеж: а вдруг это вообще НЕ XOR ───────────────────────────
    // Порог — НЕ «ноль стыков». Неверный XOR-ключ случайно набирает 1 стык и
    // блокирует перебор, хотя настоящий ADD32-ключ даёт 5 стыков и скор
    // втрое выше. Перебираем, пока стыков мало.
    if (best.joins < MIN_CONFIDENT_JOINS) {
        KeyCandidate alt;
        if (try_other_transforms(alt) && alt.joins > best.joins) {
            best = alt;
            runner_up = -1;
            method = std::string("перебор преобразований (") +
                     (alt.transform ? alt.transform->name() : "XOR32") + ")";
        }
    }

    // Проверка на ложную находку. Перебор может выдать ключ с парой случайных
    // стыков и НУЛЁМ якорей. Настоящий ключ даёт И стыки, И якоря: на всех
    // реальных сборках 5 стыков и 3+ якоря. Требуем оба признака.
    if (best.anchors == 0 && best.joins < MIN_CONFIDENT_JOINS) {
        throw MetadataError(
            "заголовок не поддался расшифровке.\n"
            "  лучший кандидат: " + best.describe() + "\n"
            "  Стыки секций есть, но по строковой секции не нашлось ни\n"
            "  одной обязательной строки — значит смещения ведут не туда.");
    }
    if (best.joins == 0 && best.anchors < 3) {
        throw MetadataError(
            "не удалось восстановить ключ шифрования.\n"
            "  лучший кандидат: " + best.describe() + "\n"
            "  Перебраны: XOR32, ADD32, SUB32, XOR со сдвигом, XOR с\n"
            "  зависимостью от позиции, отсутствие шифрования — ни одно\n"
            "  не дало связного заголовка.\n\n"
            "  Скорее всего, сменился сам способ шифрования (например,\n"
            "  на AES) — такой ключ из структуры заголовка не выводится,\n"
            "  его нужно доставать из кода расшифровки в libil2cpp.so.");
    }

    // Фиксируем результат. transform_ указывает внутрь transforms_, который
    // живёт вместе с объектом, поэтому указатель остаётся валиден.
    key_ = best.key;
    transform_ = best.transform;

    const char* tn = best.transform ? best.transform->name() : "XOR32";
    std::string rep;
    rep += "ключ восстановлен: " + hex(best.key, 8) + "\n";
    rep += "  метод: " + method + "\n";
    rep += "  преобразование: " + std::string(tn) + "\n";
    rep += "  " + best.describe();
    if (runner_up >= 0) {
        rep += "\n  отрыв от второго места: " +
               std::to_string(best.score() - runner_up);
    }
    if (best.key == 0 && best.transform == nullptr) {
        rep += "\n  (шифрование отсутствует)";
    }
    key_report_ = rep;
}

u32 Metadata::field(u32 off) const noexcept {
    if (off + 4 > v_.size) return 0;
    const u32 v = v_.read_u32(off);
    return transform_ == nullptr ? (v ^ key_) : transform_->decode(v, key_, off);
}

std::string Metadata::cstr(u32 base, u32 idx) const {
    return v_.cstr(base, idx);
}

std::vector<Section> Metadata::sections() const {
    // Все непустые секции: size>0 и целиком внутри файла. Сортируем по offset.
    std::vector<Section> out;
    const u32 end = hdr_end();
    const u32 n = static_cast<u32>(v_.size);
    for (u32 off = HDR_START; off + 8 <= end && off + 8 <= v_.size; off += 8) {
        const u32 o = field(off);
        const u32 s = field(off + 4);
        if (s > 0 && o >= 0x100 && o < n && o + s <= n) {
            out.push_back({off, o, s});
        }
    }
    std::sort(out.begin(), out.end(),
              [](const Section& a, const Section& b) { return a.offset < b.offset; });
    return out;
}

} // namespace oxdump::metadata
