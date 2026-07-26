// oxdump/metadata/tdlayout.cpp — вывод раскладки Il2CppTypeDefinition.
//
// Калька с tdlayout.py. Все инварианты и замеренные пороги перенесены вместе
// с причинами: например, fieldCount на +0x3E найден замощением (22 241
// совпадение, 0 расхождений), а прежняя эвристика «разность fieldStart
// соседей» ошибалась на 12.2% типов.
#include "oxdump/metadata/tdlayout.h"
#include <algorithm>
#include <vector>

namespace oxdump::metadata {

namespace {

// Сколько типов брать в выборку при проверке инвариантов.
constexpr u32 TD_SAMPLE = 300;

// Размеры записей таблиц метаданных IL2CPP. По размеру секции, делённому на
// число записей, однозначно определяется, что это за таблица. Параметры тоже
// 12 байт — различаются по привязке, не по размеру.
struct RecordKind { u32 size; const char* kind; };
const RecordKind RECORD_SIZES[] = {
    {32, "method"}, {20, "property"}, {16, "event"},
    {12, "field"}, {8, "interface_offset"}, {4, "nested"},
};

s32 read_s32(ByteView v, u32 base, u32 i, u32 rec, u32 off) noexcept {
    return v.read_s32(base + i * rec + off);
}
u16 read_u16(ByteView v, u32 base, u32 i, u32 rec, u32 off) noexcept {
    return v.read_u16(base + i * rec + off);
}

std::string hx2(s32 v) {
    return v < 0 ? std::string("—") : hex(static_cast<u32>(v), 2);
}

} // namespace

std::string TDLayout::report() const {
    const char* src = derived ? "выведена из данных"
                              : "значения по умолчанию (v39)";
    std::string s;
    s += "раскладка Il2CppTypeDefinition: " + std::string(src) + "\n";
    s += "  размер записи : " + std::to_string(rec_size) + "\n";
    s += "  name          : " + hx2(name) + "\n";
    s += "  byvalType     : " + hx2(byval_type) + "\n";
    s += "  fieldStart    : " + hx2(field_start) +
         "   fieldCount  : " + hx2(field_count) + "\n";
    s += "  methodStart   : " + hx2(method_start) +
         "   methodCount : " + hx2(method_count);
    for (const std::string& n : notes) s += "\n  " + n;
    return s;
}

TDLayout default_v39() {
    TDLayout L;
    L.rec_size = 82;
    L.name = 0x00;
    L.namespace_off = 0x04;
    L.byval_type = 0x08;
    L.declaring = 0x0C;
    L.parent = 0x10;
    L.flags = 0x16;
    L.field_start = 0x1A;
    L.method_start = 0x1E;
    L.method_count = 0x3A;
    // Найдено замощением: раньше считалось, что счётчика полей нет.
    L.field_count = 0x3E;
    L.derived = false;
    return L;
}

namespace {

// Имя типа: непустое, разумной длины, печатный ASCII.
bool is_good_name(const std::string& s) noexcept {
    if (s.empty() || s.size() > 128) return false;
    for (unsigned char c : s) if (c < 32 || c >= 127) return false;
    return true;
}

// Размеры записи, при которых по началу каждой читается имя класса. Лучший
// первым (обычно он один).
std::vector<u32> detect_rec_size(const Metadata& md, u32 sec_off, u32 sec_size,
                                 u32 string_off, u32 string_size) {
    struct Cand { double ratio; u32 count; u32 rec; };
    std::vector<Cand> out;
    for (u32 rec = TD_REC_MIN; rec <= TD_REC_MAX; ++rec) {
        if (sec_size % rec) continue;
        const u32 count = sec_size / rec;
        if (count < 100) continue;
        u32 good = 0, total = 0;
        const u32 lim = std::min<u32>(count, 200);
        for (u32 i = 0; i < lim; ++i) {
            const u32 p = sec_off + i * rec;
            if (p + 4 > md.size()) break;
            ++total;
            const u32 ni = md.u32_at(p);
            if (ni >= string_size) continue;
            if (is_good_name(md.cstr(string_off, ni))) ++good;
        }
        if (total && static_cast<double>(good) / total >= 0.90) {
            out.push_back({static_cast<double>(good) / total, count, rec});
        }
    }
    // По убыванию: ratio, потом count, потом rec — как reverse=True в Python.
    std::sort(out.begin(), out.end(), [](const Cand& a, const Cand& b) {
        if (a.ratio != b.ratio) return a.ratio > b.ratio;
        if (a.count != b.count) return a.count > b.count;
        return a.rec > b.rec;
    });
    std::vector<u32> recs;
    for (const Cand& c : out) recs.push_back(c.rec);
    return recs;
}

// Смещение byvalType: то, что замыкает петлю обратно на свой typedef.
// Возвращает (смещение, доля_попаданий); смещение -1, если ниже 0.5.
std::pair<s32, double> detect_byval(const Metadata& md, const binary::BinaryImage& img,
                                    ByteView bin, u32 sec_off, u32 count,
                                    u32 rec, u64 types_va, u64 types_count) {
    const u32 step = std::max<u32>(1, count / 120);
    s32 best = -1;
    double best_ratio = 0.0;
    for (u32 off = 0; off + 3 < rec; off += 2) {
        u32 hits = 0, total = 0;
        for (u32 i = 0; i < count; i += step) {
            const u32 p = sec_off + i * rec + off;
            if (p + 4 > md.size()) break;
            ++total;
            const u32 tidx = md.u32_at(p);
            if (tidx >= types_count) continue;
            const u64 type_va = img.ptr(types_va + tidx * 8);
            const auto fo = img.va2fo(type_va);
            if (!fo || *fo + 8 > bin.size) continue;
            if ((bin.read_u64(*fo) & 0xFFFFFFFF) == i) ++hits;
        }
        if (total) {
            const double r = static_cast<double>(hits) / total;
            if (r > best_ratio) { best_ratio = r; best = static_cast<s32>(off); }
        }
    }
    if (best_ratio >= 0.5) return {best, best_ratio};
    return {-1, best_ratio};
}

// Одна замощающая пара: доля стыков, смещения start/count, макс start.
struct TilingPair { double ratio; u32 start_off; u32 count_off; s32 max_start; };

// Все пары (start:s32, count:u16), замощающие непрерывную таблицу.
std::vector<TilingPair> detect_tiling_pairs(const Metadata& md, u32 sec_off,
                                            u32 count, u32 rec) {
    const ByteView v = md.bytes();
    const u32 n = std::min<u32>(count, 8000);

    // Кандидаты в start: знаковое поле, ≥25% неотрицательных, максимум в
    // разумных пределах для таблицы метаданных.
    struct Field { u32 off; std::vector<s32> vals; };
    std::vector<Field> starts;
    for (u32 off = 0; off + 3 < rec; ++off) {
        std::vector<s32> vals(n);
        u32 nz = 0;
        s32 mx = 0;
        for (u32 i = 0; i < n; ++i) {
            const s32 x = read_s32(v, sec_off, i, rec, off);
            vals[i] = x;
            if (x >= 0) { ++nz; if (x > mx) mx = x; }
        }
        if (nz < n * 0.25 || nz == 0) continue;
        if (mx > 100 && mx < 20000000) starts.push_back({off, std::move(vals)});
    }

    // Кандидаты в count: беззнаковое короткое, значения небольшие.
    struct FieldU { u32 off; std::vector<u16> vals; };
    std::vector<FieldU> counts;
    for (u32 off = 0; off + 1 < rec; ++off) {
        std::vector<u16> vals(n);
        u16 mx = 0;
        u32 pos = 0;
        for (u32 i = 0; i < n; ++i) {
            const u16 x = read_u16(v, sec_off, i, rec, off);
            vals[i] = x;
            if (x > mx) mx = x;
            if (x > 0) ++pos;
        }
        if (mx < 4000 && pos > n * 0.25) counts.push_back({off, std::move(vals)});
    }

    std::vector<TilingPair> found;
    for (const Field& sf : starts) {
        for (const FieldU& cf : counts) {
            if (cf.off == sf.off) continue;
            std::vector<std::pair<s32, u16>> pairs;
            pairs.reserve(n);
            for (u32 i = 0; i < n; ++i) {
                if (sf.vals[i] >= 0) pairs.emplace_back(sf.vals[i], cf.vals[i]);
            }
            if (pairs.size() < 100) continue;
            std::sort(pairs.begin(), pairs.end());
            u32 joins = 0;
            for (std::size_t i = 1; i < pairs.size(); ++i) {
                if (pairs[i - 1].first + pairs[i - 1].second == pairs[i].first) {
                    ++joins;
                }
            }
            const double ratio =
                static_cast<double>(joins) / (pairs.size() - 1);
            if (ratio >= TD_TILE_THRESHOLD) {
                s32 mx = 0;
                for (const auto& p : pairs) mx = std::max(mx, p.first);
                found.push_back({ratio, sf.off, cf.off, mx});
            }
        }
    }
    // По размеру таблицы, на которую ссылается пара: методов больше всего.
    std::sort(found.begin(), found.end(),
              [](const TilingPair& a, const TilingPair& b) {
                  return a.max_start > b.max_start;
              });
    return found;
}

// Сколько всего записей в таблице, на которую ссылается пара.
u32 table_total(const Metadata& md, u32 sec_off, u32 count, u32 rec,
                u32 start_off, u32 count_off) {
    const ByteView v = md.bytes();
    u32 total = 0;
    for (u32 i = 0; i < count; ++i) {
        const u32 p = sec_off + i * rec;
        const s32 s = v.read_s32(p + start_off);
        if (s < 0) continue;
        const u16 c = v.read_u16(p + count_off);
        const u32 sum = static_cast<u32>(s) + c;
        if (sum > total) total = sum;
    }
    return total;
}

// Итог опознания: назначение таблицы -> (start_off, count_off, total, ratio).
struct IdentPair { s32 start_off = -1; s32 count_off = -1; u32 total = 0; double ratio = 0.0; };

// Отсеивает случайные замощения, привязывая каждое к реальной секции.
// Настоящая пара описывает существующую таблицу: max(start+count) — число её
// записей, и в файле есть секция ровно `число_записей * размер_записи`.
std::vector<std::pair<std::string, IdentPair>>
identify_pairs(const Metadata& md, u32 sec_off, u32 count, u32 rec,
               const std::vector<TilingPair>& pairs) {
    std::vector<u32> sizes;
    for (const Section& sec : md.sections()) sizes.push_back(sec.size);

    std::vector<std::pair<std::string, IdentPair>> out;
    auto find = [&out](const std::string& kind) -> IdentPair* {
        for (auto& kv : out) if (kv.first == kind) return &kv.second;
        return nullptr;
    };

    for (const TilingPair& tp : pairs) {
        const u32 total = table_total(md, sec_off, count, rec,
                                      tp.start_off, tp.count_off);
        if (total == 0) continue;
        for (const RecordKind& rk : RECORD_SIZES) {
            const u64 want = static_cast<u64>(total) * rk.size;
            bool has = false;
            for (u32 sz : sizes) if (sz == want) { has = true; break; }
            if (!has) continue;
            // Одну и ту же таблицу могут описать две пары — берём точнее.
            IdentPair* prev = find(rk.kind);
            if (!prev) {
                out.push_back({rk.kind, IdentPair{static_cast<s32>(tp.start_off),
                              static_cast<s32>(tp.count_off), total, tp.ratio}});
            } else if (tp.ratio > prev->ratio) {
                *prev = IdentPair{static_cast<s32>(tp.start_off),
                                  static_cast<s32>(tp.count_off), total, tp.ratio};
            }
            break;
        }
    }
    return out;
}

// Смещения parent / declaring — по разрешимости через types[]. Оба индексы в
// types[], оба принимают -1; различает доля -1 (у declaring большинство, у
// parent единицы) и доля разрешимых.
std::pair<s32, s32> detect_type_refs(const Metadata& md, const Layout& layout,
                                     const binary::BinaryImage& img, ByteView bin,
                                     const binary::MetadataRegistrationCandidate& mr,
                                     u32 rec, const std::vector<s32>& exclude) {
    const u64 tv = mr.types;
    const u64 tc = mr.types_count;
    const u32 tdc = layout.typedef_count;
    const u32 N = std::min<u32>(tdc, 1500);
    const ByteView v = md.bytes();

    auto resolves = [&](s32 tidx) -> bool {
        if (tidx < 0 || static_cast<u64>(tidx) >= tc) return false;
        const u64 type_va = img.ptr(tv + static_cast<u64>(tidx) * 8);
        const auto fo = img.va2fo(type_va);
        if (!fo || *fo + 12 > bin.size) return false;
        // Il2CppType: тег типа в байте (data+8)>>16. Класс/структура = 0x11/0x12.
        const u32 tag = (bin.read_u32(*fo + 8) >> 16) & 0xFF;
        if (tag != 0x11 && tag != 0x12) return false;
        const u64 ti = bin.read_u64(*fo) & 0xFFFFFFFF;
        if (ti >= tdc) return false;
        const u32 ni = md.u32_at(layout.typedef_offset +
                                 static_cast<u32>(ti) * rec);
        return !md.cstr(layout.string_offset, ni).empty();
    };

    struct Scored { double ratio; double negr; u32 off; };
    std::vector<Scored> scored;
    for (u32 off = 0; off + 3 < rec; ++off) {
        // Уже опознанные поля пропускаем: byvalType тоже разрешается через
        // types[] и без исключения выигрывал у parent.
        if (std::find(exclude.begin(), exclude.end(), static_cast<s32>(off)) !=
            exclude.end()) {
            continue;
        }
        u32 good = 0, neg = 0;
        for (u32 i = 0; i < N; ++i) {
            const u32 p = layout.typedef_offset + i * rec + off;
            if (p + 4 > md.size()) break;
            const s32 x = v.read_s32(p);
            if (x == -1) { ++neg; ++good; }
            else if (resolves(x)) ++good;
        }
        scored.push_back({static_cast<double>(good) / N,
                          static_cast<double>(neg) / N, off});
    }

    // declaring: почти всё разрешается, большинство значений -1.
    s32 decl = -1;
    double best = 0.0;
    for (const Scored& s : scored) {
        if (s.ratio > 0.95 && s.negr > 0.5 && s.negr < 0.98 && s.ratio > best) {
            best = s.ratio;
            decl = static_cast<s32>(s.off);
        }
    }
    // parent: разрешается хуже (родитель бывает generic/интерфейсом), но -1
    // почти нет.
    s32 par = -1;
    best = 0.0;
    for (const Scored& s : scored) {
        if (static_cast<s32>(s.off) == decl) continue;
        if (s.negr < 0.30 && s.ratio > best && s.ratio > 0.35) {
            best = s.ratio;
            par = static_cast<s32>(s.off);
        }
    }
    return {par, decl};
}

// Смещение flags — по битовой структуре TypeAttributes. Честное ограничение:
// признак слаб, настоящее поле стабильно на втором месте. Возвращаем -1, если
// уверенного победителя нет.
s32 detect_flags(const Metadata& md, const Layout& layout, u32 rec,
                 const std::vector<std::pair<s32, u32>>& known) {
    const u32 N = std::min<u32>(layout.typedef_count, 3000);
    const ByteView v = md.bytes();

    // Байты, занятые уже опознанными полями: флаги там лежать не могут, а как
    // кандидаты выигрывают (0x05, 0x04 — это namespace).
    std::vector<bool> occupied(rec, false);
    for (const auto& bw : known) {
        if (bw.first < 0) continue;
        for (u32 k = 0; k < bw.second; ++k) {
            const u32 idx = static_cast<u32>(bw.first) + k;
            if (idx < rec) occupied[idx] = true;
        }
    }

    s32 best = -1;
    double best_score = 0.0;
    for (u32 off = 0; off + 1 < rec; ++off) {
        if (occupied[off]) continue;
        std::vector<u16> vals;
        vals.reserve(N);
        for (u32 i = 0; i < N; ++i) {
            const u32 p = layout.typedef_offset + i * rec + off;
            if (p + 2 > md.size()) break;
            vals.push_back(v.read_u16(p));
        }
        if (vals.empty()) continue;

        u32 iface_c = 0, vis_c = 0, small_c = 0, ffff_c = 0;
        for (u16 x : vals) {
            if (x & 0x20) ++iface_c;
            if ((x & 0x7) <= 2) ++vis_c;  // visibility 0/1/2 — самые частые
            if (x <= 0xFFF) ++small_c;
            if (x == 0xFFFF) ++ffff_c;
        }
        const double iface = static_cast<double>(iface_c) / vals.size();
        const double vis = static_cast<double>(vis_c) / vals.size();
        const double small = static_cast<double>(small_c) / vals.size();

        // РАЗНООБРАЗИЕ: флаги — комбинации битов, разных значений десятки.
        // Служебные поля («есть/нет») дают 2-3 значения и проходят битовые
        // проверки, но не это.
        std::vector<u16> uniq = vals;
        std::sort(uniq.begin(), uniq.end());
        uniq.erase(std::unique(uniq.begin(), uniq.end()), uniq.end());
        if (uniq.size() < 8) continue;

        // 0xFFFF — заполнитель, не маска атрибутов.
        if (static_cast<double>(ffff_c) / vals.size() > 0.2) continue;

        const double score =
            vis * small * ((iface > 0.01 && iface < 0.35) ? 1.0 : 0.1);
        if (score > best_score) {
            best_score = score;
            best = static_cast<s32>(off);
        }
    }
    return best;
}

} // namespace

TDLayout detect(const Metadata& md, const Layout& layout,
                const binary::BinaryImage& img, ByteView bin,
                const binary::MetadataRegistrationCandidate& mr,
                const TDLayout* fallback) {
    TDLayout L;
    const u32 sec_off = layout.typedef_offset;
    const u32 count = layout.typedef_count;

    // ── 1. размер записи ─────────────────────────────────────────────────
    const u32 fb_rec = fallback ? fallback->rec_size : 82;
    const u32 sec_size = count * fb_rec;
    std::vector<u32> recs = detect_rec_size(md, sec_off, sec_size,
                                            layout.string_offset,
                                            layout.string_size);
    if (!recs.empty()) {
        L.rec_size = recs[0];
        if (recs.size() > 1) {
            std::string list;
            for (std::size_t i = 0; i < recs.size(); ++i) {
                if (i) list += ", ";
                list += std::to_string(recs[i]);
            }
            L.notes.push_back("размеры-кандидаты: [" + list + "] — взят первый");
        }
    } else {
        L.rec_size = fb_rec;
        L.notes.push_back("размер записи определить не удалось — взят обычный");
    }

    // ── 2. byvalType через замкнутую петлю ───────────────────────────────
    auto bv = detect_byval(md, img, bin, sec_off, count, L.rec_size,
                           mr.types, mr.types_count);
    if (bv.first >= 0) {
        L.byval_type = bv.first;
        L.notes.push_back("byvalType подтверждён петлёй: " +
                          std::to_string(static_cast<int>(bv.second * 100 + 0.5)) + "%");
    } else {
        L.byval_type = fallback ? fallback->byval_type : 0x08;
        L.notes.push_back("byvalType не подтвердился (лучшее " +
                          std::to_string(static_cast<int>(bv.second * 100 + 0.5)) +
                          "%) — взято обычное значение");
    }

    // ── 3. пары start/count по замощению + привязка к секциям ────────────
    auto pairs = detect_tiling_pairs(md, sec_off, count, L.rec_size);
    auto ident = identify_pairs(md, sec_off, count, L.rec_size, pairs);
    auto get = [&ident](const char* kind) -> const IdentPair* {
        for (const auto& kv : ident) if (kv.first == kind) return &kv.second;
        return nullptr;
    };

    if (!pairs.empty() && ident.empty()) {
        L.notes.push_back("замощающих пар найдено " +
                          std::to_string(pairs.size()) +
                          ", но ни одна не привязалась к реальной секции");
    }

    if (const IdentPair* m = get("method")) {
        L.method_start = m->start_off;
        L.method_count = m->count_off;
        L.notes.push_back("методы: start=" + hex(m->start_off, 2) +
                          " count=" + hex(m->count_off, 2) + " → " +
                          thousands(m->total) + " записей");
    }
    if (const IdentPair* f = get("field")) {
        L.field_start = f->start_off;
        L.field_count = f->count_off;
        L.notes.push_back("поля:   start=" + hex(f->start_off, 2) +
                          " count=" + hex(f->count_off, 2) + " → " +
                          thousands(f->total) + " записей");
    }
    for (const char* kind : {"property", "event"}) {
        if (const IdentPair* k = get(kind)) {
            L.notes.push_back(std::string(kind) + ": start=" +
                              hex(k->start_off, 2) + " count=" +
                              hex(k->count_off, 2));
        }
    }

    // ── 4. parent / declaring / flags ────────────────────────────────────
    // byvalType и оба индекса имён исключаем: они тоже «разрешаются».
    std::vector<s32> known_refs = {L.name, L.namespace_off};
    if (L.byval_type >= 0) known_refs.push_back(L.byval_type);
    auto pd = detect_type_refs(md, layout, img, bin, mr, L.rec_size, known_refs);
    if (pd.second >= 0) {
        L.declaring = pd.second;
        L.notes.push_back("declaring: " + hex(pd.second, 2) +
                          " (разрешается через types[])");
    }
    if (pd.first >= 0) {
        L.parent = pd.first;
        L.notes.push_back("parent:    " + hex(pd.first, 2) +
                          " (разрешается через types[])");
    }

    // Ширины: индексы имён и типов по 4 байта, счётчики по 2.
    std::vector<std::pair<s32, u32>> occupied = {
        {L.name, 4}, {L.namespace_off, 4}, {L.byval_type, 4},
        {L.declaring, 4}, {L.parent, 4},
        {L.field_start, 4}, {L.method_start, 4},
        {L.field_count, 2}, {L.method_count, 2},
    };
    const s32 fl = detect_flags(md, layout, L.rec_size, occupied);
    if (fl >= 0) {
        L.flags = fl;
        L.notes.push_back("flags:     " + hex(fl, 2) + " (битовая структура)");
    }

    // Что не определилось — берём из fallback.
    if (fallback) {
        struct Ref { const char* name; s32* p; s32 v; };
        Ref refs[] = {
            {"field_start", &L.field_start, fallback->field_start},
            {"field_count", &L.field_count, fallback->field_count},
            {"method_start", &L.method_start, fallback->method_start},
            {"method_count", &L.method_count, fallback->method_count},
            {"parent", &L.parent, fallback->parent},
            {"declaring", &L.declaring, fallback->declaring},
            {"flags", &L.flags, fallback->flags},
        };
        for (const Ref& r : refs) {
            if (*r.p < 0) {
                *r.p = r.v;
                L.notes.push_back(std::string(r.name) + ": взято обычное значение");
            }
        }
    }

    L.derived = true;
    return L;
}

} // namespace oxdump::metadata
