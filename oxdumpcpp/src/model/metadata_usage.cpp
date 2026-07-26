// oxdump/model/metadata_usage.cpp — детект и разбор Il2CppMetadataUsage.
//
// Детект строго по СОДЕРЖИМОМУ, без опоры на позицию поля в заголовке (её у
// разных сборок разъезжает, а у обфусцированных секций может не быть вовсе).
// Логика в два шага с перекрёстной проверкой:
//
//   (1) metadataUsagePairs — Il2CppMetadataUsagePair[] {dest u32, enc u32}:
//         • enc: старшие 3 бита ∈ {1..6} практически у 100% записей (это вид
//           токена; случайные данные так себя не ведут — см. probe);
//         • dest: ПЛОТНЫЙ и УНИКАЛЬНЫЙ на всём файле — покрывает [0, count)
//           почти без дыр и без повторов (это индекс слота назначения).
//       Именно связка «enc — валидные виды» + «dest — плотная перестановка»
//       отличает настоящую таблицу от блоба флотов/строк, который по одному
//       лишь верхнему-3-бита критерию даёт ложное 85%.
//
//   (2) metadataUsageLists — Il2CppMetadataUsageList[] {start u32, count u32}:
//         • ровно method_count записей (по одной на метод);
//         • ЗАМОЩАЮТ таблицу пар: start[i]+count[i] == start[i+1] (с пропуском
//           методов без usage'ей), а Σcount == pair_count.
//
// Если хоть один шаг не сходится — usable()==false и честное пояснение в report.
// На агрессивно обфусцированных сборках (как Oxide Survival Island) эти секции
// вырезаны — детект вернёт «не найдено», и деобфускатор откатится на
// дизассемблер (analysis::build_hints).
#include "oxdump/model/metadata_usage.h"
#include <algorithm>
#include <vector>

namespace oxdump::model {

namespace {

// Секция файла как массив 8-байтных записей: (offset, count). Использует
// «настоящий» размер: у упакованных сборок stated size в заголовке раздут, а
// реальный обрезается ближайшим offset'ом справа (mirror-хак игры). Поэтому
// считаем размер по расстоянию до следующей секции, как это делает layout.
struct Rec8 {
    u32 offset;
    u32 count;
};

std::vector<Rec8> rec8_sections(const metadata::Metadata& md) {
    std::vector<metadata::Section> secs = md.sections();   // отсортированы по offset
    std::vector<Rec8> out;
    const u32 file_end = static_cast<u32>(md.size());
    for (std::size_t i = 0; i < secs.size(); ++i) {
        const u32 next = (i + 1 < secs.size()) ? secs[i + 1].offset : file_end;
        const u32 real = std::min(secs[i].size, next - secs[i].offset);
        if (real % 8 != 0) continue;
        const u32 c = real / 8;
        if (c < 8) continue;
        out.push_back({secs[i].offset, c});
    }
    return out;
}

// Оценка «похоже на metadataUsagePairs». Возвращает долю записей, чей enc даёт
// валидный вид (1..6), и заполняет плотность/уникальность dest.
struct PairScore {
    double kind_ok = 0.0;     // доля enc с видом 1..6
    double dest_cover = 0.0;  // доля [0,count), покрытая dest
    double dest_dup = 1.0;    // доля повторов среди dest (меньше — лучше)
};

PairScore score_pairs(const metadata::Metadata& md, const Rec8& s) {
    PairScore ps;
    const ByteView bv = md.bytes();
    const u32 c = s.count;
    // dest покрытие/повторы считаем по всей таблице (это дёшево: один u8 на слот).
    std::vector<u8> seen(static_cast<std::size_t>(c), 0);
    u32 kind_ok = 0, covered = 0, dups = 0;
    for (u32 i = 0; i < c; ++i) {
        const u32 dest = bv.read_u32(s.offset + i * 8);
        const u32 enc  = bv.read_u32(s.offset + i * 8 + 4);
        if (usage_kind(enc) != MetadataUsageKind::Invalid) ++kind_ok;
        if (dest < c) {
            if (seen[dest]) ++dups;
            else { seen[dest] = 1; ++covered; }
        }
    }
    ps.kind_ok = static_cast<double>(kind_ok) / c;
    ps.dest_cover = static_cast<double>(covered) / c;
    ps.dest_dup = static_cast<double>(dups) / c;
    return ps;
}

// Порог «настоящей» таблицы пар. enc-виды почти у всех записей; dest — почти
// полная перестановка [0,count): высокое покрытие и почти без повторов.
constexpr double PAIR_KIND_MIN = 0.98;
constexpr double PAIR_COVER_MIN = 0.90;
constexpr double PAIR_DUP_MAX = 0.02;

} // namespace

MetadataUsageTable MetadataUsageTable::detect(const metadata::Metadata& md,
                                              const metadata::Layout& L) {
    MetadataUsageTable t;
    const ByteView bv = md.bytes();
    const std::vector<Rec8> secs = rec8_sections(md);

    // ── шаг 1: пары ─────────────────────────────────────────────────────────
    // Берём лучшую по всем трём критериям сразу. Настоящая таблица одна; если
    // ни одна не проходит порог — тем и заканчиваем (usable остаётся false).
    u32 pairs_off = 0, pairs_cnt = 0;
    double best = -1.0;
    for (const Rec8& s : secs) {
        // Таблица пар большая (сотни тысяч на крупной игре) — мелочь не она.
        if (s.count < 1000) continue;
        const PairScore ps = score_pairs(md, s);
        if (ps.kind_ok < PAIR_KIND_MIN) continue;
        if (ps.dest_cover < PAIR_COVER_MIN) continue;
        if (ps.dest_dup > PAIR_DUP_MAX) continue;
        // Ранжируем по покрытию dest минус штраф за повторы: у настоящей
        // перестановки покрытие ~1.0, повторов ~0.
        const double rank = ps.dest_cover - ps.dest_dup;
        if (rank > best) { best = rank; pairs_off = s.offset; pairs_cnt = s.count; }
    }

    if (!pairs_off) {
        t.report_ =
            "usage-таблицы: metadataUsagePairs не опознаны — ни одна секция\n"
            "  rec=8 не имеет плотного уникального destinationIndex с валидными\n"
            "  видами токенов. На этой сборке таблицы, судя по всему, вырезаны\n"
            "  обфускатором (характерно для v29+/защищённых игр). Деобфускация\n"
            "  откатывается на дизассемблер (--xref-names).";
        return t;
    }

    // ── шаг 2: списки ───────────────────────────────────────────────────────
    // Ровно method_count записей {start,count}, замощающих таблицу пар.
    u32 lists_off = 0, lists_cnt = 0;
    for (const Rec8& s : secs) {
        if (s.offset == pairs_off) continue;
        // Разрешаем небольшой люфт по числу записей: у части сборок хвост
        // таблицы чуть длиннее числа методов.
        if (L.method_count == 0) break;
        if (s.count < L.method_count || s.count > L.method_count + 64) continue;

        // Проверяем замощение: перебираем записи, у которых count>0, и требуем
        // start[i]+count[i] == start[следующей ненулевой]. Σcount ≈ pair_count.
        u64 sum = 0;
        u32 tile_ok = 0, tile_tot = 0;
        s64 prev_end = -1;
        bool sane = true;
        for (u32 i = 0; i < s.count && sane; ++i) {
            const u32 start = bv.read_u32(s.offset + i * 8);
            const u32 cnt   = bv.read_u32(s.offset + i * 8 + 4);
            if (cnt == 0) continue;
            // start/count обязаны лежать внутри таблицы пар.
            if (static_cast<u64>(start) + cnt > pairs_cnt) { sane = false; break; }
            sum += cnt;
            if (prev_end >= 0) {
                ++tile_tot;
                if (static_cast<s64>(start) == prev_end) ++tile_ok;
            }
            prev_end = static_cast<s64>(start) + cnt;
        }
        if (!sane) continue;
        const double tile_ratio =
            tile_tot ? static_cast<double>(tile_ok) / tile_tot : 0.0;
        // Замощение почти идеальное и суммарное число usage'ей совпадает с
        // числом пар (в пределах небольшого люфта).
        const bool sum_ok =
            sum <= pairs_cnt && sum + pairs_cnt / 20 + 16 >= pairs_cnt;
        if (tile_ratio >= 0.95 && sum_ok) {
            lists_off = s.offset;
            lists_cnt = s.count;
            break;
        }
    }

    if (!lists_off) {
        t.pairs_offset_ = pairs_off;
        t.pair_count_ = pairs_cnt;
        t.report_ =
            "usage-таблицы: найдены пары (offset=" + hex(pairs_off) + ", " +
            thousands(pairs_cnt) + "), но metadataUsageLists с " +
            thousands(L.method_count) + " замощающими записями нет —\n"
            "  без списков привязка usage→метод невозможна. Таблица не введена.";
        return t;
    }

    // ── разбор ───────────────────────────────────────────────────────────────
    t.pairs_offset_ = pairs_off;
    t.pair_count_ = pairs_cnt;
    t.lists_offset_ = lists_off;
    t.list_count_ = lists_cnt;

    t.pairs_.resize(pairs_cnt);
    for (u32 i = 0; i < pairs_cnt; ++i) {
        const u32 dest = bv.read_u32(pairs_off + i * 8);
        const u32 enc  = bv.read_u32(pairs_off + i * 8 + 4);
        MetadataUsage u;
        u.kind = usage_kind(enc);
        u.destination_index = dest;
        u.target_index = usage_index(enc);
        t.pairs_[i] = u;
    }
    t.lists_.resize(lists_cnt);
    for (u32 i = 0; i < lists_cnt; ++i) {
        MethodUsages mu;
        mu.start = bv.read_u32(lists_off + i * 8);
        mu.count = bv.read_u32(lists_off + i * 8 + 4);
        t.lists_[i] = mu;
    }

    t.usable_ = true;
    t.report_ =
        "usage-таблицы: ОПОЗНАНЫ\n"
        "  metadataUsageLists @ " + hex(lists_off) + "  (" +
        thousands(lists_cnt) + " методов)\n"
        "  metadataUsagePairs @ " + hex(pairs_off) + "  (" +
        thousands(pairs_cnt) + " usage'ей)";
    return t;
}

std::vector<MetadataUsage> MetadataUsageTable::for_method(u32 method_index) const {
    std::vector<MetadataUsage> out;
    if (!usable_ || method_index >= lists_.size()) return out;
    const MethodUsages& mu = lists_[method_index];
    if (mu.count == 0) return out;
    const u32 end = std::min<u32>(mu.start + mu.count,
                                  static_cast<u32>(pairs_.size()));
    if (mu.start >= pairs_.size()) return out;
    out.reserve(end - mu.start);
    for (u32 i = mu.start; i < end; ++i) out.push_back(pairs_[i]);
    return out;
}

MetadataUsage MetadataUsageTable::at(u32 dest_index) const {
    if (usable_ && dest_index < pairs_.size()) return pairs_[dest_index];
    return MetadataUsage{};
}

u32 MetadataUsageTable::kind_count(MetadataUsageKind k) const noexcept {
    if (!usable_) return 0;
    u32 n = 0;
    for (const MetadataUsage& u : pairs_) if (u.kind == k) ++n;
    return n;
}

} // namespace oxdump::model
