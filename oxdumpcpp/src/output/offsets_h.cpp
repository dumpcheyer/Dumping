// oxdump/output/offsets_h.cpp — генерация offsets.h, offsets.cs, types.txt.
//
// Это то, чего нет в стандартном Il2CppDumper: сразу пригодные к вставке в чит
// константы (TDI, type-index) и смещения ВСЕХ полей важных классов — по имени,
// а не текстом, который нужно разбирать глазами. offsets.h задуман как «один
// файл, который вставил и работаешь»:
//
//   #include "offsets.h"
//   uintptr_t player = ...;
//   auto* transform = *(void**)(player + ox::PlayerManager::worldCameraRoot);
//
// «Шапка» (константы вида PLAYERMANAGER_TDI / PLAYERMANAGER_TYPE_IDX) сохранена
// байт-в-байт в прежнем формате — под неё заточены грепы, диффы и integration-
// тест. Всё новое (namespace-блоки по классу, sizeof-оценка, offsets.cs,
// types.txt) добавлено СВЕРХУ, ничего старого не убрано.
//
// Обфускация. В этой сборке имена вида nqW, Qw, sA, ncK, cWw, NpA, AAB — мусор
// от обфускатора (короткие случайные последовательности с нетипичным регистром
// и без гласных). Их отфильтровываем эвристикой looks_obfuscated(): в
// namespace-блоках такое поле получает синтетическое имя fieldN, а исходное имя
// уходит в комментарий как fallback (// nqW). Читаемые короткие имена (id, key,
// min, max, url, pos, dir...) сохраняем по curated-списку.
#include "oxdump/output/generators.h"
#include "oxdump/analysis/xref.h"
#include <algorithm>
#include <unordered_set>

namespace oxdump::output {

namespace {

// ── целевые классы ───────────────────────────────────────────────────────────
// Канонический набор. Порядок важен: под первые совпадения заточены грепы,
// диффы и контрольная проверка отчёта/теста. Расширенный список (namespace-ы,
// топ по числу полей) добавляется в select_targets() ПОСЛЕ этих.
const char* const TARGETS[] = {
    "PlayerManager", "BuildingPiece", "MouseLook", "KCC", "NetworkIdentity",
    "PlayerInventory", "PlayerHealth", "PlayerVitals", "RaycastManager",
    "FPManager",
};

// Сколько классов добавить «топом по числу полей» сверх namespace-выборки.
constexpr std::size_t TOP_BY_FIELDS = 30;
// Классы с меньшим числом полей в расширенную выборку не берём — держит файл
// компактным (ТЗ: под ~200 КБ, опускать типы с < 3 полей).
constexpr u32 MIN_FIELDS = 3;

// ── строковые утилиты ────────────────────────────────────────────────────────

// Верхний регистр (PlayerManager -> PLAYERMANAGER) — для имён шапки-констант.
std::string upper(const std::string& s) {
    std::string o = s;
    for (char& c : o) if (c >= 'a' && c <= 'z') c = static_cast<char>(c - 32);
    return o;
}

// Идентификатор, пригодный для C/C++/C#: не-[A-Za-z0-9_] -> '_', ведущая
// цифра префиксуется подчёркиванием.
std::string sanitize(const std::string& name) {
    std::string s;
    s.reserve(name.size());
    for (char ch : name) {
        const bool ok = (ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z') ||
                        (ch >= '0' && ch <= '9') || ch == '_';
        s += ok ? ch : '_';
    }
    if (s.empty() || (s[0] >= '0' && s[0] <= '9')) s = "_" + s;
    return s;
}

// PascalCase для имени C#-константы: worldCameraRoot -> WorldCameraRoot.
// Сначала санитайзим, затем поднимаем первую букву. Пустое/цифра -> как есть
// (sanitize уже добавил '_').
std::string pascal(const std::string& name) {
    std::string s = sanitize(name);
    if (!s.empty() && s[0] >= 'a' && s[0] <= 'z') s[0] = static_cast<char>(s[0] - 32);
    return s;
}

// Смещение как "0xNN", дополненное пробелами до ширины колонки w (считая "0x").
std::string off_col(u32 v, int w) {
    std::string h = hex(v);
    while (static_cast<int>(h.size()) < w) h += " ";
    return h;
}

// ── эвристика обфускации ─────────────────────────────────────────────────────

bool has_vowel(const std::string& s) {
    for (char c : s) {
        const char l = (c >= 'A' && c <= 'Z') ? static_cast<char>(c + 32) : c;
        if (l == 'a' || l == 'e' || l == 'i' || l == 'o' || l == 'u' || l == 'y')
            return true;
    }
    return false;
}

int case_changes(const std::string& s) {
    int ch = 0;
    for (std::size_t i = 1; i < s.size(); ++i) {
        const bool a = s[i - 1] >= 'A' && s[i - 1] <= 'Z';
        const bool b = s[i]     >= 'A' && s[i]     <= 'Z';
        if (a != b) ++ch;
    }
    return ch;
}

// Короткие, но настоящие имена, которые обфускатор бы «прошёл»: держим их явно,
// чтобы не выкинуть полезное (id, key, min, max, pos, dir, x/y/z ...).
bool short_allowlist(const std::string& n) {
    static const std::unordered_set<std::string> ok = {
        "id","ok","to","up","dx","dy","dz","hp","xp","ui","io","db",
        "x","y","z","w","r","g","b","a",
        "key","min","max","url","ctx","tag","pos","dir","idx","end","off",
        "log","all","any","low","top","add","new","old","map","get","set",
        "sum","raw","buf","len","num","cur","src","dst","rot","col","row",
        "age","bit","cmd","msg","net","gui","obj","arr","str","val","ptr",
        "fov","ray","hit","cam","uid","rpc","seq","fps","lod","aim",
    };
    return ok.count(n) != 0;
}

// Похоже ли имя на мусор обфускатора? Обфусцированные имена в этой сборке —
// короткие случайные последовательности букв с нетипичным регистром/без
// гласных (nqW, Qw, sA, ncK, cWw, NpA, AAB, ABC...). Длинные (>=5) имена
// считаем настоящими всегда.
bool looks_obfuscated(const std::string& n) {
    if (n.size() >= 5) return false;
    int letters = 0;
    for (char c : n)
        if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')) ++letters;
    if (letters == 0) return false;             // только цифры/подчёркивания — не трогаем
    if (short_allowlist(n)) return false;       // настоящее короткое имя
    const int cc = case_changes(n);
    const bool starts_upper = n[0] >= 'A' && n[0] <= 'Z';
    if (n.size() == 1) return true;             // одиночная буква не из allowlist
    if (!has_vowel(n)) return true;             // Qw, sA, nqW ...
    if (cc >= 1 && n.size() <= 4) return true;  // ncK, cWw, NpA, AAb ...
    if (starts_upper && n.size() <= 3) return true; // AAA, ABC ...
    return false;
}

// ── выборка целевых классов ──────────────────────────────────────────────────

// Один выбранный класс: индекс typedef, короткое и полное имя.
struct Target {
    std::string name;     // короткое имя (для namespace/struct/константы)
    std::string full;     // полное имя (для комментария)
    s32 idx = -1;
};

// Попадает ли namespace под расширенную выборку (Oxide, Oxide.*,
// HyperHug.Games.Oxide и его под-namespace-ы, Mirror, Mirror.*).
bool wanted_namespace(const std::string& ns) {
    auto is_or_under = [&](const char* p) {
        const std::string pre = p;
        if (ns == pre) return true;
        return ns.size() > pre.size() &&
               ns.compare(0, pre.size(), pre) == 0 && ns[pre.size()] == '.';
    };
    return is_or_under("Oxide") || is_or_under("HyperHug.Games.Oxide") ||
           is_or_under("Mirror");
}

// Собрать итоговый список целевых классов.
//  1. Фиксированный TARGETS (в исходном порядке; сохраняет и «НЕ НАЙДЕН»).
//  2. Все типы нужных namespace-ов c >= MIN_FIELDS полей.
//  3. Топ-TOP_BY_FIELDS классов по числу полей (по всей сборке), c >= MIN_FIELDS.
// Дубликаты (по индексу typedef) отсекаются; порядок 2/3 — по полному имени.
struct Selection {
    std::vector<Target> fixed;    // TARGETS, ok или «НЕ НАЙДЕН» (idx==-1)
    std::vector<Target> extra;    // namespace + топ, уникальные, без fixed
};

Selection select_targets(model::Model& m) {
    auto& L = m.layout();
    const u32 total = L.typedef_count;

    Selection sel;

    // (1) фиксированные — первое вхождение по короткому имени.
    struct Fx { std::string name; s32 idx; bool ok; };
    std::vector<Fx> fx;
    for (const char* t : TARGETS) fx.push_back({t, -1, false});

    // Один проход: заполняем fixed-индексы и параллельно копим кандидатов
    // расширенной выборки (namespace + число полей для топа).
    struct Cand { s32 idx; u32 fields; std::string full; };
    std::vector<Cand> ns_cands;      // из нужных namespace-ов
    std::vector<Cand> all_cands;     // все с >= MIN_FIELDS (для топа)

    for (u32 i = 0; i < total; ++i) {
        const std::string nm = m.td_name(i);
        if (nm.empty()) continue;
        for (auto& f : fx)
            if (!f.ok && f.name == nm) { f.idx = static_cast<s32>(i); f.ok = true; }

        const u32 fcount = m.field_count_of(i);
        if (fcount < MIN_FIELDS) continue;

        const std::string full = m.full_name(static_cast<s32>(i));
        const std::string ns = m.td_namespace(i);
        Cand c{static_cast<s32>(i), fcount, full};
        if (wanted_namespace(ns)) ns_cands.push_back(c);
        all_cands.push_back(std::move(c));
    }

    for (auto& f : fx)
        sel.fixed.push_back({f.name, f.ok ? m.full_name(f.idx) : f.name, f.idx});

    // Индексы, уже покрытые fixed — не дублируем в extra.
    std::unordered_set<s32> seen;
    for (const auto& f : sel.fixed) if (f.idx >= 0) seen.insert(f.idx);

    // (3) топ по числу полей: частичная сортировка, затем добавим в общий пул.
    std::sort(all_cands.begin(), all_cands.end(),
              [](const Cand& x, const Cand& y){
                  if (x.fields != y.fields) return x.fields > y.fields;
                  return x.full < y.full;           // стабильность вывода
              });
    std::unordered_set<s32> extra_set;
    std::vector<Cand> chosen;
    for (const auto& c : ns_cands) {                // (2) namespace-выборка целиком
        if (seen.count(c.idx) || extra_set.count(c.idx)) continue;
        extra_set.insert(c.idx);
        chosen.push_back(c);
    }
    std::size_t added_top = 0;
    for (const auto& c : all_cands) {               // (3) топ по полям
        if (added_top >= TOP_BY_FIELDS) break;
        if (seen.count(c.idx) || extra_set.count(c.idx)) continue;
        extra_set.insert(c.idx);
        chosen.push_back(c);
        ++added_top;
    }

    // Единый порядок extra — по полному имени: и стабильно, и удобно читать.
    std::sort(chosen.begin(), chosen.end(),
              [](const Cand& x, const Cand& y){ return x.full < y.full; });
    for (const auto& c : chosen) {
        Target t;
        t.idx = c.idx;
        t.full = c.full;
        // короткое имя = последний сегмент полного (после последней точки)
        const auto dot = c.full.find_last_of('.');
        t.name = (dot == std::string::npos) ? c.full : c.full.substr(dot + 1);
        sel.extra.push_back(std::move(t));
    }
    return sel;
}

// Уникальное имя namespace/структуры/класса на случай коллизии коротких имён
// (два класса Settings из разных namespace-ов). Держим набор уже выданных и
// при повторе дописываем _<idx>.
struct NameAllocator {
    std::unordered_set<std::string> used;
    std::string make(const std::string& base, s32 idx) {
        std::string s = sanitize(base);
        if (used.insert(s).second) return s;
        s = sanitize(base) + "_" + std::to_string(idx);
        used.insert(s);
        return s;
    }
};

// ── оценка размера объекта ───────────────────────────────────────────────────
// Грубая оценка sizeof: max(смещение НЕстатического поля) + размер этого поля.
// Best-effort: неточно для generic/встроенных value-type полей, поэтому и
// помечаем как estimate. Полезно для placement-new проверок.
u32 prim_size(const std::string& t) {
    struct P { const char* cs; u32 sz; };
    static const P prim[] = {
        {"bool",1},{"sbyte",1},{"byte",1},{"char",2},{"short",2},{"ushort",2},
        {"int",4},{"uint",4},{"float",4},{"long",8},{"ulong",8},{"double",8},
        {"IntPtr",8},{"UIntPtr",8},
    };
    for (const P& p : prim) if (t == p.cs) return p.sz;
    return 8;   // ссылки/указатели/неизвестное — слово
}

u32 size_estimate(const std::vector<model::Field>& fields) {
    u32 best_off = 0;
    u32 best_sz = 8;
    bool any = false;
    for (const auto& f : fields) {
        if (f.is_static) continue;
        if (!any || f.offset >= best_off) {
            best_off = f.offset;
            best_sz = prim_size(f.type_name);
            any = true;
        }
    }
    if (!any) return 0;
    return best_off + best_sz;
}

// ── общий рендер одного класса ───────────────────────────────────────────────
// Одна запись «поля со смещениями»: и для namespace-блока C++, и для C#-класса.
// Возвращает пары (имя-константы, строка-значение-с-комментарием).
struct FieldLine {
    std::string cpp_name;   // имя для C++ constexpr (camelCase, sanitized/synthetic)
    std::string cs_name;    // имя для C# const (PascalCase)
    std::string type_name;  // человекочитаемый тип (для комментария)
    std::string orig;       // исходное имя, если было обфусцировано (для // fallback)
    u32 offset = 0;
    bool is_static = false;
};

// Построить строки полей класса с фильтром обфускации. Синтетические имена
// (fieldN / staticN) уникальны в пределах класса.
std::vector<FieldLine> build_field_lines(const std::vector<model::Field>& fields) {
    std::vector<FieldLine> out;
    std::unordered_set<std::string> used;   // уникальность имён в классе
    u32 fidx = 0, sidx = 0;
    for (const auto& f : fields) {
        FieldLine fl;
        fl.type_name = f.type_name;
        fl.offset = f.offset;
        fl.is_static = f.is_static;

        std::string base = f.name;
        if (looks_obfuscated(f.name)) {
            fl.orig = f.name;                 // сохраним как fallback-комментарий
            base = (f.is_static ? "static" : "field") +
                   std::to_string(f.is_static ? sidx : fidx);
        }
        if (f.is_static) ++sidx; else ++fidx;

        std::string cpp = sanitize(base);
        // гарантируем уникальность в пределах класса
        if (!used.insert(cpp).second) {
            std::string u = cpp + "_" + hex(f.offset).substr(2);
            while (!used.insert(u).second) u += "_";
            cpp = u;
        }
        fl.cpp_name = cpp;
        fl.cs_name = pascal(base);
        // C#-имя тоже должно быть уникальным; если pascal совпал — добьём hex.
        out.push_back(std::move(fl));
    }
    // Уникализируем C#-имена отдельным проходом (PascalCase может схлопнуть
    // разные cpp-имена в одно).
    std::unordered_set<std::string> cs_used;
    for (auto& fl : out) {
        std::string c = fl.cs_name;
        if (!cs_used.insert(c).second) {
            std::string u = c + "_" + hex(fl.offset).substr(2);
            while (!cs_used.insert(u).second) u += "_";
            fl.cs_name = u;
        }
    }
    return out;
}

} // namespace

// ─────────────────────────────────────────────────────────────────────────────
//  offsets.h
// ─────────────────────────────────────────────────────────────────────────────
std::string gen_offsets_h(model::Model& m) {
    const auto& TD = m.td_layout();
    Selection sel = select_targets(m);

    std::string out;
    out.reserve(256 * 1024);
    out += "// Auto-generated by oxdump. Do not edit.\n";
    out += "//\n";
    out += "// Ready-to-include cheat header. Read any field by name:\n";
    out += "//   #include \"offsets.h\"\n";
    out += "//   uintptr_t player = ...;\n";
    out += "//   auto* t = *(void**)(player + ox::PlayerManager::worldCameraRoot);\n";
    out += "//\n";
    out += "// TDI      = TypeDefinitionIndex (index into metadata type table).\n";
    out += "// TYPE_IDX = byvalTypeIndex (index into MetadataRegistration.types[]);\n";
    out += "//            this is what il2cpp_class_from_il2cpp_type() needs.\n";
    out += "//\n";
    out += "//   Il2CppType** g = (Il2CppType**)(base + ox::IL2CPP_TYPES_RVA);\n";
    out += "//   Il2CppClass* k = il2cpp_class_from_il2cpp_type(g[TYPE_IDX]);\n";
    out += "//\n";
    out += "// Field offsets are exact. Obfuscated field names (nqW, cWw...) are\n";
    out += "// renamed to fieldN with the original kept as a trailing comment.\n";
    out += "#pragma once\n";
    out += "#include <cstdint>\n\n";
    out += "namespace ox {\n\n";

    out += "static constexpr unsigned long long IL2CPP_TYPES_RVA = " +
           hex(m.types_va()) + ";  // " + std::to_string(m.types_count()) +
           " записей\n\n";

    // ── шапка: константы TDI / TYPE_IDX (ФОРМАТ НЕ МЕНЯТЬ) ────────────────
    // Только фиксированные TARGETS, в исходном порядке — под это заточены
    // грепы/диффы/тест (PLAYERMANAGER_TDI и т.п.).
    for (const auto& f : sel.fixed) {
        const std::string up = upper(f.name);
        if (f.idx < 0) {
            out += "// " + f.name + ": НЕ НАЙДЕН в этой сборке\n";
            continue;
        }
        const u32 byval = m.td_u32(static_cast<u32>(f.idx), TD.byval_type);
        out += "static constexpr int " + up + "_TDI      = " +
               std::to_string(f.idx) + ";\n";
        out += "static constexpr int " + up + "_TYPE_IDX = " +
               std::to_string(byval) + ";\n";
    }
    out += "\n";

    // ── совместимость: комментарии-смещения первых ~50 полей (как раньше) ─
    // Оставлено ради грепов, привыкших к строкам "//   +0xNN <тип> <имя>".
    for (const auto& f : sel.fixed) {
        if (f.idx < 0) continue;
        std::vector<model::Field> fields = m.fields_of(static_cast<u32>(f.idx));
        if (fields.empty()) continue;
        out += "// " + f.full + "\n";
        std::size_t shown = 0;
        for (const auto& fld : fields) {
            if (shown++ >= 50) break;
            const std::string tag = fld.is_static ? "static " : "";
            out += "//   +" + off_col(fld.offset, 7) + " " + tag +
                   fld.type_name + " " + fld.name + "\n";
        }
        out += "\n";
    }

    // ── namespace-блоки по классу со ВСЕМИ полями ────────────────────────
    // Читать: *(T*)((uintptr_t)obj + ox::Class::field). Смещения точные.
    out += "// ── Per-class field offsets (all fields) ────────────────────\n";
    out += "// Read a field:  *(T*)((uintptr_t)obj + ox::Class::field)\n\n";

    NameAllocator alloc;
    auto emit_class = [&](const Target& t) {
        if (t.idx < 0) return;
        std::vector<model::Field> fields = m.fields_of(static_cast<u32>(t.idx));
        if (fields.empty()) return;
        const u32 byval = m.td_u32(static_cast<u32>(t.idx), TD.byval_type);
        const std::string ns_name = alloc.make(t.name, t.idx);
        const std::vector<FieldLine> lines = build_field_lines(fields);

        out += "namespace " + ns_name + " {  // " + t.full + "\n";
        out += "    constexpr int      TDI      = " + std::to_string(t.idx) + ";\n";
        out += "    constexpr int      TypeIdx  = " + std::to_string(byval) + ";\n";
        for (const auto& fl : lines) {
            const std::string tag = fl.is_static ? "static " : "";
            std::string line = "    constexpr uint64_t " + fl.cpp_name;
            // выравниваем '=' в аккуратную колонку; для очень длинных имён
            // гарантируем хотя бы один пробел (иначе получится "name= 0x..").
            const std::size_t col = 4 + 18 + 24;   // отступ + "constexpr uint64_t " + имя
            do { line += " "; } while (line.size() < col);
            line += "= " + hex(fl.offset) + ";  // " + tag + fl.type_name;
            if (!fl.orig.empty()) line += "  (obf: " + fl.orig + ")";
            out += line + "\n";
        }
        const u32 est = size_estimate(fields);
        if (est) out += "    constexpr uint64_t __sizeof_estimate = " +
                        hex(est) + ";  // best-effort\n";

        // Подсказки по обфусцированным методам класса (--xref-names): для тех,
        // у кого в коде нашёлся строковый литерал, дописываем его комментарием.
        // Без флага analysis::have_hints() == false — блок не появляется, вывод
        // прежний. Только методы С подсказкой; остальные не засоряем.
        if (analysis::have_hints()) {
            std::vector<model::Method> methods =
                m.methods_of(static_cast<u32>(t.idx));
            bool header_written = false;
            for (u32 mi = 0; mi < methods.size(); ++mi) {
                const std::string& hint = analysis::lookup_hint(
                    static_cast<u32>(t.idx), mi);
                if (hint.empty()) continue;
                if (!header_written) {
                    out += "    // obfuscated methods with recovered string hints:\n";
                    header_written = true;
                }
                out += "    //   " + methods[mi].name + "()  ~ \"" + hint + "\"\n";
            }
        }
        out += "}\n\n";
    };

    for (const auto& t : sel.fixed) emit_class(t);
    for (const auto& t : sel.extra) emit_class(t);

    out += "} // namespace ox\n";
    return out;
}

// ─────────────────────────────────────────────────────────────────────────────
//  offsets.cs — те же данные C#-константами
// ─────────────────────────────────────────────────────────────────────────────
std::string gen_offsets_cs(model::Model& m) {
    const auto& TD = m.td_layout();
    Selection sel = select_targets(m);

    std::string out;
    out.reserve(256 * 1024);
    out += "// Auto-generated by oxdump. Do not edit.\n";
    out += "//\n";
    out += "// Same offsets as offsets.h, but as C# constants — for tools/cheats\n";
    out += "// written in C# (e.g. Mono.Cecil consumers). One static class per\n";
    out += "// game class: TDI, TypeIdx and every field offset as a const long.\n";
    out += "//\n";
    out += "// Obfuscated field names (nqW, cWw...) are renamed to FieldN with the\n";
    out += "// original kept as a trailing comment.\n\n";
    out += "namespace Ox\n{\n";
    out += "    public static class Il2Cpp\n    {\n";
    out += "        public const ulong TypesRva = " + hex(m.types_va()) +
           "UL;  // " + std::to_string(m.types_count()) + " entries\n";
    out += "    }\n\n";

    NameAllocator alloc;
    auto emit_class = [&](const Target& t) {
        if (t.idx < 0) return;
        std::vector<model::Field> fields = m.fields_of(static_cast<u32>(t.idx));
        if (fields.empty()) return;
        const u32 byval = m.td_u32(static_cast<u32>(t.idx), TD.byval_type);
        const std::string cls = alloc.make(t.name, t.idx);
        const std::vector<FieldLine> lines = build_field_lines(fields);

        out += "    // " + t.full + "\n";
        out += "    public static class " + cls + "\n    {\n";
        out += "        public const long TDI = " + std::to_string(t.idx) + ";\n";
        out += "        public const long TypeIdx = " + std::to_string(byval) + ";\n";
        for (const auto& fl : lines) {
            const std::string tag = fl.is_static ? "static " : "";
            std::string line = "        public const long " + fl.cs_name +
                               " = " + hex(fl.offset) + ";";
            line += "  // " + tag + fl.type_name;
            if (!fl.orig.empty()) line += "  (obf: " + fl.orig + ")";
            out += line + "\n";
        }
        const u32 est = size_estimate(fields);
        if (est) out += "        public const long SizeofEstimate = " +
                        hex(est) + ";  // best-effort\n";
        out += "    }\n\n";
    };

    for (const auto& t : sel.fixed) emit_class(t);
    for (const auto& t : sel.extra) emit_class(t);

    out += "}\n";
    return out;
}

// ─────────────────────────────────────────────────────────────────────────────
//  types.txt — плоский grep-friendly индекс всех классов
// ─────────────────────────────────────────────────────────────────────────────
std::string gen_types_txt(model::Model& m) {
    const auto& TD = m.td_layout();
    auto& L = m.layout();
    const u32 total = L.typedef_count;

    // Собираем строки, сортируем по полному имени.
    struct Row { std::string full; std::string line; };
    std::vector<Row> rows;
    rows.reserve(total);

    for (u32 i = 0; i < total; ++i) {
        const std::string nm = m.td_name(i);
        if (nm.empty()) continue;
        const std::string full = m.full_name(static_cast<s32>(i));
        const u32 byval = m.td_u32(i, TD.byval_type);
        const u32 fcount = m.field_count_of(i);
        const u16 mcount = m.method_count_of(i);

        std::string line = "[TDI=" + std::to_string(i) +
                           "  TypeIdx=" + std::to_string(byval) +
                           "  Fields=" + std::to_string(fcount) +
                           "  Methods=" + std::to_string(mcount) + "]  " + full;
        rows.push_back({full, std::move(line)});
    }

    std::sort(rows.begin(), rows.end(),
              [](const Row& a, const Row& b){
                  if (a.full != b.full) return a.full < b.full;
                  return a.line < b.line;
              });

    std::string out;
    out.reserve(total * 64);
    out += "# oxdump type index — one line per class, sorted by full name.\n";
    out += "# Format: [TDI=..  TypeIdx=..  Fields=..  Methods=..]  <FullName>\n";
    out += "# grep for a class:  grep PlayerManager types.txt\n\n";
    for (const auto& r : rows) out += r.line + "\n";
    return out;
}

} // namespace oxdump::output
