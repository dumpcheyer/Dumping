// oxdump/model/model.cpp — реализация модели IL2CPP.
//
// Строгая калька с model.py. Все смещения полей идут из TDLayout (TD_), а не из
// констант: раскладка Il2CppTypeDefinition выведена из данных и на v40+ не
// поедет. Пороги и «послабления» (арность generic, ограничение глубины
// рекурсии, верхняя граница числа полей) перенесены вместе с причинами.
#include "oxdump/model/model.h"
#include <algorithm>

namespace oxdump::model {

namespace {

// Примитивы Il2CppTypeEnum, у которых есть короткое имя в C#. Держим локально:
// нужны только type_name(). Индекс — сам тег, за пределами — не примитив.
const char* primitive_name(u8 tag) noexcept {
    switch (tag) {
        case 0x01: return "void";    case 0x02: return "bool";
        case 0x03: return "char";    case 0x04: return "sbyte";
        case 0x05: return "byte";    case 0x06: return "short";
        case 0x07: return "ushort";  case 0x08: return "int";
        case 0x09: return "uint";    case 0x0A: return "long";
        case 0x0B: return "ulong";   case 0x0C: return "float";
        case 0x0D: return "double";  case 0x0E: return "string";
        case 0x16: return "TypedReference";
        case 0x18: return "IntPtr";  case 0x19: return "UIntPtr";
        case 0x1C: return "object";
        default:   return nullptr;
    }
}

} // namespace

Model::Model(metadata::Metadata& md, metadata::Layout& L, binary::BinaryImage& b,
             MetadataRegistration mr, metadata::TDLayout td)
    : md_(md), L_(L), b_(b), mr_(mr), TD_(td) {
    // Опознаём usage-таблицы (метод → ссылки на метадату) по содержимному.
    // Может вернуть непригодную таблицу — тогда генераторы/деобфускатор
    // работают по запасному пути, ничего не ломается.
    usages_ = MetadataUsageTable::detect(md_, L_);
}

// ── Il2CppType ──────────────────────────────────────────────────────────────

u64 Model::type_va(s32 idx) const {
    if (idx < 0 || static_cast<u64>(idx) >= mr_.types_count) return 0;
    return b_.ptr(mr_.types + static_cast<u64>(idx) * 8);
}

u8 Model::type_tag(u64 va) const {
    if (!b_.va2fo(va)) return 0;
    // Il2CppType: { void* data; uint attrs:16, type:8, ... } — тег в байте 3.
    // Поле attrs/type не релоцируется, поэтому ptr() вернёт сырое слово файла:
    // читаем u64 по va+8 и достаём байт 3. Отдельного доступа к байтам файла у
    // Elf64 нет — а он и не нужен, ptr() покрывает этот случай.
    return static_cast<u8>((b_.ptr(va + 8) >> 16) & 0xFF);
}

u64 Model::type_data(u64 va) const {
    // Поле data релоцируемо: сперва карта релокаций (там настоящий указатель),
    // иначе сырые байты. ptr() уже делает ровно это.
    return b_.ptr(va);
}

s64 Model::typedef_index_of(s32 type_idx) const {
    const u64 va = type_va(type_idx);
    if (!va) return -1;
    return static_cast<s64>(type_data(va) & 0xFFFFFFFF);
}

// ── имена ────────────────────────────────────────────────────────────────────

std::string Model::full_name(s32 i) {
    auto it = name_cache_.find(i);
    if (it != name_cache_.end()) return it->second;
    if (i < 0 || static_cast<u32>(i) >= L_.typedef_count) return "?";

    // Раскрытие вложенности: поднимаемся по declaringType до внешнего типа.
    std::vector<std::string> parts;
    parts.push_back(td_name(static_cast<u32>(i)));
    s32 decl = td_s32(static_cast<u32>(i), TD_.declaring);
    s32 top = i;
    int guard = 0;
    while (decl >= 0 && guard < 16) {
        const s64 di = typedef_index_of(decl);
        if (di < 0 || static_cast<u32>(di) >= L_.typedef_count) break;
        parts.push_back(td_name(static_cast<u32>(di)));
        top = static_cast<s32>(di);
        decl = td_s32(static_cast<u32>(di), TD_.declaring);
        ++guard;
    }

    const std::string ns = td_namespace(static_cast<u32>(top));

    // Собираем имя от внешнего к внутреннему и обрезаем арность generic у
    // каждого сегмента: "List`1" -> "List". Разделитель между сегментами — '.'.
    std::string name;
    for (std::size_t k = parts.size(); k-- > 0;) {
        std::string seg = parts[k];
        const auto tick = seg.find('`');
        if (tick != std::string::npos) seg = seg.substr(0, tick);
        if (!name.empty()) name += ".";
        name += seg;
    }

    std::string out = ns.empty() ? name : (ns + "." + name);
    name_cache_[i] = out;
    return out;
}

std::string Model::type_name(u64 va, int depth) {
    if (!va || depth > 8) return "object";
    const u8 tag = type_tag(va);
    if (const char* p = primitive_name(tag)) return p;
    const u64 data = type_data(va);

    if (tag == T_CLASS || tag == T_VALUETYPE) {
        return full_name(static_cast<s32>(data & 0xFFFFFFFF));
    }

    if (tag == T_SZARRAY || tag == T_PTR || tag == T_BYREF) {
        std::string inner = type_name(data, depth + 1);
        if (tag == T_SZARRAY) return inner + "[]";
        return inner + (tag == T_PTR ? "*" : "&");
    }

    if (tag == T_ARRAY) {
        // Il2CppArrayType { Il2CppType* etype; uint8 rank; ... }
        if (!b_.va2fo(data)) return "object[]";
        const u64 etype = b_.ptr(data);            // etype* релоцируем
        const u8 rank = static_cast<u8>(b_.ptr(data + 8) & 0xFF);  // rank сырой
        std::string commas;
        for (int k = 1; k < (rank > 0 ? rank : 1); ++k) commas += ",";
        return type_name(etype, depth + 1) + "[" + commas + "]";
    }

    if (tag == T_GENERICINST) {
        // Il2CppGenericClass { Il2CppType* type; Il2CppGenericContext ctx }
        if (!b_.va2fo(data)) return "object";
        std::string base = type_name(b_.ptr(data), depth + 1);
        std::vector<std::string> args = generic_args(data, depth);
        if (args.empty()) return base;
        std::string joined;
        for (std::size_t k = 0; k < args.size(); ++k) {
            if (k) joined += ", ";
            joined += args[k];
        }
        return base + "<" + joined + ">";
    }

    if (tag == T_VAR || tag == T_MVAR) return "T";

    return "object";
}

std::vector<std::string> Model::generic_args(u64 gclass_va, int depth) {
    std::vector<std::string> out;
    const auto fo = b_.va2fo(gclass_va);
    if (!fo) return out;
    // Il2CppGenericContext сразу за type*: { class_inst*, method_inst* }.
    const u64 inst = b_.ptr(gclass_va + 8);
    if (!b_.is_valid_va(inst)) return out;
    if (!b_.va2fo(inst)) return out;
    // Il2CppGenericInst { uint32 argc; Il2CppType** argv }. argc — сырое слово.
    const u32 argc = static_cast<u32>(b_.ptr(inst) & 0xFFFFFFFF);
    const u64 argv = b_.ptr(inst + 8);
    if (argc > 32 || !b_.is_valid_va(argv)) return out;
    for (u32 k = 0; k < argc; ++k) {
        out.push_back(type_name(b_.ptr(argv + static_cast<u64>(k) * 8), depth + 1));
    }
    return out;
}

// ── поля ──────────────────────────────────────────────────────────────────────

u32 Model::field_count_of(u32 i) const {
    // fieldCount читается прямо из записи (+0x3E, найдено замощением). Верхняя
    // граница 4096 — страховка на случай неверной раскладки: столько
    // собственных полей у типа не бывает.
    if (TD_.field_count >= 0) {
        const u16 c = td_u16(i, TD_.field_count);
        return c <= 4096 ? c : 0;
    }
    return field_count_fallback(i);
}

u32 Model::field_count_fallback(u32 i) const {
    // Запасной путь: граница по fieldStart следующего типа. Нужен, только если
    // fieldCount в раскладке не определился.
    const s32 start = td_s32(i, TD_.field_start);
    if (start < 0) return 0;
    const s32 nxt = (i + 1 < L_.typedef_count) ? td_s32(i + 1, TD_.field_start) : -1;
    if (nxt > start) return static_cast<u32>(nxt - start);
    const u32 upper = std::min<u32>(i + 12, L_.typedef_count);
    for (u32 j = i + 2; j < upper; ++j) {
        const s32 v = td_s32(j, TD_.field_start);
        if (v > start) return static_cast<u32>(v - start);
    }
    if (static_cast<u32>(start) >= L_.field_count) return 0;
    return std::min<u32>(L_.field_count - static_cast<u32>(start), 512);
}

u16 Model::method_count_of(u32 i) const {
    const u16 c = td_u16(i, TD_.method_count);
    return c < 8192 ? c : 0;
}

std::vector<u32> Model::field_offsets(u32 i, u32 count) const {
    // Реальные смещения полей из MetadataRegistration.fieldOffsets: массив
    // указателей, по одному на тип; каждый ведёт на массив u32-смещений.
    std::vector<u32> out(count, 0);
    if (!mr_.field_offsets) return out;
    const u64 entry = b_.ptr(mr_.field_offsets + static_cast<u64>(i) * 8);
    if (!b_.is_valid_va(entry)) return out;
    // Смещения полей лежат сырыми u32 подряд и релокациям не подлежат: ptr()
    // по entry+k*4 вернёт слово файла, младшие 32 бита — искомое смещение.
    // Читать нужно только по валидному адресу, иначе ptr() отдаст 0.
    for (u32 k = 0; k < count; ++k) {
        const u64 p = entry + static_cast<u64>(k) * 4;
        out[k] = b_.va2fo(p) ? static_cast<u32>(b_.ptr(p) & 0xFFFFFFFF) : 0;
    }
    return out;
}

std::vector<Field> Model::fields_of(u32 i) {
    std::vector<Field> out;
    const s32 start = td_s32(i, TD_.field_start);
    const u32 count = field_count_of(i);
    if (start < 0 || count == 0 || count > 4096) return out;
    const std::vector<u32> offs = field_offsets(i, count);

    for (u32 k = 0; k < count; ++k) {
        const u32 rec = L_.field_offset + (static_cast<u32>(start) + k) * 12;
        if (rec + 12 > md_.size()) break;
        Field f;
        f.name = s(md_.u32_at(rec));
        const s32 tidx = md_.s32_at(rec + 4);
        const u64 tva = type_va(tidx);
        f.type_name = type_name(tva);
        // Статические поля помечены битом 0x10 в атрибутах Il2CppType (нижние
        // 16 бит слова attrs/type по va+8). Слово не релоцируется — ptr() отдаёт
        // сырое значение файла.
        u32 attrs = 0;
        if (tva && b_.va2fo(tva)) attrs = static_cast<u32>(b_.ptr(tva + 8) & 0xFFFF);
        f.is_static = (attrs & 0x10) != 0;
        f.offset = (k < offs.size()) ? offs[k] : 0;
        out.push_back(std::move(f));
    }
    return out;
}

// ── методы ────────────────────────────────────────────────────────────────────

std::vector<Method> Model::methods_of(u32 i) {
    std::vector<Method> out;
    const s32 start = td_s32(i, TD_.method_start);
    const u16 count = method_count_of(i);
    if (start < 0 || count == 0) return out;

    for (u16 k = 0; k < count; ++k) {
        const u32 rec = L_.method_offset + (static_cast<u32>(start) + k) * 32;
        if (rec + 32 > md_.size()) break;
        // Раскладка Il2CppMethodDefinition в этой сборке (сверена с эталонным
        // дампом на PlayerManager): +0x00 name, +0x0C returnType, +0x14 token
        // (0x06xxxxxx), +0x18 parameterStart, +0x1C parameterCount.
        Method m;
        m.name = s(md_.u32_at(rec));
        m.token = md_.u32_at(rec + 0x14);
        m.param_start = md_.s32_at(rec + 0x18);
        const s32 ret_idx = md_.s32_at(rec + 0x0C);
        u16 pcount = (rec + 0x1E <= md_.size()) ? md_.u16_at(rec + 0x1C) : 0;
        if (pcount > 64) pcount = 0;
        m.param_count = pcount;
        m.ret_type = type_name(type_va(ret_idx));
        m.rva = method_rva(m.token);
        out.push_back(std::move(m));
    }
    return out;
}

std::vector<Param> Model::params_of(s32 start, u16 count) {
    std::vector<Param> out;
    if (start < 0 || count == 0 || count > 64 || !L_.param_offset) return out;
    for (u16 k = 0; k < count; ++k) {
        const u32 rec = L_.param_offset + (static_cast<u32>(start) + k) * 12;
        if (rec + 12 > md_.size()) break;
        Param p;
        p.name = s(md_.u32_at(rec));
        if (p.name.empty()) p.name = "p" + std::to_string(k);
        const s32 tidx = md_.s32_at(rec + 8);
        p.type_name = type_name(type_va(tidx));
        out.push_back(std::move(p));
    }
    return out;
}

u64 Model::method_rva(u32 token) const {
    // Адреса кода лежат НЕ в метаданных, а в per-module массиве methodPointers
    // внутри libil2cpp. Индекс — младшие 24 бита токена минус единица: токены
    // методов нумеруются с 0x06000001. Работает для основной сборки
    // (Assembly-CSharp); для остальных вернётся 0 — осознанное ограничение.
    if (!method_pointers_ || !token) return 0;
    const s64 idx = static_cast<s64>(token & 0x00FFFFFF) - 1;
    if (idx < 0 || static_cast<u32>(idx) >= method_pointers_count_) return 0;
    return b_.ptr(method_pointers_ + static_cast<u64>(idx) * 8);
}

// ── таблица параметров (определяется отложенно) ─────────────────────────────────

void Model::detect_params() {
    // Таблица параметров: 12 байт на запись, индексируется из методов
    // (parameterStart на +0x18). Ищем секцию, чей размер только-только
    // перекрывает максимальный parameterStart.
    if (!L_.method_offset) return;
    const ByteView v = md_.bytes();

    s32 hi = -1;
    const u32 step = std::max<u32>(1, L_.method_count / 4000);
    for (u32 k = 0; k < L_.method_count; k += step) {
        const u32 rec = L_.method_offset + k * 32 + 0x18;
        if (rec + 4 > md_.size()) break;
        const s32 val = v.read_s32(rec);
        if (val >= 0 && val < 5000000) hi = std::max(hi, val);
    }
    if (hi <= 0) return;

    u32 best = 0;
    bool have = false;
    u32 slack = 0;
    for (const metadata::Section& sec : md_.sections()) {
        if (sec.size % 12) continue;
        const u32 c = sec.size / 12;
        if (c > static_cast<u32>(hi) &&
            (!have || (c - static_cast<u32>(hi)) < slack)) {
            slack = c - static_cast<u32>(hi);
            best = sec.offset;
            have = true;
        }
    }
    if (best) {
        L_.param_offset = best;
        L_.param_count = static_cast<u32>(hi) + 1;
    }
}

} // namespace oxdump::model
