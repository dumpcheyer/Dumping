// oxdump/analysis/xref.cpp — реализация частичной деобфускации по строкам.
//
// Подход (Option 2 из ТЗ): лёгкий ARM64-дизассемблер начала тела метода. Ищем
// два идиома загрузки строки:
//   ADRP xN, page ; ADD  xN, xN, #off     → адрес C-строки прямо в rodata;
//   ADRP xN, page ; LDR  xM, [xN, #off]   → указатель на строку через слот.
// Берём ПЕРВЫЙ осмысленный литерал. «Осмысленный» — это фильтр против шума:
// строка должна быть похожа на имя/сообщение, а не на служебные рантайм-строки
// вроде "kernel32.dll" или "libc", которые встречаются в сотнях P/Invoke-стабов
// и ничего не говорят о конкретном методе.
//
// Почему только ARM64: тестовая цель — libil2cpp.so под arm64 (EM_AARCH64).
// Для других архитектур пасс просто вернёт пусто (проверяем e_machine, если
// образ — ELF; иначе сканируем всё равно, безопасно — мусор отсеет фильтр).
#include "oxdump/analysis/xref.h"
#include "oxdump/arm64/disasm.h"
#include "oxdump/elf/elf64.h"
#include "oxdump/model/metadata_usage.h"
#include <algorithm>
#include <cctype>
#include <cstring>
#include <memory>

namespace oxdump::analysis {

namespace {

// Прежний ad-hoc мини-декодер (4 формы) заменён на полноценный декодер из
// модуля oxdump::arm64 — см. first_string_ref ниже. Настоящий декодер вдобавок
// к ADRP/ADD/LDR распознаёт перенос страницы через MOV Xd, Xm, одиночные ADR и
// PC-литералы, что делает извлечение адресов полнее и корректнее.
//
// ЧЕСТНОЕ ОГРАНИЧЕНИЕ (подтверждено замером на тестовой цели). IL2CPP почти
// никогда не встраивает игровые литералы в код — они идут через usage-таблицы,
// которые на этой сборке вырезаны обфускатором. Прямых ADRP+ADD/LDR-ссылок на
// строки в телах обфусцированных методов — единицы (около полудюжины
// P/Invoke-стабов на весь бинарь). Более мощный декодер НЕ создаёт ссылок,
// которых нет: потолок по строковым подсказкам здесь ~6 при любом декодере.
// Ценность настоящего декодера — корректность и задел под будущие фичи (граф
// вызовов, деобфускация по кросс-рефам).

// ── чтение и фильтрация строк ─────────────────────────────────────────────

// Читает нуль-терминированную ASCII-строку по VA. Пустая, если не отображается
// или встретился не-ASCII байт (значит это не строка).
std::string read_cstr(binary::BinaryImage& img, ByteView bin, u64 va,
                      std::size_t max_len = 96) {
    const auto fo = img.va2fo(va);
    if (!fo) return {};
    std::string s;
    for (std::size_t i = 0; i < max_len && *fo + i < bin.size; ++i) {
        const char c = static_cast<char>(bin.data[*fo + i]);
        if (c == 0) break;
        if (c < 32 || c >= 127) return {};   // непечатное — не C-строка
        s += c;
    }
    return s;
}

// Служебные рантайм-строки, которые встречаются в сотнях методов и подсказкой
// НЕ являются (P/Invoke-имена библиотек, точки входа платформенных хуков и
// т.п.). Если первый литерал — из этого списка, метод остаётся без подсказки:
// лучше ничего, чем «hlA ~ kernel32.dll».
bool is_generic_runtime_string(const std::string& s) noexcept {
    static const char* const kDeny[] = {
        "kernel32.dll", "libc", "libc.so", "kernel32", "ntdll.dll",
        "on_application_paused", "on_application_focus",
        "user32.dll", "__Internal", "libcap.so",
    };
    for (const char* d : kDeny) if (s == d) return true;
    return false;
}

// Похоже ли на осмысленный литерал-подсказку. Требуем: разумная длина, буквы
// есть, преобладают «идентификаторные»/сообщенческие символы. Отсекаем строки
// из одних знаков препинания, форматные хвосты и т.п.
bool is_meaningful(const std::string& s) noexcept {
    if (s.size() < 4 || s.size() > 64) return false;
    std::size_t alpha = 0, idish = 0;
    for (unsigned char c : s) {
        if (std::isalpha(c)) ++alpha;
        if (std::isalnum(c) || c == '_' || c == '.' || c == '/' ||
            c == ' ' || c == '<' || c == '>' || c == '-')
            ++idish;
    }
    // Минимум 4 буквы и почти вся строка — «читаемые» символы.
    return alpha >= 4 && idish >= s.size() * 9 / 10;
}

// Обрезка подсказки до 64 символов (контракт MethodHint::first_string).
std::string clamp64(std::string s) {
    if (s.size() > 64) s.resize(64);
    return s;
}

// Локализатор строковых литералов метадаты для usage-пути. Il2CppStringLiteral
// = {u32 length; u32 dataIndex}; байты — в отдельной ASCII-секции. Секции
// детекта в Layout нет, поэтому находим по сигнатуре здесь; это чисто
// вспомогательная логика деобфускации, метадата/layout не трогаются.
class LitResolver {
public:
    explicit LitResolver(const metadata::Metadata& md) : md_(md) { find(); }
    bool ok() const noexcept { return table_off_ && data_off_; }
    std::string value(u32 idx) const {
        if (!ok() || idx >= table_count_) return {};
        const u32 rec = table_off_ + idx * 8;
        const u32 len = md_.u32_at(rec);
        const u32 di  = md_.u32_at(rec + 4);
        if (len == 0 || len > 4096) return {};
        const ByteView bv = md_.bytes();
        if (static_cast<u64>(data_off_) + di + len > bv.size) return {};
        return std::string(reinterpret_cast<const char*>(bv.data + data_off_ + di), len);
    }
private:
    void find() {
        const ByteView bv = md_.bytes();
        std::vector<metadata::Section> secs = md_.sections();
        const u32 file_end = static_cast<u32>(md_.size());
        for (std::size_t i = 0; i < secs.size(); ++i) {
            const u32 next = (i + 1 < secs.size()) ? secs[i + 1].offset : file_end;
            const u32 real = std::min(secs[i].size, next - secs[i].offset);
            if (real % 8 != 0 || real / 8 < 16) continue;
            const u32 cnt = real / 8;
            const u32 n = std::min<u32>(cnt, 2000);
            u32 small = 0, mono = 0; s64 prev = -1;
            for (u32 k = 0; k < n; ++k) {
                const u32 len = bv.read_u32(secs[i].offset + k * 8);
                const u32 di  = bv.read_u32(secs[i].offset + k * 8 + 4);
                if (len <= 4096) ++small;
                if (prev < 0 || static_cast<s64>(di) >= prev) ++mono;
                prev = di;
            }
            if (small < n * 95 / 100 || mono < n * 95 / 100) continue;
            table_off_ = secs[i].offset; table_count_ = cnt; break;
        }
        if (!table_off_) return;
        for (std::size_t i = 0; i < secs.size(); ++i) {
            const u32 next = (i + 1 < secs.size()) ? secs[i + 1].offset : file_end;
            const u32 real = std::min(secs[i].size, next - secs[i].offset);
            if (real < 64) continue;
            u32 hits = 0, tries = 0;
            for (u32 k = 0; k < std::min<u32>(table_count_, 64); ++k) {
                const u32 len = bv.read_u32(table_off_ + k * 8);
                const u32 di  = bv.read_u32(table_off_ + k * 8 + 4);
                if (len == 0 || len > 256 || di + len > real) continue;
                ++tries;
                std::size_t pr = 0;
                for (u32 j = 0; j < len; ++j) {
                    const u8 c = bv.data[secs[i].offset + di + j];
                    if (c >= 32 && c < 127) ++pr;
                }
                if (pr >= len * 9 / 10) ++hits;
            }
            if (tries >= 8 && hits >= tries * 9 / 10) { data_off_ = secs[i].offset; break; }
        }
    }
    const metadata::Metadata& md_;
    u32 table_off_ = 0, table_count_ = 0, data_off_ = 0;
};

// Годен ли VA как адрес C-строки в образе (грубый «в секции данных?»-фильтр).
// Строгой карты секций у BinaryImage нет, но va2fo уже гарантирует попадание в
// загружаемый сегмент; этого достаточно как границы «строка внутри образа».
inline bool addr_in_image(binary::BinaryImage& img, u64 va) noexcept {
    return va != 0 && static_cast<bool>(img.va2fo(va));
}

// Пытается извлечь первый осмысленный строковый литерал из тела метода,
// начиная с rva. Возвращает пустую строку, если ничего надёжного нет.
//
// Использует полноценный декодер oxdump::arm64. Обход — ЛИНЕЙНЫЙ по порядку
// кода (нужен «первый» литерал), с отслеживанием страницы ADRP по регистрам и
// переносом её через MOV Xd, Xm. Останов — на RET после небольшого префикса
// (как раньше), чтобы не «утечь» в чужой код, но и не оборваться на ранней
// tail-call-заглушке. Безусловный B специально НЕ останавливает разбор: часть
// строк (общие thunk'и P/Invoke) достижимы только линейным продолжением за
// хвост-переходом — на этом держались прежние подсказки.
std::string first_string_ref(binary::BinaryImage& img, ByteView bin, u64 rva,
                             std::size_t budget_bytes) {
    const auto fo = img.va2fo(rva);
    if (!fo) return {};
    // budget в БАЙТАХ → число 4-байтных инструкций; потолок 4096 байт как в
    // decode_function. Ограничиваем и хвостом файла.
    std::size_t max_bytes = std::min<std::size_t>(budget_bytes, 4096);
    if (bin.size - *fo < max_bytes) max_bytes = bin.size - *fo;
    const std::size_t max_insn = max_bytes / 4;

    // Страница ADRP по каждому регистру: держим последнюю, пока не «потрачена».
    u64 page[32] = {0};
    bool have[32] = {false};

    const u8* code = bin.data + *fo;
    for (std::size_t k = 0; k < max_insn; ++k) {
        const std::size_t byte_off = k * 4;
        u32 raw;
        std::memcpy(&raw, code + byte_off, 4);
        const arm64::Insn in = arm64::decode(raw, rva + byte_off);

        // Конец функции — дальше чужой код. Держим небольшой префикс (k>6),
        // чтобы не оборваться на ранней tail-call-заглушке.
        if (in.op == arm64::Op::RET && k > 6) break;

        switch (in.op) {
            case arm64::Op::ADRP:
                page[in.rd] = static_cast<u64>(in.imm);   // imm = VA страницы
                have[in.rd] = true;
                break;
            case arm64::Op::ADD_imm:
                if (have[in.rn]) {
                    // Прямой адрес строки: ADRP+ADD.
                    const u64 va = page[in.rn] + static_cast<u64>(in.imm);
                    if (addr_in_image(img, va)) {
                        const std::string s = read_cstr(img, bin, va);
                        if (is_meaningful(s) && !is_generic_runtime_string(s))
                            return clamp64(s);
                    }
                }
                have[in.rd] = false;   // Rd перезаписан результатом ADD
                break;
            case arm64::Op::LDR_imm:
                // Значим только 64-битный unsigned-offset поверх ADRP-регистра.
                if (in.sf && !in.writeback && have[in.rn]) {
                    // Косвенно: слот [ADRP+off] хранит указатель на строку.
                    const u64 loaded = img.ptr(page[in.rn] + static_cast<u64>(in.imm));
                    if (img.is_valid_va(loaded)) {
                        const std::string s = read_cstr(img, bin, loaded);
                        if (is_meaningful(s) && !is_generic_runtime_string(s))
                            return clamp64(s);
                    }
                }
                have[in.rd] = false;   // Rt перезаписан загруженным значением
                break;
            case arm64::Op::MOV_reg:
                // Перенос регистра переносит и «страничность» (только 64-бит).
                if (in.sf && have[in.rm]) {
                    page[in.rd] = page[in.rm];
                    have[in.rd] = true;
                } else {
                    have[in.rd] = false;
                }
                break;
            case arm64::Op::ADR: {
                // Одиночный ADR несёт готовый VA строки/данных.
                const u64 va = static_cast<u64>(in.imm);
                if (addr_in_image(img, va)) {
                    const std::string s = read_cstr(img, bin, va);
                    if (is_meaningful(s) && !is_generic_runtime_string(s))
                        return clamp64(s);
                }
                have[in.rd] = false;
                break;
            }
            default:
                // Прочие формы, пишущие в Rd, могли его перезаписать. Точного
                // трекинга произвольных записей нет (заведомо неполно), но
                // известные writeback-загрузки гасим, чтобы не тянуть устаревшую
                // страницу.
                if (in.op == arm64::Op::LDR_imm && in.writeback)
                    have[in.rd] = false;
                break;
        }
    }
    return {};
}

}  // namespace

bool looks_obfuscated(const std::string& name) noexcept {
    // Обфусцированное имя в этой сборке — короткое (2–4 симв.) со смешанным
    // регистром букв: `hlA`, `nqW`, `UVb`. Осмысленные короткие имена почти
    // всегда однорегистровые (`get`, `Add`, `ID`) — их не трогаем.
    if (name.size() < 2 || name.size() > 4) return false;
    int upper = 0, lower = 0;
    for (unsigned char c : name) {
        if (!std::isalpha(c)) return false;
        if (std::isupper(c)) ++upper;
        else ++lower;
    }
    return upper > 0 && lower > 0;
}

std::vector<MethodHint>
build_hints(model::Model& m, ByteView bin, binary::BinaryImage& img,
            std::size_t budget_per_method) {
    std::vector<MethodHint> out;

    // Источник подсказок №1 — usage-таблицы (если опознаны). Они дают связь
    // метод→строковый литерал НАПРЯМУЮ из метадаты: надёжнее и полнее любого
    // дизассемблера, работает для ВСЕХ методов (не только с прямым ADRP+ADD),
    // и не зависит от архитектуры. Дизассемблер остаётся ЗАПАСНЫМ путём — для
    // методов без usage-строки и для сборок, где usage-таблиц нет вовсе.
    const model::MetadataUsageTable& usages = m.usages();
    const bool have_usages = usages.usable();
    std::unique_ptr<LitResolver> lits;
    if (have_usages) lits = std::make_unique<LitResolver>(m.md());

    // Дизассемблер — только ARM64 (тестовая цель — arm64 libil2cpp). На других
    // машинах прямых ADRP+ADD/LDR-идиом нет. При наличии usage-таблиц это
    // ограничение неважно: usage-путь архитектурно-независим.
    bool disasm_ok = true;
    if (auto* elf = dynamic_cast<elf::Elf64*>(&img)) {
        if (elf->machine() != 0xB7 /* EM_AARCH64 */) disasm_ok = false;
    }
    // Совсем нечем работать — ни usage-таблиц, ни подходящего дизассемблера.
    if (!have_usages && !disasm_ok) return out;

    auto& L = m.layout();
    const u32 total = L.typedef_count;
    const s32 method_start_off = m.td_layout().method_start;

    for (u32 i = 0; i < total; ++i) {
        // methods_of повторяет разбор из генераторов: те же RVA и порядок.
        std::vector<model::Method> methods = m.methods_of(i);
        const s32 mstart =
            (method_start_off >= 0) ? m.td_s32(i, method_start_off) : -1;
        for (u32 mi = 0; mi < methods.size(); ++mi) {
            const model::Method& mo = methods[mi];
            if (mo.rva == 0) continue;                 // нет кода — нечего сканировать
            if (!looks_obfuscated(mo.name)) continue;  // осмысленному имени подсказка не нужна

            std::string s;
            // (1) usage-таблица: первый строковый литерал метода.
            if (have_usages && lits && mstart >= 0) {
                const u32 method_index = static_cast<u32>(mstart) + mi;
                for (const model::MetadataUsage& u :
                     usages.for_method(method_index)) {
                    if (u.kind != model::MetadataUsageKind::StringLiteral) continue;
                    std::string v = lits->value(u.target_index);
                    if (is_meaningful(v) && !is_generic_runtime_string(v)) {
                        s = clamp64(std::move(v));
                        break;
                    }
                }
            }
            // (2) запасной путь: дизассемблер начала тела метода.
            if (s.empty() && disasm_ok)
                s = first_string_ref(img, bin, mo.rva, budget_per_method);
            if (s.empty()) continue;

            MethodHint h;
            h.type_idx = i;
            h.method_idx = mi;
            h.first_string = s;
            out.push_back(std::move(h));
        }
    }
    return out;
}

std::unordered_map<u64, std::string>
hint_index(const std::vector<MethodHint>& hints) {
    std::unordered_map<u64, std::string> idx;
    idx.reserve(hints.size() * 2);
    for (const MethodHint& h : hints)
        idx.emplace(hint_key(h.type_idx, h.method_idx), h.first_string);
    return idx;
}

// ── реестр активных подсказок ────────────────────────────────────────────
namespace {
// Индекс по (type_idx,method_idx). Заполняется один раз из main.cpp.
std::unordered_map<u64, std::string> g_hints;
// Возвращается по ссылке, когда подсказки нет — чтобы lookup_hint() не плодил
// временных объектов в горячем цикле генераторов.
const std::string g_empty;
}  // namespace

void set_active_hints(std::vector<MethodHint> hints) {
    g_hints = hint_index(hints);
}

const std::string& lookup_hint(u32 type_idx, u32 method_idx) noexcept {
    if (g_hints.empty()) return g_empty;
    const auto it = g_hints.find(hint_key(type_idx, method_idx));
    return it == g_hints.end() ? g_empty : it->second;
}

bool have_hints() noexcept { return !g_hints.empty(); }

}  // namespace oxdump::analysis
