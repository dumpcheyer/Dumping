// oxdump — IL2CPP-дампер на C++17. Точка входа CLI.
//
// Собирает всё: crypto/transforms, metadata (Metadata/Layout/TDLayout/
// headerless/pairing), elf (Elf64, MR-finder, codeGenModules), model
// (Model), output (dump.cs, il2cpp.h, script.json, offsets.h, REPORT.txt).
// Результат кладёт в ZIP-архив.
//
// Философия: делать всё быстро, никогда не выдавать молча кривой дамп.
// Каждая известная сломанная ситуация (файлы из разных сборок, упакованная
// либа, необычный шифр) должна быть распознана и объяснена, а не
// проигнорирована.

#include "oxdump/common.h"
#include "oxdump/io/file_map.h"
#include "oxdump/io/zip_writer.h"
#include "oxdump/crypto/container.h"
#include "oxdump/metadata/header.h"
#include "oxdump/metadata/layout.h"
#include "oxdump/metadata/tdlayout.h"
#include "oxdump/metadata/headerless.h"
#include "oxdump/metadata/pairing.h"
#include "oxdump/binary/image.h"
#include "oxdump/elf/elf64.h"
#include "oxdump/elf/codegen.h"
#include "oxdump/macho/macho.h"
#include "oxdump/pe/pe.h"
#include "oxdump/model/model.h"
#include "oxdump/output/generators.h"
#include "oxdump/analysis/xref.h"

#include <chrono>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <memory>
#include <string>
#include <system_error>
#include <vector>

using namespace oxdump;
using clock_t_ = std::chrono::steady_clock;

namespace {

const char* USAGE =
    "OxDumpCpp — IL2CPP-дампер для Oxide Survival Island (и любой Unity-IL2CPP игры)\n"
    "\n"
    "Usage:\n"
    "  oxdump <metadata> <binary> [-o out.zip] [-v] [-q] [--skip-pair-check]\n"
    "\n"
    "Аргументы:\n"
    "  <metadata>            global-metadata.dat (файл начинается с AF 1B B1 FA)\n"
    "  <binary>              libil2cpp.so / UnityFramework / GameAssembly.dll (ELF, Mach-O или PE)\n"
    "\n"
    "Опции:\n"
    "  -o FILE              имя архива с дампом (по умолчанию oxide_dump.zip)\n"
    "  -v, --verbose        подробный лог: как найдены ключ, таблицы, MR\n"
    "  -q, --quiet          только путь к архиву (для скриптов)\n"
    "  --skip-pair-check    не отказываться, если файлы из разных сборок\n"
    "  --xref-names         собрать подсказки по строковым литералам для\n"
    "                       обфусцированных методов (медленнее на секунды)\n"
    "  --compress           сжимать текстовые файлы (DEFLATE, method 8) —\n"
    "                       ВКЛЮЧЕНО по умолчанию; архив ~25-30 МБ вместо ~99 МБ\n"
    "  --no-compress        писать всё без сжатия (STORED) — крупный архив\n"
    "\n"
    "Файлы можно передавать в любом порядке — они различаются по сигнатуре.\n";

// Определяем, кто есть кто, по первым байтам.
bool looks_like_metadata(const io::FileMap& f) {
    return f.size() >= 4 && f.data()[0] == 0xAF && f.data()[1] == 0x1B &&
           f.data()[2] == 0xB1 && f.data()[3] == 0xFA;
}
bool looks_like_binary(const io::FileMap& f) {
    if (f.size() < 4) return false;
    // ELF, Mach-O или PE (Windows GameAssembly.dll начинается с 'MZ').
    return (std::memcmp(f.data(), "\x7f""ELF", 4) == 0) ||
           (std::memcmp(f.data(), "\xcf\xfa\xed\xfe", 4) == 0) ||  // Mach-O 64
           (std::memcmp(f.data(), "\xca\xfe\xba\xbe", 4) == 0) ||  // FAT Mach-O
           (f.data()[0] == 'M' && f.data()[1] == 'Z');            // PE (DOS 'MZ')
}

// PE (Windows GameAssembly.dll) распознаём по DOS-сигнатуре 'MZ'.
bool looks_like_pe(const io::FileMap& f) {
    return f.size() >= 2 && f.data()[0] == 'M' && f.data()[1] == 'Z';
}
bool looks_like_macho(const io::FileMap& f) {
    return f.size() >= 4 &&
           (std::memcmp(f.data(), "\xcf\xfa\xed\xfe", 4) == 0 ||  // Mach-O 64
            std::memcmp(f.data(), "\xca\xfe\xba\xbe", 4) == 0);   // FAT Mach-O
}

// Единая точка выбора формата: ELF / Mach-O / PE. Все три реализуют
// binary::BinaryImage, поэтому дальше конвейер работает через базовую ссылку и
// не знает о формате. Возвращает владеющий указатель; на неизвестной сигнатуре
// бросает BinaryError (до сюда обычно не доходит — формат проверен в parse_args).
std::unique_ptr<binary::BinaryImage>
open_binary_image(const io::FileMap& f, std::string& kind) {
    if (looks_like_pe(f)) {
        kind = "PE";
        return std::make_unique<pe::PE>(f.view());
    }
    if (looks_like_macho(f)) {
        kind = "Mach-O";
        return std::make_unique<macho::Macho>(f.view());
    }
    kind = "ELF";
    return std::make_unique<elf::Elf64>(f.view());
}

struct Args {
    std::string meta_path, bin_path;
    std::string out_path = "oxide_dump.zip";
    bool verbose = false;
    bool quiet = false;
    bool skip_pair = false;
    bool xref_names = false;
    bool compress = true;   // сжатие ВКЛЮЧЕНО по умолчанию (архив иначе огромный)
    bool help = false;
    bool version = false;
    std::string error;
};

Args parse_args(int argc, char** argv) {
    Args a;
    std::vector<std::string> positionals;
    for (int i = 1; i < argc; ++i) {
        std::string s = argv[i];
        if (s == "-h" || s == "--help") a.help = true;
        else if (s == "--version") a.version = true;
        else if (s == "-v" || s == "--verbose") a.verbose = true;
        else if (s == "-q" || s == "--quiet") a.quiet = true;
        else if (s == "--skip-pair-check") a.skip_pair = true;
        else if (s == "--xref-names") a.xref_names = true;
        else if (s == "--compress") a.compress = true;
        else if (s == "--no-compress") a.compress = false;
        else if (s == "-o" || s == "--out") {
            if (i + 1 >= argc) { a.error = "-o требует аргумент"; return a; }
            a.out_path = argv[++i];
        } else if (!s.empty() && s[0] == '-') {
            a.error = "неизвестный флаг: " + s; return a;
        } else {
            positionals.push_back(s);
        }
    }
    // распознаём по сигнатурам, чтобы не важен был порядок аргументов
    for (const auto& p : positionals) {
        try {
            auto f = io::FileMap::open(p);
            if (looks_like_metadata(f)) a.meta_path = p;
            else if (looks_like_binary(f)) a.bin_path = p;
            else { a.error = "файл не распознан (ни метадата, ни ELF/Mach-O/PE): " + p; return a; }
        } catch (const std::exception& e) {
            a.error = e.what(); return a;
        }
    }
    if (!a.help && !a.version) {
        if (a.meta_path.empty()) a.error = "не указан global-metadata.dat";
        else if (a.bin_path.empty()) a.error = "не указан libil2cpp.so";
    }
    return a;
}

// Простой прогресс-бар: пишет в stderr, обновляется \r-возвратом.
struct Progress {
    bool enabled;
    std::string label;
    void tick(u64 cur, u64 total) {
        if (!enabled || !total) return;
        u32 pct = static_cast<u32>((cur * 100u) / total);
        u32 filled = pct / 4;              // 25 клеток
        std::string bar(25, '.');
        for (u32 i = 0; i < filled; ++i) bar[i] = '#';
        std::fprintf(stderr, "           [%s] %3u%%  %s%s",
                     bar.c_str(), pct, label.c_str(),
                     cur >= total ? "\n" : "\r");
        std::fflush(stderr);
    }
};

struct Timer {
    clock_t_::time_point start = clock_t_::now();
    double elapsed_s() const {
        return std::chrono::duration<double>(clock_t_::now() - start).count();
    }
};

Timer g_timer;
bool g_quiet = false;
bool g_verbose = false;

void step(const std::string& msg) {
    if (g_quiet) return;
    std::fprintf(stderr, "[%6.1fs] %s\n", g_timer.elapsed_s(), msg.c_str());
}
void detail(const std::string& msg) {
    if (g_quiet || !g_verbose) return;
    for (std::size_t i = 0, j; i < msg.size(); i = j + 1) {
        j = msg.find('\n', i);
        if (j == std::string::npos) j = msg.size();
        std::fprintf(stderr, "           %.*s\n",
                     static_cast<int>(j - i), msg.data() + i);
    }
}
void warn(const std::string& msg) {
    std::fprintf(stderr, "  ВНИМАНИЕ: %s\n", msg.c_str());
}

} // namespace

int main(int argc, char** argv) {
    Args a = parse_args(argc, argv);
    if (a.help) { std::fputs(USAGE, stderr); return 0; }
    if (a.version) { std::puts("oxdump 1.0.0 (C++17)"); return 0; }
    if (!a.error.empty()) {
        std::fprintf(stderr, "ОШИБКА: %s\n\n%s", a.error.c_str(), USAGE);
        return 2;
    }

    g_quiet = a.quiet;
    g_verbose = a.verbose;

    try {
        // ── чтение ────────────────────────────────────────────────────────
        step("Читаю входные файлы");
        auto meta = io::FileMap::open(a.meta_path);
        auto bin  = io::FileMap::open(a.bin_path);
        if (g_verbose) {
            detail("метаданные: " + thousands(meta.size()) + " байт");
            detail("бинарник:   " + thousands(bin.size())  + " байт");
        }

        // ── метаданные ────────────────────────────────────────────────────
        std::unique_ptr<metadata::Metadata> md;
        std::unique_ptr<metadata::Layout> L;
        bool headerless = false;

        step("Восстанавливаю ключ шифрования");
        try {
            md = std::make_unique<metadata::Metadata>(meta.view());
            detail(md->key_report());

            step("Определяю таблицы метаданных");
            L = std::make_unique<metadata::Layout>(*md);
            if (!L->ok()) {
                throw MetadataError("не удалось определить таблицы:\n" + L->report());
            }
            detail(L->report());
        } catch (const MetadataError& e) {
            // Заголовок не поддался — headerless-режим.
            // Тело метадаты не шифруется (доказано побайтовым сравнением),
            // поэтому карту секций строим по содержимому.
            warn(std::string("заголовок не читается: ") + e.what());
            step("Захожу без заголовка: ищу таблицы по содержимому");
            metadata::headerless::HeaderlessResult hr;
            try {
                hr = metadata::headerless::recover(meta.view());
            } catch (const std::exception& e2) {
                throw MetadataError(std::string("headerless тоже не смог: ") + e2.what());
            }
            detail(hr.report);

            // Версия не шифруется: всегда u32 по смещению 4. Читаем напрямую,
            // 39 — запасной вариант, если файл почему-то короче.
            const u32 ver = meta.size() >= 8 ? meta.view().read_u32(4) : 39;
            md = std::make_unique<metadata::Metadata>(
                metadata::Metadata::make_from_headerless(meta.view(), ver, hr));
            L = std::make_unique<metadata::Layout>(
                metadata::Layout::make_from_headerless(*md, hr));
            headerless = true;

            step("Определяю таблицы метаданных");
            if (!L->ok()) {
                throw MetadataError(
                    "headerless: типы/строки не опознаны:\n" + L->report());
            }
            detail(L->report());
            detail("карта секций построена заново, заголовок не использован");
        }

        // ── бинарник ────────────────────────────────────────────────────────
        // Формат (ELF / Mach-O / PE) выбираем по сигнатуре; все три реализуют
        // binary::BinaryImage, поэтому дальше работаем через базовую ссылку b и
        // конвейер (pairing/tdlayout/model/codegen/report) не знает о формате.
        std::string bin_kind;
        std::unique_ptr<binary::BinaryImage> img = open_binary_image(bin, bin_kind);
        binary::BinaryImage& b = *img;
        step("Разбираю " + bin_kind + " и релокации");
        detail("сегментов: " + thousands(b.segments().size()) +
               ", релокаций: " + thousands(b.reloc_count()));
        detail("источник релокаций: " + b.reloc_source());

        // Проверка на упаковку. Если упакована — не пытаемся выдать мусор,
        // а честно говорим что делать (совет зависит от формата/платформы).
        auto pk = b.packing_check();
        if (pk.packed) {
            if (bin_kind == "PE") {
                throw BinaryError(
                    "GameAssembly.dll УПАКОВАН — таблицы в файле не восстановить.\n\n  " +
                    pk.why +
                    "\n\n  Сдампь GameAssembly.dll из памяти запущенной игры\n"
                    "  (например Process Hacker / Scylla) и повтори на дампе.");
            }
            throw BinaryError(
                "библиотека УПАКОВАНА — таблицы в файле отсутствуют.\n\n  " + pk.why +
                "\n\n  Из файла на диске тут не выйти. Сдампь libil2cpp.so\n"
                "  из памяти запущенной игры (нужен root или эмулятор):\n"
                "    cat /proc/<pid>/maps | grep libil2cpp   # найти диапазон\n"
                "    dd if=/proc/<pid>/mem bs=1 skip=... count=... > libil2cpp.so\n"
                "  Метадату обычно можно брать из APK как есть.");
        }

        step("Ищу MetadataRegistration");
        auto mr_opt = b.find_metadata_registration(L->typedef_count);
        if (!mr_opt) {
            throw BinaryError(
                "MetadataRegistration не найдена. Возможно libil2cpp пропатчена,\n"
                "  или число типов сильно расходится. Запусти с --verbose\n"
                "  и приложи вывод к отчёту.");
        }
        detail("types[] @ " + hex(mr_opt->types) +
               ", элементов " + thousands(mr_opt->types_count));

        // ── сверка пары файлов ─────────────────────────────────────────────
        step("Сверяю метаданные с бинарником");
        metadata::TDLayout def = metadata::default_v39();
        auto pair = metadata::check_pair(*md, *L, b, bin.view(), *mr_opt,
                                         def.rec_size, def.byval_type);
        detail(pair.report());
        double pair_ratio = pair.ratio();
        if (!pair.matched()) {
            if (a.skip_pair) {
                warn("файлы из РАЗНЫХ сборок (" +
                     std::to_string(static_cast<int>(pair_ratio * 100)) +
                     "%) — типы будут неверными");
            } else {
                throw PairMismatch(pair.error_text());
            }
        }

        // ── раскладка записи типа ─────────────────────────────────────────
        step("Определяю раскладку Il2CppTypeDefinition");
        metadata::TDLayout td = metadata::detect(*md, *L, b, bin.view(), *mr_opt, &def);
        detail(td.report());

        // ── fieldOffsets в libil2cpp ──────────────────────────────────────
        step("Ищу таблицу смещений полей");
        u64 fo_table = b.find_field_offsets(mr_opt->base, L->typedef_count);
        if (fo_table) detail("fieldOffsets @ " + hex(fo_table));
        else warn("fieldOffsets не найдена — смещения будут нулевыми");

        // ── модель ────────────────────────────────────────────────────────
        model::MetadataRegistration mr(*mr_opt, fo_table);
        // Дочитываем расширенные поля MR (generic-классы, methodSpecs) по
        // фиксированным смещениям от base. Без них генерики просто не
        // перечислятся — модель и остальные файлы соберутся как раньше.
        {
            auto ext = b.read_mr_extended(mr_opt->base);
            mr.generic_classes = ext.generic_classes;
            mr.generic_classes_count = ext.generic_classes_count;
            mr.generic_insts = ext.generic_insts;
            mr.generic_insts_count = ext.generic_insts_count;
            mr.method_specs = ext.method_specs;
            mr.method_specs_count = ext.method_specs_count;
        }
        model::Model m(*md, *L, b, mr, td);
        m.detect_params();

        // ── usage-таблицы (метод → ссылки на метадату) ────────────────────
        // Опознаются в конструкторе модели; печатаем итог. Если не опознаны —
        // деобфускация пойдёт запасным путём (дизассемблер, --xref-names).
        if (m.usages().usable()) {
            detail("usage-таблицы: " + thousands(m.usages().method_count()) +
                   " методов, " + thousands(m.usages().pair_count()) + " пар");
        } else {
            detail("usage-таблицы не опознаны (вероятно вырезаны обфускатором)");
        }

        // ── адреса методов ─────────────────────────────────────────────────
        step("Ищу таблицы адресов методов");
        auto mp = elf::find_method_pointers(bin.view(), b,
                                            std::max<u32>(L->image_count, 32));
        if (mp.arr) {
            m.attach_method_pointers(mp.arr, mp.count);
            detail(mp.module + ": " + thousands(mp.count) +
                   " методов @ " + hex(mp.arr));
        } else {
            warn("codeGenModules не найдены — RVA методов будут пустыми");
        }

        // ── деобфускация по кросс-рефам строк (--xref-names) ──────────────
        // По каждому обфусцированному методу с известным RVA дизассемблируем
        // начало тела и ищем ADRP+ADD/LDR к строковому литералу. Первая
        // осмысленная строка становится подсказкой в dump.cs / offsets.h.
        // Пасс стоит секунд, поэтому включается флагом.
        if (a.xref_names && mp.arr) {
            step("Собираю подсказки по строкам (--xref-names)");
            auto hints = analysis::build_hints(m, bin.view(), b);
            detail("подсказок собрано: " + thousands(hints.size()));
            analysis::set_active_hints(std::move(hints));
        }

        // ── generic-инстансы ───────────────────────────────────────────────
        // Перечисляем все Il2CppGenericClass (List<int>, Dictionary<...>).
        // Строим после подключения methodPointers, чтобы имена раскрывались
        // полностью. Если поля MR не нашлись — таблица пустая, файл-заглушка.
        step("Перечисляю generic-инстансы");
        model::GenericInstanceTable gt = model::GenericInstanceTable::load(m, b);
        if (gt.loaded()) {
            detail("generic-инстансов: " + thousands(gt.count()));
        } else {
            detail("genericClasses[] не найдены — generics.txt будет заглушкой");
        }

        // ── генерация ──────────────────────────────────────────────────────
        auto pcs = [&](u64 c, u64 t){
            static Progress pg{!a.quiet, "dump.cs"};
            pg.tick(c, t);
        };
        auto ph = [&](u64 c, u64 t){
            static Progress pg{!a.quiet, "il2cpp.h"};
            pg.tick(c, t);
        };
        auto pj = [&](u64 c, u64 t){
            static Progress pg{!a.quiet, "script.json"};
            pg.tick(c, t);
        };
        step("Генерирую il2cpp.h");
        std::string il2cpp_h = output::gen_il2cpp_h(m, ph);
        step("Генерирую dump.cs");
        std::string dump_cs = output::gen_dump_cs(m, pcs, &gt);
        step("Генерирую script.json");
        std::string script_json = output::gen_script_json(m, pj);
        step("Генерирую offsets.h");
        std::string offsets_h = output::gen_offsets_h(m);
        step("Генерирую offsets.cs");
        std::string offsets_cs = output::gen_offsets_cs(m);
        step("Генерирую types.txt");
        std::string types_txt = output::gen_types_txt(m);
        step("Генерирую generics.txt");
        std::string generics_txt = output::gen_generics_txt(m, gt);
        step("Генерирую ida_script.py");
        std::string ida_script = output::gen_ida_script(m);
        step("Генерирую ghidra_script.py");
        std::string ghidra_script = output::gen_ghidra_script(m);
        step("Генерирую structs.h");
        std::string structs_h = output::gen_structs_h(m);

        // ── отчёт ─────────────────────────────────────────────────────────
        output::Summary sum;
        sum.typedef_count = L->typedef_count;
        sum.bin_size = bin.size();
        sum.reloc_count = b.reloc_count();
        sum.reloc_source = b.reloc_source();
        sum.packed = pk.packed;
        sum.packing_zeros = pk.zeros_ratio;
        sum.packing_why = pk.why;
        sum.pair_ratio = pair_ratio;
        sum.main_module = mp.module;
        sum.main_module_methods = mp.count;
        sum.main_module_rva = mp.arr;
        sum.headerless = headerless;
        // Считаем методы с RVA по script.json
        {
            std::size_t n = 0, pos = 0;
            const char* key = "\"Address\":";
            while ((pos = script_json.find(key, pos)) != std::string::npos) {
                ++n; pos += 10;
            }
            sum.methods_with_rva = n;
        }

        step("Собираю отчёт");
        std::string report = output::gen_report(*md, *L, b, mr, m, sum);

        // ── архив ─────────────────────────────────────────────────────────
        // По умолчанию текстовые файлы жмём DEFLATE (method 8) — архив
        // уменьшается с ~99 МБ до ~25-30 МБ, а unzip везде понимает DEFLATE.
        // Флаг --no-compress пишет всё STORED (крупный архив, но нулевой оверхед).
        step(std::string("Пишу архив ") + a.out_path +
             (a.compress ? " (DEFLATE)" : " (STORED)"));
        {
            io::ZipWriter zw(a.out_path);
            if (!zw.ok()) throw std::runtime_error("не могу открыть архив на запись");
            // Все наши выходные файлы — текст, поэтому при --compress все идут
            // через add_deflated. Бинарных вложений сейчас нет; если появятся —
            // их следует класть через zw.add (STORED).
            auto put = [&](const std::string& name, const std::string& data) {
                if (a.compress) zw.add_deflated(name, data);
                else            zw.add(name, data);
            };
            put("dump.cs", dump_cs);
            put("il2cpp.h", il2cpp_h);
            put("script.json", script_json);
            put("offsets.h", offsets_h);
            put("offsets.cs", offsets_cs);
            put("types.txt", types_txt);
            put("generics.txt", generics_txt);
            put("ida_script.py", ida_script);
            put("ghidra_script.py", ghidra_script);
            put("structs.h", structs_h);
            put("REPORT.txt", report);
        }

        // ── итог ──────────────────────────────────────────────────────────
        // Размер архива через <filesystem> — портируемо (Linux/Mac/Windows).
        std::error_code ec;
        auto fsz = std::filesystem::file_size(a.out_path, ec);
        u64 arch_size = ec ? 0 : static_cast<u64>(fsz);
        double elapsed = g_timer.elapsed_s();

        if (a.quiet) {
            std::puts(a.out_path.c_str());
        } else {
            std::printf("\n==============================================================\n"
                        "  ГОТОВО за %.1fs\n"
                        "==============================================================\n"
                        "  архив     : %s  (%.1f МБ)\n"
                        "  метаданные: v%u, ключ 0x%08X%s\n"
                        "  типов     : %s\n"
                        "  types[]   : 0x%llX (%s)\n",
                        elapsed, a.out_path.c_str(), arch_size / 1024.0 / 1024.0,
                        md->version(), md->key(),
                        md->transform() ? (std::string(" [") + md->transform()->name() + "]").c_str() : "",
                        thousands(L->typedef_count).c_str(),
                        (unsigned long long)mr_opt->types,
                        thousands(mr_opt->types_count).c_str());
            if (mp.count) {
                std::printf("  %s: %s методов\n",
                            mp.module.c_str(), thousands(mp.count).c_str());
            }
            std::printf("\n    dump.cs         %s байт\n"
                        "    il2cpp.h        %s байт\n"
                        "    script.json     %s байт\n"
                        "    offsets.h       %s байт\n"
                        "    offsets.cs      %s байт\n"
                        "    types.txt       %s байт\n"
                        "    generics.txt    %s байт\n"
                        "    ida_script.py   %s байт\n"
                        "    ghidra_script.py %s байт\n"
                        "    structs.h       %s байт\n"
                        "    REPORT.txt      %s байт\n\n",
                        thousands(dump_cs.size()).c_str(),
                        thousands(il2cpp_h.size()).c_str(),
                        thousands(script_json.size()).c_str(),
                        thousands(offsets_h.size()).c_str(),
                        thousands(offsets_cs.size()).c_str(),
                        thousands(types_txt.size()).c_str(),
                        thousands(generics_txt.size()).c_str(),
                        thousands(ida_script.size()).c_str(),
                        thousands(ghidra_script.size()).c_str(),
                        thousands(structs_h.size()).c_str(),
                        thousands(report.size()).c_str());
        }
        return 0;

    } catch (const PairMismatch& e) {
        std::fprintf(stderr, "\n%s\n", e.what());
        return 3;
    } catch (const MetadataError& e) {
        std::fprintf(stderr, "\nНЕ УДАЛОСЬ РАЗОБРАТЬ МЕТАДАТУ:\n\n%s\n", e.what());
        return 1;
    } catch (const BinaryError& e) {
        std::fprintf(stderr, "\nНЕ УДАЛОСЬ РАЗОБРАТЬ БИНАРНИК:\n\n%s\n", e.what());
        return 1;
    } catch (const std::exception& e) {
        std::fprintf(stderr, "\nВНУТРЕННЯЯ ОШИБКА: %s\n", e.what());
        return 1;
    }
}
