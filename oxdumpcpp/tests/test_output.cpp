// tests/test_output.cpp — интеграционный тест генераторов вывода на реальных
// файлах игры (nov_meta.dat ~27 МБ, nov_bin.so ~200 МБ).
//
// Строит всю цепочку (Metadata → Layout → ELF → MR → TDLayout → Model),
// прогоняет каждый генератор, пишет файлы в /tmp/oxdumpcpp_out/ и проверяет их
// размеры и содержимое против эталонных значений питоновского дампера.
//
// Таблицы адресов методов (codeGenModules) в C++-обёртке ELF не ищутся —
// поэтому находим их здесь, локально: разбираем DT_RELA из сырых байтов и по
// значениям релокаций опознаём массив модулей (первое поле — имя "*.dll").
// Это калька с binary.py::find_codegen_modules, вынесенная в тест.
#include "oxdump/model/model.h"
#include "oxdump/output/generators.h"
#include "oxdump/metadata/pairing.h"
#include "oxdump/elf/elf64.h"
#include "oxdump/elf/codegen.h"
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

using namespace oxdump;

namespace {

int g_failures = 0;

void check(bool cond, const char* what) {
    std::printf("  [%s] %s\n", cond ? "OK " : "FAIL", what);
    if (!cond) ++g_failures;
}

struct Mapped {
    const u8* data = nullptr;
    std::size_t size = 0;
    void* raw = nullptr;
    ByteView view() const { return ByteView{data, size}; }
};

bool map_file(const char* path, Mapped& out) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) { std::perror(path); return false; }
    struct stat st{};
    if (fstat(fd, &st) != 0) { std::perror("fstat"); close(fd); return false; }
    void* p = mmap(nullptr, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);
    if (p == MAP_FAILED) { std::perror("mmap"); return false; }
    out.raw = p;
    out.data = static_cast<const u8*>(p);
    out.size = static_cast<std::size_t>(st.st_size);
    return true;
}

// Записать строку в файл целиком. Возвращает число записанных байт или 0.
std::size_t write_file(const std::string& path, const std::string& data) {
    int fd = open(path.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) { std::perror(path.c_str()); return 0; }
    std::size_t off = 0;
    while (off < data.size()) {
        ssize_t w = write(fd, data.data() + off, data.size() - off);
        if (w <= 0) break;
        off += static_cast<std::size_t>(w);
    }
    close(fd);
    return off;
}

bool contains(const std::string& hay, const char* needle) {
    return hay.find(needle) != std::string::npos;
}

// ── поиск таблицы адресов методов (локальная калька binary.py) ───────────────
//
// Собираем ЗНАЧЕНИЯ релокаций (addend'ы, ведущие внутрь образа) прямо из
// DT_RELA, затем каждое пробуем как массив указателей на Il2CppCodeGenModule.
// Модуль опознаём по первому полю — указателю на имя, оканчивающееся ".dll".
struct MethodPointers { u64 arr = 0; u32 count = 0; std::string module; };

// Читает ASCII-имя из бинарника по VA (имена не релоцируются — ptr() отдаёт
// сырые байты; читаем по 8 и режем на первом нуле).
std::string read_name(const elf::Elf64& elf, ByteView bin, u64 va) {
    const auto fo = elf.va2fo(va);
    if (!fo) return {};
    std::string s;
    for (u32 k = 0; k < 128 && *fo + k < bin.size; ++k) {
        const char c = static_cast<char>(bin.data[*fo + k]);
        if (c == 0) break;
        s += c;
    }
    return s;
}

bool ends_with(const std::string& s, const char* suf) {
    const std::size_t n = std::strlen(suf);
    return s.size() >= n && s.compare(s.size() - n, n, suf) == 0;
}

// Все addend'ы RELATIVE-релокаций, ведущие внутрь образа. Разбор DT_RELA
// повторяет elf64.cpp; для AArch64 тип RELATIVE == 1027.
std::vector<u64> reloc_values(ByteView bin, const elf::Elf64& elf) {
    std::vector<u64> vals;
    const auto dyn = elf.dynamic_offset();
    const auto rrel = elf.r_relative();
    if (!dyn || !rrel) return vals;

    u64 rela_va = 0, rela_sz = 0, rela_ent = 24;
    u64 o = *dyn;
    while (o + 16 <= bin.size) {
        const s64 tag = bin.read_s64(o);
        const u64 val = bin.read_u64(o + 8);
        o += 16;
        if (tag == 0) break;            // DT_NULL
        else if (tag == 7) rela_va = val;   // DT_RELA
        else if (tag == 8) rela_sz = val;   // DT_RELASZ
        else if (tag == 9) rela_ent = val;  // DT_RELAENT
    }
    if (!rela_va || !rela_sz) return vals;
    const auto rela_fo = elf.va2fo(rela_va);
    if (!rela_fo) return vals;
    if (rela_ent == 0) rela_ent = 24;

    const u64 cnt = rela_sz / rela_ent;
    vals.reserve(cnt);
    for (u64 k = 0; k < cnt; ++k) {
        const u64 base = *rela_fo + k * rela_ent;
        if (base + 24 > bin.size) break;
        const u64 r_info = bin.read_u64(base + 8);
        const s64 r_add = bin.read_s64(base + 16);
        if ((r_info & 0xFFFFFFFF) != *rrel) continue;
        if (r_add != 0 && elf.va2fo(static_cast<u64>(r_add)))
            vals.push_back(static_cast<u64>(r_add));
    }
    return vals;
}

MethodPointers find_method_pointers(ByteView bin, const elf::Elf64& elf,
                                    u32 image_count) {
    MethodPointers out;
    const std::vector<u64> vals = reloc_values(bin, elf);

    // Лучший кандидат в codeGenModules: массив, где больше всего подряд идущих
    // валидных модулей с именем "*.dll".
    u64 best_arr = 0;
    int best_ok = 0;
    std::string main_module_va_name;
    u64 main_module_va = 0;

    const u32 lim = image_count < 64 ? image_count : 64;
    for (u64 val : vals) {
        if (!elf.is_valid_va(val)) continue;
        int ok = 0;
        u64 asm_csharp = 0;
        for (u32 i = 0; i < lim; ++i) {
            const u64 p = elf.ptr(val + static_cast<u64>(i) * 8);
            if (!elf.is_valid_va(p)) break;
            const u64 name_ptr = elf.ptr(p);
            if (!elf.is_valid_va(name_ptr)) break;
            const std::string nm = read_name(elf, bin, name_ptr);
            if (!ends_with(nm, ".dll")) break;
            if (nm == "Assembly-CSharp.dll") asm_csharp = p;
            ++ok;
        }
        if (ok >= 8 && ok > best_ok) {
            best_ok = ok;
            best_arr = val;
            main_module_va = asm_csharp;
            main_module_va_name = "Assembly-CSharp.dll";
        }
    }
    if (!best_arr || !main_module_va) return out;

    // module_method_pointers: count по +8, массив по +16.
    const auto fo = elf.va2fo(main_module_va);
    if (!fo) return out;
    const u32 cnt = bin.read_u32(*fo + 8);
    const u64 arr = elf.ptr(main_module_va + 16);
    if (cnt > 2000000 || !elf.is_valid_va(arr)) return out;
    out.arr = arr;
    out.count = cnt;
    out.module = main_module_va_name;
    return out;
}

} // namespace

int main() {
    const char* meta_path = "tests/nov_meta.dat";
    const char* bin_path = "tests/nov_bin.so";
    const std::string outdir = "/tmp/oxdumpcpp_out";
    mkdir(outdir.c_str(), 0755);

    Mapped meta, bin;
    if (!map_file(meta_path, meta)) return 2;
    if (!map_file(bin_path, bin)) { munmap(meta.raw, meta.size); return 2; }
    std::printf("meta = %s (%zu байт)\nbin  = %s (%zu байт)\n\n",
                meta_path, meta.size, bin_path, bin.size);

    // ── сборка модели ────────────────────────────────────────────────────
    metadata::Metadata md(meta.view());
    std::printf("%s\n", md.key_report().c_str());
    metadata::Layout L(md);
    std::printf("%s\n", L.report().c_str());
    check(L.ok(), "layout.ok()");

    elf::Elf64 elf(bin.view());
    auto cand = elf.find_metadata_registration(L.typedef_count);
    check(cand.has_value(), "MetadataRegistration найден");
    if (!cand) { std::printf("нет MR — дальше нельзя\n"); return 1; }

    auto pk = elf.packing_check();
    auto pc = metadata::check_pair(md, L, elf, bin.view(), *cand, 82, 0x08);

    metadata::TDLayout def = metadata::default_v39();
    metadata::TDLayout td = metadata::detect(md, L, elf, bin.view(), *cand, &def);
    const u64 fo_table = elf.find_field_offsets(cand->base, L.typedef_count);

    model::MetadataRegistration mr(*cand, fo_table);
    model::Model m(md, L, elf, mr, td);
    m.detect_params();

    // Адреса методов: находим таблицу и подключаем к модели.
    MethodPointers mp = find_method_pointers(bin.view(), elf,
                                             std::max<u32>(L.image_count, 32));
    if (mp.arr) {
        m.attach_method_pointers(mp.arr, mp.count);
        std::printf("methodPointers: %s методов @ %s (%s)\n",
                    thousands(mp.count).c_str(), hex(mp.arr).c_str(),
                    mp.module.c_str());
    } else {
        std::printf("ВНИМАНИЕ: methodPointers не найдены — RVA будут пусты\n");
    }
    check(mp.arr != 0, "methodPointers (Assembly-CSharp) найдены");
    std::printf("\n");

    // ── генерация ────────────────────────────────────────────────────────
    auto prog = [](const char*){};
    (void)prog;

    std::printf("генерирую dump.cs ...\n");
    std::string dump_cs = output::gen_dump_cs(m);
    std::printf("генерирую il2cpp.h ...\n");
    std::string il2cpp_h = output::gen_il2cpp_h(m);
    std::printf("генерирую script.json ...\n");
    std::string script_json = output::gen_script_json(m);
    std::printf("генерирую offsets.h ...\n");
    std::string offsets_h = output::gen_offsets_h(m);

    // Сводка для отчёта.
    output::Summary sum;
    sum.typedef_count = L.typedef_count;
    sum.bin_size = bin.size;
    sum.reloc_count = elf.reloc_count();
    sum.reloc_source = elf.reloc_source();
    sum.packed = pk.packed;
    sum.packing_zeros = pk.zeros_ratio;
    sum.packing_why = pk.why;
    sum.pair_ratio = pc.ratio();
    sum.main_module = mp.module;
    sum.main_module_methods = mp.count;
    sum.main_module_rva = mp.arr;
    // Число методов с RVA в script.json — считаем по числу записей "Address".
    {
        std::size_t n = 0, pos = 0;
        const char* key = "\"Address\":";
        while ((pos = script_json.find(key, pos)) != std::string::npos) {
            ++n; pos += 10;
        }
        sum.methods_with_rva = n;
    }
    std::printf("генерирую REPORT.txt ...\n");
    std::string report = output::gen_report(md, L, elf, mr, m, sum);

    // ── запись файлов ─────────────────────────────────────────────────────
    const std::size_t n_cs   = write_file(outdir + "/dump.cs", dump_cs);
    const std::size_t n_h    = write_file(outdir + "/il2cpp.h", il2cpp_h);
    const std::size_t n_json = write_file(outdir + "/script.json", script_json);
    const std::size_t n_off  = write_file(outdir + "/offsets.h", offsets_h);
    const std::size_t n_rep  = write_file(outdir + "/REPORT.txt", report);

    std::printf("\nразмеры вывода:\n");
    std::printf("  dump.cs     = %s байт\n", thousands(n_cs).c_str());
    std::printf("  il2cpp.h    = %s байт\n", thousands(n_h).c_str());
    std::printf("  script.json = %s байт\n", thousands(n_json).c_str());
    std::printf("  offsets.h   = %s байт\n", thousands(n_off).c_str());
    std::printf("  REPORT.txt  = %s байт\n\n", thousands(n_rep).c_str());

    // ── проверки ──────────────────────────────────────────────────────────
    check(n_cs > 20u * 1024 * 1024, "dump.cs > 20 MB");
    check(contains(dump_cs, "public class PlayerManager"),
          "dump.cs содержит \"public class PlayerManager\"");
    check(contains(dump_cs, "kccReference; // 0xB0"),
          "dump.cs содержит \"kccReference; // 0xB0\"");

    check(n_h > 5u * 1024 * 1024, "il2cpp.h > 5 MB");
    check(contains(il2cpp_h, "struct PlayerManager_o"),
          "il2cpp.h содержит \"struct PlayerManager_o\"");

    check(n_json > 10u * 1024 * 1024, "script.json > 10 MB");
    check(contains(script_json, "ScriptMethod"),
          "script.json содержит \"ScriptMethod\"");

    check(contains(offsets_h, "PLAYERMANAGER_TDI"),
          "offsets.h содержит \"PLAYERMANAGER_TDI\"");
    check(contains(offsets_h, "PLAYERMANAGER_TYPE_IDX"),
          "offsets.h содержит \"PLAYERMANAGER_TYPE_IDX\"");

    check(contains(report, "ключ восстановлен: 0xA5C3F19D"),
          "REPORT.txt содержит \"ключ восстановлен: 0xA5C3F19D\"");
    check(contains(report, "PlayerManager"),
          "REPORT.txt содержит \"PlayerManager\"");
    check(contains(report, "полей=136"),
          "REPORT.txt содержит \"полей=136\"");

    munmap(meta.raw, meta.size);
    munmap(bin.raw, bin.size);

    std::printf("\n=== %s (%d провалов) ===\n",
                g_failures ? "ЕСТЬ ПРОВАЛЫ" : "ВСЕ ПРОВЕРКИ ПРОШЛИ", g_failures);
    return g_failures ? 1 : 0;
}
