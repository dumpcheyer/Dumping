// tests/test_generics.cpp — интеграционный тест таблицы generic-инстансов на
// реальных файлах игры (nov_meta.dat ~27 МБ, nov_bin.so ~200 МБ).
//
// Строит полную модель (Metadata → Layout → ELF → MR → TDLayout → Model),
// дочитывает расширенные поля MetadataRegistration (genericClasses[] и т.п.),
// строит GenericInstanceTable и проверяет:
//   - таблица построена (loaded), инстансов > 1000;
//   - у System.Collections.Generic.List несколько инстанциаций;
//   - печатает топ-20 крупнейших generic-семейств (по числу инстанциаций).
//
// Метод-пойнтеры (codeGenModules) для генериков не нужны: имена раскрываются
// из самих Il2CppType*, поэтому здесь их не ищем — тест короче, чем test_output.
#include "oxdump/model/model.h"
#include "oxdump/model/generics.h"
#include "oxdump/metadata/pairing.h"
#include "oxdump/elf/elf64.h"
#include <algorithm>
#include <cstdio>
#include <string>
#include <unordered_map>
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

// Индекс typedef по полному имени (первое совпадение). Нужен, чтобы найти
// System.Collections.Generic.List без привязки к конкретному TDI сборки.
s32 find_typedef(model::Model& m, const char* full_name) {
    const u32 total = m.layout().typedef_count;
    for (u32 i = 0; i < total; ++i) {
        if (m.full_name(static_cast<s32>(i)) == full_name)
            return static_cast<s32>(i);
    }
    return -1;
}

} // namespace

int main() {
    const char* meta_path = "tests/nov_meta.dat";
    const char* bin_path = "tests/nov_bin.so";

    Mapped meta, bin;
    if (!map_file(meta_path, meta)) return 2;
    if (!map_file(bin_path, bin)) { munmap(meta.raw, meta.size); return 2; }
    std::printf("meta = %s (%zu байт)\nbin  = %s (%zu байт)\n\n",
                meta_path, meta.size, bin_path, bin.size);

    // ── сборка модели ────────────────────────────────────────────────────
    metadata::Metadata md(meta.view());
    metadata::Layout L(md);
    check(L.ok(), "layout.ok()");

    elf::Elf64 elf(bin.view());
    auto cand = elf.find_metadata_registration(L.typedef_count);
    check(cand.has_value(), "MetadataRegistration найден");
    if (!cand) { std::printf("нет MR — дальше нельзя\n"); return 1; }

    metadata::TDLayout def = metadata::default_v39();
    metadata::TDLayout td = metadata::detect(md, L, elf, bin.view(), *cand, &def);
    const u64 fo_table = elf.find_field_offsets(cand->base, L.typedef_count);

    model::MetadataRegistration mr(*cand, fo_table);
    // Дочитываем расширенные поля MR (генерики, methodSpecs).
    auto ext = elf.read_mr_extended(cand->base);
    mr.generic_classes = ext.generic_classes;
    mr.generic_classes_count = ext.generic_classes_count;
    mr.generic_insts = ext.generic_insts;
    mr.generic_insts_count = ext.generic_insts_count;
    mr.method_specs = ext.method_specs;
    mr.method_specs_count = ext.method_specs_count;

    std::printf("MR: genericClasses @ %s (%s), methodSpecs @ %s (%s)\n",
                hex(mr.generic_classes).c_str(),
                thousands(mr.generic_classes_count).c_str(),
                hex(mr.method_specs).c_str(),
                thousands(mr.method_specs_count).c_str());
    check(mr.generic_classes != 0, "MR.genericClasses прочитан");

    model::Model m(md, L, elf, mr, td);
    m.detect_params();

    // ── таблица генериков ────────────────────────────────────────────────
    std::printf("\nстрою таблицу generic-инстансов ...\n");
    model::GenericInstanceTable gt = model::GenericInstanceTable::load(m, elf);
    check(gt.loaded(), "GenericInstanceTable.loaded()");
    std::printf("generic-инстансов: %s\n", thousands(gt.count()).c_str());
    std::printf("methodSpecs распознано: %s\n\n",
                thousands(gt.method_specs().size()).c_str());

    check(gt.count() > 1000, "инстансов > 1000");

    // ── List должен иметь несколько инстанциаций ─────────────────────────
    const s32 list_idx = find_typedef(m, "System.Collections.Generic.List");
    check(list_idx >= 0, "нашёл typedef System.Collections.Generic.List");
    if (list_idx >= 0) {
        auto list_inst = gt.instances_of(static_cast<u32>(list_idx));
        std::printf("System.Collections.Generic.List (TDI=%d): %zu инстанциаций\n",
                    list_idx, list_inst.size());
        for (std::size_t k = 0; k < std::min<std::size_t>(list_inst.size(), 8); ++k)
            std::printf("    %s\n", list_inst[k]->display_name.c_str());
        check(list_inst.size() > 1, "List имеет несколько инстанциаций");
    }

    // ── by_va кросс-поиск (проверка индекса) ─────────────────────────────
    if (!gt.all().empty()) {
        const u64 va = gt.all().front().va;
        const model::GenericInstance* found = gt.by_va(va);
        check(found != nullptr && found->va == va, "by_va находит инстанс по VA");
    }

    // ── топ-20 крупнейших generic-семейств ───────────────────────────────
    std::unordered_map<u32, u32> family_count;   // base typedef idx -> число
    for (const auto& gi : gt.all())
        if (gi.base_type_idx != 0xFFFFFFFFu) ++family_count[gi.base_type_idx];

    std::vector<std::pair<u32, u32>> fams(family_count.begin(), family_count.end());
    std::sort(fams.begin(), fams.end(),
              [](const std::pair<u32, u32>& a, const std::pair<u32, u32>& b) {
                  return a.second > b.second;
              });

    std::printf("\nтоп-20 generic-семейств по числу инстанциаций:\n");
    for (std::size_t k = 0; k < std::min<std::size_t>(fams.size(), 20); ++k) {
        const u32 tdi = fams[k].first;
        std::printf("  %5u  %s\n", fams[k].second,
                    m.full_name(static_cast<s32>(tdi)).c_str());
    }

    munmap(meta.raw, meta.size);
    munmap(bin.raw, bin.size);

    std::printf("\n=== %s (%d провалов) ===\n",
                g_failures ? "ЕСТЬ ПРОВАЛЫ" : "ВСЕ ПРОВЕРКИ ПРОШЛИ", g_failures);
    return g_failures ? 1 : 0;
}
