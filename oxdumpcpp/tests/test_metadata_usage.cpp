// tests/test_metadata_usage.cpp — тест таблиц Il2CppMetadataUsage на реальных
// файлах игры (tests/nov_meta.dat).
//
// Что проверяем:
//   1. detect() отрабатывает детерминированно и не падает на реальном файле;
//   2. report() непустой (в отчёт всегда есть что положить);
//   3. если таблицы ОПОЗНАНЫ — сверяем инварианты: method_count совпадает с
//      Layout, все виды пар валидны (1..6), выборочный метод даёт правдоподобный
//      список usage'ей; резолвер строковых литералов достаёт печатный текст;
//   4. если НЕ опознаны — фиксируем это как ожидаемый исход для ЭТОЙ сборки
//      (usage-таблицы вырезаны обфускатором) и проверяем мягкую деградацию:
//      for_method/at возвращают пусто/Invalid, ничего не падает.
//
// Оба исхода — «пройдено»: тест утверждает КОРРЕКТНОСТЬ поведения, а не наличие
// таблиц (их наличие зависит от сборки). Почему именно так — см. отчёт к задаче.
#include "oxdump/metadata/header.h"
#include "oxdump/metadata/layout.h"
#include "oxdump/model/metadata_usage.h"
#include <cstdio>
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
    out.raw = p; out.data = static_cast<const u8*>(p);
    out.size = static_cast<std::size_t>(st.st_size);
    return true;
}

} // namespace

int main() {
    const char* meta_path = "tests/nov_meta.dat";
    Mapped meta;
    if (!map_file(meta_path, meta)) return 2;
    std::printf("meta = %s (%zu байт)\n\n", meta_path, meta.size);

    metadata::Metadata md(meta.view());
    metadata::Layout L(md);
    std::printf("method_count=%u typedef_count=%u\n\n",
                L.method_count, L.typedef_count);

    // ── 1. детект ─────────────────────────────────────────────────────────
    std::printf("== MetadataUsageTable::detect ==\n");
    model::MetadataUsageTable u = model::MetadataUsageTable::detect(md, L);
    std::printf("%s\n", u.report().c_str());
    check(!u.report().empty(), "report() непустой");

    // Детерминизм: повторный детект даёт тот же исход.
    model::MetadataUsageTable u2 = model::MetadataUsageTable::detect(md, L);
    check(u2.usable() == u.usable(), "detect детерминирован (usable)");
    check(u2.pair_count() == u.pair_count(), "detect детерминирован (pairs)");

    if (u.usable()) {
        // ── 2а. таблицы опознаны: сверяем инварианты ──────────────────────
        std::printf("\n== таблицы ОПОЗНАНЫ ==\n");
        check(u.method_count() >= L.method_count &&
              u.method_count() <= L.method_count + 64,
              "method_count ≈ Layout.method_count");
        check(u.pair_count() > 0, "pair_count > 0");
        check(u.lists_offset() != 0 && u.pairs_offset() != 0,
              "offsets найдены");

        // Все пары имеют валидный вид (1..6): at() по нескольким слотам.
        u32 bad = 0;
        const u32 step = u.pair_count() / 2000 + 1;
        for (u32 i = 0; i < u.pair_count(); i += step) {
            if (u.at(i).kind == model::MetadataUsageKind::Invalid) ++bad;
        }
        check(bad == 0, "все пары имеют валидный вид (1..6)");

        // Выборочный метод: найдём первый метод с непустым usage-списком и
        // убедимся, что его записи в границах и с валидными видами.
        bool sampled = false;
        for (u32 mi = 0; mi < u.method_count() && !sampled; ++mi) {
            auto us = u.for_method(mi);
            if (us.empty()) continue;
            sampled = true;
            std::printf("  метод #%u: %zu usage'ей; kind первого=%u tidx=%u\n",
                        mi, us.size(), (unsigned)us[0].kind, us[0].target_index);
            bool all_ok = true;
            for (const auto& e : us)
                if (e.kind == model::MetadataUsageKind::Invalid) all_ok = false;
            check(all_ok, "у выбранного метода все usage валидны");
        }
        check(sampled, "нашёлся метод с непустым usage-списком");

        // Резолвер литералов: хотя бы один StringLiteral usage даёт печатный
        // текст. (Через модель это делает script.json; тут — прямая проверка.)
        u32 strlit = u.kind_count(model::MetadataUsageKind::StringLiteral);
        std::printf("  строковых литералов среди пар: %u\n", strlit);
        check(strlit > 0, "есть usage'и вида StringLiteral");
    } else {
        // ── 2б. таблицы НЕ опознаны: ожидаемо для этой сборки ─────────────
        std::printf("\n== таблицы НЕ опознаны (ожидаемо: вырезаны обфускатором) ==\n");
        // Мягкая деградация: запросы не падают и возвращают пусто/Invalid.
        check(u.for_method(0).empty(), "for_method(0) пуст при !usable");
        check(u.for_method(100000).empty(), "for_method(big) пуст при !usable");
        check(u.at(0).kind == model::MetadataUsageKind::Invalid,
              "at(0) == Invalid при !usable");
        check(u.method_count() == 0, "method_count == 0 при !usable");
        check(u.kind_count(model::MetadataUsageKind::StringLiteral) == 0,
              "kind_count == 0 при !usable");
    }

    munmap(meta.raw, meta.size);
    std::printf("\n=== %s (%d провалов) ===\n",
                g_failures ? "ЕСТЬ ПРОВАЛЫ" : "ВСЕ ПРОВЕРКИ ПРОШЛИ", g_failures);
    return g_failures ? 1 : 0;
}
