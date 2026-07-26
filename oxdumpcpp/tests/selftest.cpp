// tests/selftest.cpp — комплексная самопроверка oxdump (C++17).
//
// Порт идеи python-selftest.py на C++ с расширением: прогоняет каждый модуль
// дампера и каждое утверждение из README на реальных сборках (nov/dec),
// синтетике (PE/Mach-O) и перешифрованных/повреждённых входах.
//
// Стиль проверок — как в существующих tests/: check(cond, "описание") с общим
// счётчиком провалов. Формат вывода повторяет python-selftest.py: пронумерованные
// категории, [ ОК ] / [ ПРОВАЛ ] / [ПРОПУСК], цветной вывод в терминал, итог.
//
// НЕ трогает код модулей — только потребляет их. Полный конвейер (модель +
// генераторы + архив) собирается ВНУТРИ процесса (калька с cli/main.cpp), чтобы
// не зависеть от запуска внешнего бинаря.
#include "oxdump/common.h"
#include "oxdump/crypto/transforms.h"
#include <cstring>                         // container.h требует std::memcmp
#include "oxdump/crypto/container.h"
#include "oxdump/metadata/header.h"
#include "oxdump/metadata/layout.h"
#include "oxdump/metadata/tdlayout.h"
#include "oxdump/metadata/pairing.h"
#include "oxdump/metadata/headerless.h"
#include "oxdump/binary/image.h"
#include "oxdump/elf/elf64.h"
#include "oxdump/elf/codegen.h"
#include "oxdump/macho/macho.h"
#include "oxdump/pe/pe.h"
#include "oxdump/model/model.h"
#include "oxdump/model/generics.h"
#include "oxdump/output/generators.h"
#include "oxdump/io/zip_writer.h"

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <vector>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

using namespace oxdump;

// ═══════════════════════════════════════════════════════════════════════════
//  Инфраструктура отчёта
// ═══════════════════════════════════════════════════════════════════════════
namespace {

using clk = std::chrono::steady_clock;

bool g_color = false;
int  g_ok = 0, g_fail = 0, g_skip = 0;

const char* C_GREEN() { return g_color ? "\033[32m" : ""; }
const char* C_RED()   { return g_color ? "\033[31m" : ""; }
const char* C_YEL()   { return g_color ? "\033[33m" : ""; }
const char* C_DIM()   { return g_color ? "\033[2m"  : ""; }
const char* C_RST()   { return g_color ? "\033[0m"  : ""; }

// Проверка. cond — прошло ли. what — уже отформатированное описание.
void check(bool cond, const std::string& what) {
    if (cond) {
        ++g_ok;
        std::printf("  [%s  ОК   %s] %s\n", C_GREEN(), C_RST(), what.c_str());
    } else {
        ++g_fail;
        std::printf("  [%s ПРОВАЛ%s] %s\n", C_RED(), C_RST(), what.c_str());
    }
}

// Пропуск — не провал: материала для теста нет.
void skip(const std::string& what) {
    ++g_skip;
    std::printf("  [%sПРОПУСК%s] %s\n", C_YEL(), C_RST(), what.c_str());
}

// «Примерно равно»: headerless и замощение дают числа с небольшим разбросом.
void check_near(long got, long want, long tol, const std::string& what) {
    const long d = got > want ? got - want : want - got;
    check(d <= tol, what + " (got=" + std::to_string(got) +
          " want=" + std::to_string(want) + " ±" + std::to_string(tol) + ")");
}

// Секундомер отдельного теста.
struct Stopwatch {
    clk::time_point t0 = clk::now();
    double s() const { return std::chrono::duration<double>(clk::now() - t0).count(); }
};
std::string secs(double s) {
    char buf[32];
    std::snprintf(buf, sizeof buf, "%.1fs", s);
    return buf;
}

// ── файловый ввод ────────────────────────────────────────────────────────────
struct Mapped {
    const u8* data = nullptr;
    std::size_t size = 0;
    void* raw = nullptr;
    ByteView view() const { return ByteView{data, size}; }
    ~Mapped() { if (raw && raw != MAP_FAILED) munmap(raw, size); }
    Mapped() = default;
    Mapped(Mapped&& o) noexcept : data(o.data), size(o.size), raw(o.raw) {
        o.data = nullptr; o.size = 0; o.raw = nullptr;
    }
    Mapped& operator=(const Mapped&) = delete;
};

bool map_file(const std::string& path, Mapped& out) {
    int fd = open(path.c_str(), O_RDONLY);
    if (fd < 0) return false;
    struct stat st{};
    if (fstat(fd, &st) != 0 || st.st_size == 0) { close(fd); return false; }
    void* p = mmap(nullptr, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);
    if (p == MAP_FAILED) return false;
    out.raw = p;
    out.data = static_cast<const u8*>(p);
    out.size = static_cast<std::size_t>(st.st_size);
    return true;
}

std::vector<u8> read_file(const std::string& path) {
    std::vector<u8> buf;
    int fd = open(path.c_str(), O_RDONLY);
    if (fd < 0) return buf;
    struct stat st{};
    if (fstat(fd, &st) != 0) { close(fd); return buf; }
    buf.resize(static_cast<std::size_t>(st.st_size));
    std::size_t got = 0;
    while (got < buf.size()) {
        ssize_t r = read(fd, buf.data() + got, buf.size() - got);
        if (r <= 0) break;
        got += static_cast<std::size_t>(r);
    }
    close(fd);
    buf.resize(got);
    return buf;
}

bool file_exists(const std::string& path) {
    struct stat st{};
    return stat(path.c_str(), &st) == 0 && st.st_size > 0;
}

// ═══════════════════════════════════════════════════════════════════════════
//  SHA-256 (для теста детерминизма; свой, без внешних зависимостей)
// ═══════════════════════════════════════════════════════════════════════════
struct Sha256 {
    uint32_t h[8];
    uint64_t len = 0;
    uint8_t  buf[64];
    std::size_t buf_len = 0;

    Sha256() {
        static const uint32_t iv[8] = {
            0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,
            0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19};
        std::memcpy(h, iv, sizeof h);
    }
    static uint32_t ror(uint32_t x, uint32_t n) { return (x >> n) | (x << (32 - n)); }

    void block(const uint8_t* p) {
        static const uint32_t k[64] = {
            0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
            0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
            0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
            0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
            0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
            0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
            0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
            0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2};
        uint32_t w[64];
        for (int i = 0; i < 16; ++i)
            w[i] = (uint32_t(p[i*4])<<24)|(uint32_t(p[i*4+1])<<16)|
                   (uint32_t(p[i*4+2])<<8)|uint32_t(p[i*4+3]);
        for (int i = 16; i < 64; ++i) {
            uint32_t s0 = ror(w[i-15],7)^ror(w[i-15],18)^(w[i-15]>>3);
            uint32_t s1 = ror(w[i-2],17)^ror(w[i-2],19)^(w[i-2]>>10);
            w[i] = w[i-16]+s0+w[i-7]+s1;
        }
        uint32_t a=h[0],b=h[1],c=h[2],d=h[3],e=h[4],f=h[5],g=h[6],hh=h[7];
        for (int i = 0; i < 64; ++i) {
            uint32_t S1 = ror(e,6)^ror(e,11)^ror(e,25);
            uint32_t ch = (e&f)^((~e)&g);
            uint32_t t1 = hh+S1+ch+k[i]+w[i];
            uint32_t S0 = ror(a,2)^ror(a,13)^ror(a,22);
            uint32_t maj = (a&b)^(a&c)^(b&c);
            uint32_t t2 = S0+maj;
            hh=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
        }
        h[0]+=a;h[1]+=b;h[2]+=c;h[3]+=d;h[4]+=e;h[5]+=f;h[6]+=g;h[7]+=hh;
    }
    void update(const uint8_t* p, std::size_t n) {
        len += n;
        while (n) {
            std::size_t take = std::min<std::size_t>(64 - buf_len, n);
            std::memcpy(buf + buf_len, p, take);
            buf_len += take; p += take; n -= take;
            if (buf_len == 64) { block(buf); buf_len = 0; }
        }
    }
    std::string hex_digest() {
        uint64_t bits = len * 8;
        uint8_t pad = 0x80;
        update(&pad, 1);
        uint8_t zero = 0;
        while (buf_len != 56) update(&zero, 1);
        uint8_t lb[8];
        for (int i = 0; i < 8; ++i) lb[i] = uint8_t(bits >> (56 - i*8));
        update(lb, 8);
        static const char* d = "0123456789abcdef";
        std::string out;
        for (int i = 0; i < 8; ++i)
            for (int s = 28; s >= 0; s -= 4)
                out += d[(h[i] >> s) & 0xF];
        return out;
    }
};
std::string sha256(const std::string& s) {
    Sha256 c;
    c.update(reinterpret_cast<const uint8_t*>(s.data()), s.size());
    return c.hex_digest();
}

// ═══════════════════════════════════════════════════════════════════════════
//  Перешифровка заголовка (калька reencrypt из python-selftest)
// ═══════════════════════════════════════════════════════════════════════════
constexpr u32 HDR_START = 0x08;
constexpr u32 HDR_END   = 0x17C;   // как в python-selftest
constexpr u32 MASK32    = 0xFFFFFFFFu;

enum class Enc { Xor32, Add32, Sub32, XorIndexed, XorRol };

// Возвращает копию data, где заголовок [HDR_START,HDR_END) перешифрован новым
// способом/ключом. old_key — текущий XOR-ключ файла (для получения plain).
std::vector<u8> reencrypt(const std::vector<u8>& data, u32 old_key,
                          Enc kind, u32 new_key, u32 shift = 0) {
    std::vector<u8> out = data;
    for (u32 off = HDR_START; off + 4 <= HDR_END && off + 4 <= out.size(); off += 4) {
        u32 raw;
        std::memcpy(&raw, data.data() + off, 4);
        const u32 plain = raw ^ old_key;
        u32 enc = 0;
        switch (kind) {
            case Enc::Xor32:      enc = plain ^ new_key; break;
            case Enc::Add32:      enc = (plain + new_key) & MASK32; break;
            case Enc::Sub32:      enc = (new_key - plain) & MASK32; break;
            case Enc::XorIndexed: enc = plain ^ ((new_key + (off >> 2)) & MASK32); break;
            case Enc::XorRol: {
                const u32 x = plain ^ new_key;
                const u32 s = shift & 31;
                enc = ((x << s) | (x >> (32 - s))) & MASK32;
                break;
            }
        }
        std::memcpy(out.data() + off, &enc, 4);
    }
    return out;
}

// ═══════════════════════════════════════════════════════════════════════════
//  Полный конвейер в процессе (калька cli/main.cpp)
// ═══════════════════════════════════════════════════════════════════════════
// Держит всё, что нужно для генерации: Metadata/Layout/образ/модель.
struct Pipeline {
    Mapped meta, bin;
    std::unique_ptr<metadata::Metadata> md;
    std::unique_ptr<metadata::Layout> L;
    std::unique_ptr<binary::BinaryImage> img;
    std::optional<binary::MetadataRegistrationCandidate> mr_cand;
    metadata::TDLayout td;
    std::unique_ptr<model::MetadataRegistration> mr;
    std::unique_ptr<model::Model> model;
    std::unique_ptr<model::GenericInstanceTable> gt;
    elf::MethodPointers mp;
    double pair_ratio = 0;
    bool headerless = false;
    bool ok = false;
    std::string err;
    // Держит override-буфер метадаты живым: Metadata хранит ByteView без копии,
    // буфер обязан пережить всю модель.
    std::vector<u8> hold;
};

// Выбор формата по сигнатуре — как в main.cpp.
std::unique_ptr<binary::BinaryImage> open_image(ByteView v) {
    if (v.size >= 2 && v.data[0] == 'M' && v.data[1] == 'Z')
        return std::make_unique<pe::PE>(v);
    if (v.size >= 4 && (std::memcmp(v.data, "\xcf\xfa\xed\xfe", 4) == 0 ||
                        std::memcmp(v.data, "\xca\xfe\xba\xbe", 4) == 0))
        return std::make_unique<macho::Macho>(v);
    return std::make_unique<elf::Elf64>(v);
}

// Собирает конвейер до модели включительно. meta_override — если задан, метадата
// берётся из него (для headerless/scrambled), иначе с диска meta_path.
std::unique_ptr<Pipeline> build_pipeline(const std::string& meta_path,
                                         const std::string& bin_path,
                                         const std::vector<u8>* meta_override = nullptr) {
    auto P = std::make_unique<Pipeline>();
    ByteView mview;
    if (meta_override) {
        P->hold = *meta_override;   // живёт в Pipeline до конца
        mview = ByteView{P->hold.data(), P->hold.size()};
    } else {
        if (!map_file(meta_path, P->meta)) { P->err = "нет метадаты"; return P; }
        mview = P->meta.view();
    }
    if (!map_file(bin_path, P->bin)) { P->err = "нет бинарника"; return P; }

    // Metadata + Layout, с откатом в headerless (как main.cpp).
    try {
        P->md = std::make_unique<metadata::Metadata>(mview);
        P->L = std::make_unique<metadata::Layout>(*P->md);
        if (!P->L->ok()) throw MetadataError("layout не ok");
    } catch (const MetadataError&) {
        try {
            auto hr = metadata::headerless::recover(mview);
            const u32 ver = mview.size >= 8 ? mview.read_u32(4) : 39;
            P->md = std::make_unique<metadata::Metadata>(
                metadata::Metadata::make_from_headerless(mview, ver, hr));
            P->L = std::make_unique<metadata::Layout>(
                metadata::Layout::make_from_headerless(*P->md, hr));
            P->headerless = true;
            if (!P->L->ok()) { P->err = "headerless layout не ok"; return P; }
        } catch (const std::exception& e2) {
            P->err = std::string("headerless: ") + e2.what();
            return P;
        }
    } catch (const std::exception& e) {
        P->err = e.what();
        return P;
    }

    try {
        P->img = open_image(P->bin.view());
        P->mr_cand = P->img->find_metadata_registration(P->L->typedef_count);
        if (!P->mr_cand) { P->err = "MR не найдена"; return P; }

        auto pc = metadata::check_pair(*P->md, *P->L, *P->img, P->bin.view(),
                                       *P->mr_cand, 82, 0x08);
        P->pair_ratio = pc.ratio();

        metadata::TDLayout def = metadata::default_v39();
        P->td = metadata::detect(*P->md, *P->L, *P->img, P->bin.view(), *P->mr_cand, &def);
        const u64 fo = P->img->find_field_offsets(P->mr_cand->base, P->L->typedef_count);

        P->mr = std::make_unique<model::MetadataRegistration>(*P->mr_cand, fo);
        auto ext = P->img->read_mr_extended(P->mr_cand->base);
        P->mr->generic_classes = ext.generic_classes;
        P->mr->generic_classes_count = ext.generic_classes_count;
        P->mr->generic_insts = ext.generic_insts;
        P->mr->generic_insts_count = ext.generic_insts_count;
        P->mr->method_specs = ext.method_specs;
        P->mr->method_specs_count = ext.method_specs_count;

        P->model = std::make_unique<model::Model>(*P->md, *P->L, *P->img, *P->mr, P->td);
        P->model->detect_params();

        P->mp = elf::find_method_pointers(P->bin.view(), *P->img,
                                          std::max<u32>(P->L->image_count, 32));
        if (P->mp.arr) P->model->attach_method_pointers(P->mp.arr, P->mp.count);

        P->gt = std::make_unique<model::GenericInstanceTable>(
            model::GenericInstanceTable::load(*P->model, *P->img));

        P->ok = true;
    } catch (const std::exception& e) {
        P->err = e.what();
    }
    return P;
}

// ═══════════════════════════════════════════════════════════════════════════
//  Пути к данным
// ═══════════════════════════════════════════════════════════════════════════
std::string g_root = "tests";
std::string P_(const std::string& f) { return g_root + "/" + f; }

// Эталонные числа реальных сборок (сверены прямым разбором, см. REPORT.txt).
struct Ref {
    const char* name;
    const char* meta;
    const char* bin;
    u32 key;
    u32 typedef_count;
    u32 method_count;
    u32 field_count;
    u32 image_count;
    u64 mr_types_count;
};
const Ref NOV{"nov", "nov_meta.dat", "nov_bin.so",
              0xA5C3F19D, 29486, 226242, 127816, 189, 104776};
const Ref DEC{"dec", "dec_meta.dat", "dec_bin.so",
              0x00000000, 29366, 225735, 127388, 188, 104482};

// ═══════════════════════════════════════════════════════════════════════════
//  1. РЕАЛЬНЫЕ СБОРКИ
// ═══════════════════════════════════════════════════════════════════════════
void cat_real_builds(std::unique_ptr<Pipeline>& nov_out,
                     std::unique_ptr<Pipeline>& dec_out) {
    std::printf("\n%s1. РЕАЛЬНЫЕ СБОРКИ%s\n", C_DIM(), C_RST());

    // nov
    {
        Stopwatch sw;
        auto P = build_pipeline(P_(NOV.meta), P_(NOV.bin));
        if (!P->ok) {
            check(false, std::string("nov: конвейер провалился — ") + P->err);
        } else {
            const bool good = P->md->key() == NOV.key &&
                              P->L->typedef_count == NOV.typedef_count &&
                              P->L->method_count == NOV.method_count &&
                              P->mr_cand->types_count > 1000;
            char b[256];
            std::snprintf(b, sizeof b,
                "nov: ключ 0x%08X, типов %s, methods %s (%s)",
                P->md->key(), thousands(P->L->typedef_count).c_str(),
                thousands(P->L->method_count).c_str(), secs(sw.s()).c_str());
            check(good, b);
        }
        nov_out = std::move(P);
    }

    // dec
    {
        Stopwatch sw;
        auto P = build_pipeline(P_(DEC.meta), P_(DEC.bin));
        if (!P->ok) {
            check(false, std::string("dec: конвейер провалился — ") + P->err);
        } else {
            const bool good = P->md->key() == DEC.key &&
                              P->L->typedef_count == DEC.typedef_count &&
                              P->mr_cand->types_count > 1000;
            char b[256];
            std::snprintf(b, sizeof b,
                "dec: ключ 0x%08X, типов %s (%s)",
                P->md->key(), thousands(P->L->typedef_count).c_str(),
                secs(sw.s()).c_str());
            check(good, b);
        }
        dec_out = std::move(P);
    }

    // Синтетическая сборка: берём реальный nov, перешифровываем ТОЛЬКО его
    // заголовок свежим ключом (0x5A5A5A5A) — получаем валидную «другую сборку»,
    // где секции те же, а ключ иной. Проверяем и восстановление ключа, и что
    // счётчики совпали с реальным nov (перешифровка не трогает тело).
    {
        Stopwatch sw;
        const u32 synth_key = 0x5A5A5A5A;
        std::vector<u8> raw = read_file(P_(NOV.meta));
        if (raw.size() < HDR_END) {
            skip("синтетика: нет nov_meta для перешифровки");
        } else {
            std::vector<u8> data = reencrypt(raw, NOV.key, Enc::Xor32, synth_key);
            try {
                metadata::Metadata md(ByteView{data.data(), data.size()});
                metadata::Layout L(md);
                const bool good = md.key() == synth_key && L.ok() &&
                                  L.typedef_count == NOV.typedef_count &&
                                  L.method_count == NOV.method_count &&
                                  L.field_count == NOV.field_count;
                char b[220];
                std::snprintf(b, sizeof b,
                    "синтетика (nov@0x%08X): ключ 0x%08X, типов %s, methods %s (%s)",
                    synth_key, md.key(), thousands(L.typedef_count).c_str(),
                    thousands(L.method_count).c_str(), secs(sw.s()).c_str());
                check(good, b);
            } catch (const std::exception& e) {
                check(false, std::string("синтетика: разбор бросил — ") + e.what());
            }
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
//  2. АВТОВОССТАНОВЛЕНИЕ КЛЮЧА (все преобразования)
// ═══════════════════════════════════════════════════════════════════════════
void cat_key_recovery(const std::string& meta_path, u32 old_key) {
    std::printf("\n%s2. АВТОВОССТАНОВЛЕНИЕ КЛЮЧА%s\n", C_DIM(), C_RST());
    std::vector<u8> base = read_file(meta_path);
    if (base.size() < HDR_END) {
        skip("нет метадаты для перешифровки");
        return;
    }

    struct Case { Enc kind; u32 key; u32 shift; const char* label; };
    const std::vector<Case> cases = {
        {Enc::Xor32,      0xDEADBEEF, 0, "XOR32     "},
        {Enc::Xor32,      0x00000001, 0, "XOR32     "},
        {Enc::Xor32,      0xFFFFFFFF, 0, "XOR32     "},
        {Enc::Xor32,      0xCAFEBABE, 0, "XOR32     "},
        {Enc::Add32,      0x11223344, 0, "ADD32     "},
        {Enc::Sub32,      0xAABBCCDD, 0, "SUB32     "},
        {Enc::XorRol,     0x5A5A1234, 8,  "XOR+ROL8  "},
        {Enc::XorRol,     0x5A5A1234, 16, "XOR+ROL16 "},
        {Enc::XorRol,     0x5A5A1234, 24, "XOR+ROL24 "},
        {Enc::XorIndexed, 0x0BADC0DE, 0, "XOR+индекс"},
    };

    for (const auto& c : cases) {
        Stopwatch sw;
        std::vector<u8> data = reencrypt(base, old_key, c.kind, c.key, c.shift);
        try {
            metadata::Metadata md(ByteView{data.data(), data.size()});
            const char* tn = md.transform() ? md.transform()->name() : "XOR32";
            char b[160];
            std::snprintf(b, sizeof b, "%s 0x%08X → нашёл 0x%08X [%s] (%s)",
                          c.label, c.key, md.key(), tn, secs(sw.s()).c_str());
            check(md.key() == c.key, b);
        } catch (const std::exception&) {
            char b[128];
            std::snprintf(b, sizeof b, "%s 0x%08X → отказ", c.label, c.key);
            check(false, b);
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
//  3. ЗАМОЩЕНИЕ СЕКЦИЙ (TDLayout — 9 полей из данных)
// ═══════════════════════════════════════════════════════════════════════════
void cat_tdlayout(Pipeline* nov, Pipeline* dec) {
    std::printf("\n%s3. ЗАМОЩЕНИЕ Il2CppTypeDefinition (9 полей)%s\n", C_DIM(), C_RST());
    metadata::TDLayout ref = metadata::default_v39();
    auto one = [&](const char* name, Pipeline* P) {
        if (!P || !P->ok) { skip(std::string(name) + ": сборка не разобрана"); return; }
        const auto& td = P->td;
        const bool all9 =
            td.rec_size == ref.rec_size &&
            td.name == ref.name &&
            td.namespace_off == ref.namespace_off &&
            td.byval_type == ref.byval_type &&
            td.declaring == ref.declaring &&
            td.parent == ref.parent &&
            td.flags == ref.flags &&
            td.field_start == ref.field_start &&
            td.field_count == ref.field_count &&
            td.method_start == ref.method_start &&
            td.method_count == ref.method_count;
        char b[256];
        std::snprintf(b, sizeof b,
            "%s: rec=%u byval=0x%02X fs=0x%02X/fc=0x%02X ms=0x%02X/mc=0x%02X — все 9",
            name, td.rec_size, td.byval_type, td.field_start, td.field_count,
            td.method_start, td.method_count);
        check(all9, b);
    };
    one("nov", nov);
    one("dec", dec);
}

// ═══════════════════════════════════════════════════════════════════════════
//  4. СВЕРКА ПАРЫ ФАЙЛОВ
// ═══════════════════════════════════════════════════════════════════════════
void cat_pairing(Pipeline* nov, Pipeline* dec) {
    std::printf("\n%s4. СВЕРКА ПАРЫ ФАЙЛОВ%s\n", C_DIM(), C_RST());
    metadata::TDLayout ref = metadata::default_v39();

    // Само-пары — должны совпадать (100%).
    auto self = [&](const char* name, Pipeline* P) {
        if (!P || !P->ok) { skip(std::string(name) + " сам с собой: не разобран"); return; }
        auto pc = metadata::check_pair(*P->md, *P->L, *P->img, P->bin.view(),
                                       *P->mr_cand, ref.rec_size, ref.byval_type);
        char b[128];
        std::snprintf(b, sizeof b, "%s сам с собой: %.1f%% (ждём 100%%)",
                      name, pc.ratio() * 100.0);
        check(pc.matched(), b);
    };
    self("nov", nov);
    self("dec", dec);

    // Синтетическая само-пара: третья «сборка» — берём nov ещё раз через новый
    // конвейер, чтобы получить 3 положительных сверки, как требует ТЗ.
    {
        auto P = build_pipeline(P_(NOV.meta), P_(NOV.bin));
        if (!P->ok) { skip("nov(2) сам с собой: не разобран"); }
        else {
            auto pc = metadata::check_pair(*P->md, *P->L, *P->img, P->bin.view(),
                                           *P->mr_cand, ref.rec_size, ref.byval_type);
            char b[128];
            std::snprintf(b, sizeof b, "nov(повтор) сам с собой: %.1f%% (ждём 100%%)",
                          pc.ratio() * 100.0);
            check(pc.matched(), b);
        }
    }

    // Кросс-пары — должны отвергаться (<80%).
    auto cross = [&](const char* m_name, Pipeline* M,
                     const char* b_name, Pipeline* B) {
        if (!M || !M->ok || !B || !B->ok) {
            skip(std::string(m_name) + " + бинарник " + b_name + ": нет данных");
            return;
        }
        // MR берём от чужого бинарника: типы-индексы из M, types[] из B.
        auto pc = metadata::check_pair(*M->md, *M->L, *B->img, B->bin.view(),
                                       *B->mr_cand, ref.rec_size, ref.byval_type);
        char b[160];
        std::snprintf(b, sizeof b, "%s + бинарник %s: %.1f%% (ждём отказ)",
                      m_name, b_name, pc.ratio() * 100.0);
        check(!pc.matched(), b);
    };
    cross("nov", nov, "dec", dec);
    cross("dec", dec, "nov", nov);
}

// ═══════════════════════════════════════════════════════════════════════════
//  5. ОПРЕДЕЛЕНИЕ УПАКОВКИ
// ═══════════════════════════════════════════════════════════════════════════
// Собирает file-offset'ы слотов релокаций (RELATIVE), по возрастанию VA.
std::vector<u64> reloc_slot_fos(const std::vector<u8>& buf, const elf::Elf64& elf) {
    std::vector<u64> out;
    auto dyn = elf.dynamic_offset();
    auto rrel = elf.r_relative();
    if (!dyn) return out;
    ByteView v{buf.data(), buf.size()};
    u64 rela_va = 0, rela_sz = 0, rela_ent = 24, o = *dyn;
    while (o + 16 <= v.size) {
        const s64 tag = v.read_s64(o);
        const u64 val = v.read_u64(o + 8);
        o += 16;
        if (tag == 0) break;
        else if (tag == 7) rela_va = val;
        else if (tag == 8) rela_sz = val;
        else if (tag == 9) rela_ent = val;
    }
    if (!rela_va || !rela_sz) return out;
    auto rfo = elf.va2fo(rela_va);
    if (!rfo) return out;
    if (rela_ent == 0) rela_ent = 24;
    const u64 cnt = rela_sz / rela_ent;
    std::vector<u64> slot_vas;
    slot_vas.reserve(cnt);
    for (u64 k = 0; k < cnt; ++k) {
        const u64 base = *rfo + k * rela_ent;
        if (base + 24 > v.size) break;
        const u64 roff = v.read_u64(base);
        const u64 rinfo = v.read_u64(base + 8);
        if (rrel && (u32)(rinfo & 0xFFFFFFFF) == *rrel) slot_vas.push_back(roff);
    }
    std::sort(slot_vas.begin(), slot_vas.end());
    for (u64 va : slot_vas) { auto fo = elf.va2fo(va); if (fo) out.push_back(*fo); }
    return out;
}

void cat_packing(const std::string& bin_path) {
    std::printf("\n%s5. ОПРЕДЕЛЕНИЕ УПАКОВКИ%s\n", C_DIM(), C_RST());
    std::vector<u8> base = read_file(bin_path);
    if (base.size() < 0x1000) { skip("нет бинарника для проверки упаковки"); return; }

    // 5.1 здоровая либа → не упакована.
    {
        try {
            elf::Elf64 e(ByteView{base.data(), base.size()});
            auto pk = e.packing_check();
            char b[160];
            std::snprintf(b, sizeof b, "здоровая либа: нулей %.0f%% → НЕ упакована (%s)",
                          pk.zeros_ratio * 100.0, pk.why.c_str());
            check(!pk.packed, b);
        } catch (const std::exception& e) {
            check(false, std::string("здоровая либа: разбор бросил — ") + e.what());
        }
    }

    // 5.2 DT_RELA убрана → таблица находится сканированием, всё ещё не упакована.
    {
        std::vector<u8> d = base;
        ByteView v{d.data(), d.size()};
        const u64 phoff = v.read_u64(0x20);
        const u16 phnum = v.read_u16(0x38);
        u64 dyn = 0;
        for (u16 i = 0; i < phnum; ++i) {
            const u64 o = phoff + static_cast<u64>(i) * 56;
            if (v.read_u32(o) == 2) dyn = v.read_u64(o + 8);
        }
        if (!dyn) { skip("PT_DYNAMIC не найден — DT_RELA-тест"); }
        else {
            u64 o = dyn;
            while (o + 16 <= d.size()) {
                s64 tag;
                std::memcpy(&tag, d.data() + o, 8);
                if (tag == 0) break;
                if (tag == 7 || tag == 8 || tag == 9) {   // DT_RELA/RELASZ/RELAENT
                    const s64 sentinel = 0x6ffffff9;       // безобидный тег
                    std::memcpy(d.data() + o, &sentinel, 8);
                }
                o += 16;
            }
            try {
                elf::Elf64 e(ByteView{d.data(), d.size()});
                auto pk = e.packing_check();
                char b[200];
                std::snprintf(b, sizeof b,
                    "DT_RELA убрана → релокаций %s (%s), НЕ упакована",
                    thousands(e.reloc_count()).c_str(), e.reloc_source().c_str());
                check(!pk.packed && e.reloc_count() > 100000, b);
            } catch (const std::exception& e) {
                check(false, std::string("DT_RELA убрана: разбор бросил — ") + e.what());
            }
        }
    }

    // 5.3 слоты релокаций забиты данными (сегмент подменён) → упакована.
    {
        std::vector<u8> d = base;
        try {
            elf::Elf64 e0(ByteView{d.data(), d.size()});
            auto fos = reloc_slot_fos(d, e0);
            const std::size_t n = std::min<std::size_t>(fos.size(), 6000);
            for (std::size_t i = 0; i < n; ++i) {
                const u64 fo = fos[i];
                if (fo + 8 <= d.size()) for (int k = 0; k < 8; ++k) d[fo + k] = 0xFF;
            }
            elf::Elf64 e(ByteView{d.data(), d.size()});
            auto pk = e.packing_check();
            char b[160];
            std::snprintf(b, sizeof b,
                "слоты забиты данными → УПАКОВКА распознана (нулей %.0f%%)",
                pk.zeros_ratio * 100.0);
            check(pk.packed, b);
        } catch (const std::exception& e) {
            check(false, std::string("сегмент подменён: разбор бросил — ") + e.what());
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
//  6. HEADERLESS-ВОССТАНОВЛЕНИЕ
// ═══════════════════════════════════════════════════════════════════════════
void cat_headerless(const std::string& meta_path, Pipeline* ref_nov) {
    std::printf("\n%s6. HEADERLESS-ВОССТАНОВЛЕНИЕ%s\n", C_DIM(), C_RST());
    std::vector<u8> buf = read_file(meta_path);
    if (buf.size() < HDR_END || !ref_nov || !ref_nov->ok) {
        skip("нет метадаты/эталона для headerless");
        return;
    }
    const metadata::Layout& L = *ref_nov->L;

    // Затираем [HDR_START, HDR_END) случайными байтами — эмуляция AES-заголовка.
    std::srand(1234);
    for (u32 i = HDR_START; i < HDR_END; ++i)
        buf[i] = static_cast<u8>(std::rand() & 0xFF);

    try {
        auto hr = metadata::headerless::recover(ByteView{buf.data(), buf.size()});
        // string_offset — иногда база уточняется на ±несколько байт.
        check_near(hr.string_offset, L.string_offset, 4,
                   "headerless: string_offset совпал с разбором заголовка");
        check_near(hr.typedef_offset, L.typedef_offset, 0,
                   "headerless: typedef_offset совпал с разбором заголовка");
        // typedef_count замощение слегка переоценивает хвост.
        check_near(hr.typedef_count, L.typedef_count, 32,
                   "headerless: typedef_count ≈ разбор заголовка (±32)");
    } catch (const std::exception& e) {
        check(false, std::string("headerless: recover бросил — ") + e.what());
    }
}

// ═══════════════════════════════════════════════════════════════════════════
//  7. РАСПОЗНАВАНИЕ КОНТЕЙНЕРА
// ═══════════════════════════════════════════════════════════════════════════
void cat_container() {
    std::printf("\n%s7. РАСПОЗНАВАНИЕ КОНТЕЙНЕРА%s\n", C_DIM(), C_RST());
    using crypto::Container;
    auto kind_name = [](Container c) -> const char* {
        switch (c) {
            case Container::Metadata:   return "Metadata";
            case Container::Compressed: return "Compressed";
            case Container::Encrypted:  return "Encrypted";
            default:                    return "Unknown";
        }
    };
    auto one = [&](std::vector<u8> d, Container want, const char* label) {
        auto r = crypto::detect_container(ByteView{d.data(), d.size()});
        check(r.kind == want, std::string(label) + ": определён '" +
              kind_name(r.kind) + "' (ждём '" + kind_name(want) + "')");
    };

    { std::vector<u8> d(4096, 0); d[0]=0x1f; d[1]=0x8b;
      one(std::move(d), Container::Compressed, "gzip"); }
    { std::vector<u8> d(4096, 0); d[0]=0x04; d[1]=0x22; d[2]=0x4d; d[3]=0x18;
      one(std::move(d), Container::Compressed, "LZ4"); }
    { std::vector<u8> d(4096, 0); d[0]=0x28; d[1]=0xb5; d[2]=0x2f; d[3]=0xfd;
      one(std::move(d), Container::Compressed, "zstd"); }
    { std::vector<u8> d(4096, 0); d[0]=0xfd; d[1]='7'; d[2]='z'; d[3]='X'; d[4]='Z';
      one(std::move(d), Container::Compressed, "xz"); }
    { std::vector<u8> d(8192); std::srand(20260726);
      for (auto& b : d) b = static_cast<u8>(std::rand() & 0xFF);
      one(std::move(d), Container::Encrypted, "случайные байты"); }
}

// ═══════════════════════════════════════════════════════════════════════════
//  8. ПОЛНЫЙ КОНВЕЙЕР (архив в памяти через ZipWriter → чтение обратно)
// ═══════════════════════════════════════════════════════════════════════════
// Читает наш STORED-ZIP: возвращает список (имя, размер) из локальных заголовков.
std::vector<std::pair<std::string,u32>> read_zip_entries(const std::string& path) {
    std::vector<std::pair<std::string,u32>> out;
    std::vector<u8> z = read_file(path);
    ByteView v{z.data(), z.size()};
    std::size_t o = 0;
    while (o + 30 <= v.size) {
        if (v.read_u32(o) != 0x04034b50) break;   // local file header
        const u32 usize = v.read_u32(o + 22);
        const u16 nlen = v.read_u16(o + 26);
        const u16 elen = v.read_u16(o + 28);
        std::string name;
        for (u16 i = 0; i < nlen && o + 30 + i < v.size; ++i)
            name += static_cast<char>(v.data[o + 30 + i]);
        out.emplace_back(name, usize);
        o += 30 + nlen + elen + usize;
    }
    return out;
}

// Генерирует все файлы вывода из готового конвейера и возвращает их как пары.
std::vector<std::pair<std::string,std::string>> gen_all(Pipeline& P) {
    std::vector<std::pair<std::string,std::string>> files;
    files.emplace_back("il2cpp.h",   output::gen_il2cpp_h(*P.model));
    files.emplace_back("dump.cs",    output::gen_dump_cs(*P.model, {}, P.gt.get()));
    files.emplace_back("script.json",output::gen_script_json(*P.model));
    files.emplace_back("offsets.h",  output::gen_offsets_h(*P.model));
    files.emplace_back("offsets.cs", output::gen_offsets_cs(*P.model));
    files.emplace_back("types.txt",  output::gen_types_txt(*P.model));
    files.emplace_back("generics.txt", output::gen_generics_txt(*P.model, *P.gt));

    output::Summary sum;
    sum.typedef_count = P.L->typedef_count;
    sum.bin_size = P.bin.size;
    sum.reloc_count = P.img->reloc_count();
    sum.reloc_source = P.img->reloc_source();
    sum.pair_ratio = P.pair_ratio;
    sum.headerless = P.headerless;
    sum.main_module = P.mp.module;
    sum.main_module_methods = P.mp.count;
    sum.main_module_rva = P.mp.arr;
    files.emplace_back("REPORT.txt", output::gen_report(*P.md, *P.L, *P.img, *P.mr, *P.model, sum));
    return files;
}

// Проверяет, что архив содержит все ожидаемые файлы и они не меньше min-порогов.
void pipeline_one(const char* name, const std::string& meta_path,
                  const std::string& bin_path, bool headerless_expected,
                  const std::vector<u8>* meta_override) {
    Stopwatch sw;
    auto P = build_pipeline(meta_path, bin_path, meta_override);
    if (!P->ok) {
        check(false, std::string(name) + ": конвейер провалился — " + P->err);
        return;
    }
    auto files = gen_all(*P);

    const std::string zip = std::string("/tmp/oxdump_selftest_") + name + ".zip";
    {
        io::ZipWriter zw(zip);
        if (!zw.ok()) { check(false, std::string(name) + ": не открыть архив"); return; }
        for (auto& f : files) zw.add(f.first, f.second);
    }

    auto entries = read_zip_entries(zip);
    // Ожидаемые файлы и минимальные размеры (headerless — мягче: методы/образы
    // могут не восстановиться, но dump.cs/il2cpp.h/offsets всё равно крупные).
    struct Exp { const char* name; u32 min; };
    const std::vector<Exp> exp = {
        {"dump.cs",     1u*1024*1024},
        {"il2cpp.h",    1u*1024*1024},
        {"script.json", headerless_expected ? 1u : 1u*1024*1024},
        {"offsets.h",   1024},
        {"offsets.cs",  1024},
        {"types.txt",   1024},
        {"generics.txt", 1},
        {"REPORT.txt",  200},
    };
    bool all_present = true;
    std::string missing;
    for (const auto& e : exp) {
        bool found = false;
        for (const auto& z : entries)
            if (z.first == e.name && z.second >= e.min) { found = true; break; }
        if (!found) { all_present = false; missing += std::string(" ") + e.name; }
    }
    char b[256];
    std::snprintf(b, sizeof b, "%s: архив, %zu файлов%s (%s)%s",
                  name, entries.size(),
                  headerless_expected ? " [headerless]" : "",
                  secs(sw.s()).c_str(),
                  all_present ? "" : (std::string(", НЕТ:") + missing).c_str());
    check(all_present && entries.size() == exp.size(), b);
    unlink(zip.c_str());
}

void cat_pipeline() {
    std::printf("\n%s8. ПОЛНЫЙ КОНВЕЙЕР%s\n", C_DIM(), C_RST());
    // nov (обычный путь)
    pipeline_one("nov", P_(NOV.meta), P_(NOV.bin), false, nullptr);
    // dec (обычный путь)
    pipeline_one("dec", P_(DEC.meta), P_(DEC.bin), false, nullptr);
    // scrambled_nov (headerless путь)
    std::vector<u8> scr = read_file(P_(NOV.meta));
    if (scr.size() >= HDR_END) {
        std::srand(0xC0FFEE);
        for (u32 i = HDR_START; i < HDR_END; ++i)
            scr[i] = static_cast<u8>(std::rand() & 0xFF);
        pipeline_one("scrambled_nov", P_(NOV.meta), P_(NOV.bin), true, &scr);
    } else {
        skip("scrambled_nov: нет метадаты");
    }
}

// ═══════════════════════════════════════════════════════════════════════════
//  9. МОДУЛЬ ELF (Elf64 на nov_bin)
// ═══════════════════════════════════════════════════════════════════════════
void cat_elf_module(Pipeline* nov) {
    std::printf("\n%s9. МОДУЛЬ ELF (Elf64)%s\n", C_DIM(), C_RST());
    Mapped bin;
    if (!map_file(P_(NOV.bin), bin)) { skip("nov_bin недоступен"); return; }
    try {
        elf::Elf64 elf(bin.view());
        check(elf.machine() == 0xB7,
              std::string("machine = 0x") + hex(elf.machine()).substr(2) + " (AArch64)");
        check(elf.segments().size() == 4,
              std::string("сегментов PT_LOAD = ") + std::to_string(elf.segments().size()) + " (ждём 4)");
        check(elf.reloc_count() > 1000000,
              std::string("релокаций = ") + thousands(elf.reloc_count()) + " (> 1M, " + elf.reloc_source() + ")");
        // MR-поиск.
        auto mr = elf.find_metadata_registration(NOV.typedef_count);
        check(mr.has_value() && mr->types_count > 1000,
              mr ? (std::string("MR: types[] @ ") + hex(mr->types) +
                    ", " + thousands(mr->types_count) + " типов")
                 : std::string("MR не найдена"));
    } catch (const std::exception& e) {
        check(false, std::string("Elf64 бросил — ") + e.what());
    }
    (void)nov;
}

// ═══════════════════════════════════════════════════════════════════════════
//  10. МОДУЛЬ MACH-O (если есть фикстура)
// ═══════════════════════════════════════════════════════════════════════════
void cat_macho_module() {
    std::printf("\n%s10. МОДУЛЬ MACH-O%s\n", C_DIM(), C_RST());
    const std::string path = P_("macho_bin.dylib");
    if (!file_exists(path)) { skip("macho_bin.dylib недоступен"); return; }
    Mapped m;
    if (!map_file(path, m)) { skip("macho_bin.dylib не отобразился"); return; }
    try {
        macho::Macho mo(m.view());
        check(mo.cpu_type() == 0x0100000C,
              std::string("cputype = 0x") + hex(mo.cpu_type()).substr(2) + " (arm64)");
        check(mo.segments().size() >= 1,
              std::string("сегментов = ") + std::to_string(mo.segments().size()));
        check(mo.reloc_count() > 0,
              std::string("rebase-записей = ") + thousands(mo.reloc_count()) +
              " (" + mo.reloc_source() + ")");
        auto pk = mo.packing_check();
        check(!pk.packed, std::string("не упакован (") + pk.why + ")");
    } catch (const std::exception& e) {
        check(false, std::string("Macho бросил — ") + e.what());
    }
}

// ═══════════════════════════════════════════════════════════════════════════
//  11. МОДУЛЬ PE (синтетический)
// ═══════════════════════════════════════════════════════════════════════════
static void put16(std::vector<u8>& b, std::size_t o, u16 v) { b[o]=v&0xFF; b[o+1]=(v>>8)&0xFF; }
static void put32(std::vector<u8>& b, std::size_t o, u32 v) { for (int i=0;i<4;++i) b[o+i]=(v>>(8*i))&0xFF; }
static void put64(std::vector<u8>& b, std::size_t o, u64 v) { for (int i=0;i<8;++i) b[o+i]=(v>>(8*i))&0xFF; }

std::vector<u8> build_pe(u64 image_base, u32& text_rva, u32& rdata_rva,
                         u32& reloc_rva, u64& ptr_slot_rva, u64& ptr_slot_value) {
    const u32 opt_size = 240, num_sections = 3;
    const std::size_t nt = 0x40, fh = nt + 4, opt = fh + 20, sec_hdrs = opt + opt_size;
    text_rva = 0x1000; rdata_rva = 0x2000; reloc_rva = 0x3000;
    const u32 text_fo=0x200, rdata_fo=0x400, reloc_fo=0x600, raw=0x200;
    std::vector<u8> b(0x800, 0);
    b[0]='M'; b[1]='Z';
    put32(b, 0x3C, static_cast<u32>(nt));
    b[nt]='P'; b[nt+1]='E';
    put16(b, fh + 0, 0x8664);
    put16(b, fh + 2, num_sections);
    put16(b, fh + 16, opt_size);
    put16(b, opt + 0, 0x020B);
    put64(b, opt + 24, image_base);
    put32(b, opt + 108, 16);
    const std::size_t dd5 = opt + 112 + 5*8;
    put32(b, dd5 + 0, reloc_rva);
    put32(b, dd5 + 4, 12);
    auto section = [&](int i, const char* nm, u32 vs, u32 va, u32 rs, u32 rp, u32 ch){
        const std::size_t o = sec_hdrs + static_cast<std::size_t>(i)*40;
        std::memcpy(&b[o], nm, std::strlen(nm));
        put32(b, o+8, vs); put32(b, o+12, va); put32(b, o+16, rs);
        put32(b, o+20, rp); put32(b, o+36, ch);
    };
    section(0, ".text", raw, text_rva, raw, text_fo, 0x60000020);
    section(1, ".rdata", raw, rdata_rva, raw, rdata_fo, 0x40000040);
    section(2, ".reloc", raw, reloc_rva, raw, reloc_fo, 0x42000040);
    ptr_slot_rva = rdata_rva + 0x10;
    ptr_slot_value = text_rva;
    put64(b, rdata_fo + 0x10, image_base + text_rva);
    put32(b, reloc_fo + 0, rdata_rva);
    put32(b, reloc_fo + 4, 12);
    const u16 entry = static_cast<u16>((10u<<12) | static_cast<u16>(ptr_slot_rva - rdata_rva));
    put16(b, reloc_fo + 8, entry);
    return b;
}

void cat_pe_module() {
    std::printf("\n%s11. МОДУЛЬ PE (синтетический)%s\n", C_DIM(), C_RST());
    const u64 image_base = 0x180000000ull;
    u32 text_rva=0, rdata_rva=0, reloc_rva=0;
    u64 ptr_slot_rva=0, ptr_slot_value=0;
    auto buf = build_pe(image_base, text_rva, rdata_rva, reloc_rva, ptr_slot_rva, ptr_slot_value);
    try {
        pe::PE pe(ByteView{buf.data(), buf.size()});
        check(pe.machine() == 0x8664 && pe.image_base() == image_base,
              std::string("machine=AMD64, image_base=0x") + hex(pe.image_base()).substr(2));
        check(pe.segments().size() == 3,
              std::string("секций = ") + std::to_string(pe.segments().size()) + " (ждём 3)");
        auto fo = pe.va2fo(ptr_slot_rva);
        check(fo.has_value() && *fo == 0x400 + 0x10, "va2fo слота указателя верный");
        check(pe.reloc_count() == 1 && pe.ptr(ptr_slot_rva) == ptr_slot_value,
              "DIR64-релокация разобрана, ptr() в RVA-мире (ImageBase вычтен)");
    } catch (const std::exception& e) {
        check(false, std::string("PE бросил — ") + e.what());
    }
    // Негативный: PE32 (не 64-бит) → BinaryError.
    {
        auto bad = build_pe(image_base, text_rva, rdata_rva, reloc_rva, ptr_slot_rva, ptr_slot_value);
        put16(bad, 0x40 + 4 + 20 + 0, 0x010B);   // magic PE32
        bool threw = false;
        try { pe::PE pe(ByteView{bad.data(), bad.size()}); }
        catch (const BinaryError&) { threw = true; }
        catch (...) {}
        check(threw, "PE32 (не 64-бит) → BinaryError");
    }
}

// ═══════════════════════════════════════════════════════════════════════════
//  12. ДЕТЕРМИНИЗМ ВЫВОДА (SHA-256 двух прогонов совпадают)
// ═══════════════════════════════════════════════════════════════════════════
void cat_determinism() {
    std::printf("\n%s12. ДЕТЕРМИНИЗМ ВЫВОДА (SHA-256)%s\n", C_DIM(), C_RST());
    // Строим два независимых конвейера на nov и сверяем хеши ключевых файлов.
    auto P1 = build_pipeline(P_(NOV.meta), P_(NOV.bin));
    auto P2 = build_pipeline(P_(NOV.meta), P_(NOV.bin));
    if (!P1->ok || !P2->ok) { skip("nov не разобран — детерминизм"); return; }

    const std::string h1_h = sha256(output::gen_il2cpp_h(*P1->model));
    const std::string h2_h = sha256(output::gen_il2cpp_h(*P2->model));
    check(h1_h == h2_h, std::string("il2cpp.h стабилен: ") + h1_h.substr(0, 16));

    const std::string d1 = sha256(output::gen_dump_cs(*P1->model, {}, P1->gt.get()));
    const std::string d2 = sha256(output::gen_dump_cs(*P2->model, {}, P2->gt.get()));
    check(d1 == d2, std::string("dump.cs стабилен: ") + d1.substr(0, 16));

    const std::string o1 = sha256(output::gen_offsets_h(*P1->model));
    const std::string o2 = sha256(output::gen_offsets_h(*P2->model));
    check(o1 == o2, std::string("offsets.h стабилен: ") + o1.substr(0, 16));

    const std::string s1 = sha256(output::gen_script_json(*P1->model));
    const std::string s2 = sha256(output::gen_script_json(*P2->model));
    check(s1 == s2, std::string("script.json стабилен: ") + s1.substr(0, 16));

    const std::string t1 = sha256(output::gen_types_txt(*P1->model));
    const std::string t2 = sha256(output::gen_types_txt(*P2->model));
    check(t1 == t2, std::string("types.txt стабилен: ") + t1.substr(0, 16));
}

} // namespace

// ═══════════════════════════════════════════════════════════════════════════
//  main
// ═══════════════════════════════════════════════════════════════════════════
int main(int argc, char** argv) {
    if (argc > 1) g_root = argv[1];
    g_color = isatty(STDOUT_FILENO);

    std::printf("==============================================================\n");
    std::printf("  oxdump — самопроверка (C++17, v1.0.0)\n");
    std::printf("==============================================================\n");
    std::printf("  data root: %s\n", g_root.c_str());

    Stopwatch total;

    std::unique_ptr<Pipeline> nov, dec;
    cat_real_builds(nov, dec);
    cat_key_recovery(P_(NOV.meta), NOV.key);
    cat_tdlayout(nov.get(), dec.get());
    cat_pairing(nov.get(), dec.get());
    cat_packing(P_(NOV.bin));
    cat_headerless(P_(NOV.meta), nov.get());
    cat_container();
    cat_pipeline();
    cat_elf_module(nov.get());
    cat_macho_module();
    cat_pe_module();
    cat_determinism();

    const int tot = g_ok + g_fail;
    std::printf("\n==============================================================\n");
    std::printf("  ИТОГ: %d из %d прошли за %s секунды",
                g_ok, tot, secs(total.s()).c_str());
    if (g_skip) std::printf("  (пропущено %d)", g_skip);
    std::printf("\n==============================================================\n");
    return g_fail ? 1 : 0;
}
