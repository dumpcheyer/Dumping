// tests/test_pe.cpp — юнит-тесты разбора PE64.
//
// Настоящего GameAssembly.dll в песочнице нет, поэтому собираем крошечный, но
// валидный PE64 образ в памяти: DOS-заголовок, NT-заголовки, optional header с
// DataDirectory[5] на .reloc, три секции (.text/.rdata/.reloc) и один блок
// базовых релокаций с записью DIR64. Затем прогоняем через pe::PE и сверяем
// va2fo, ptr, is_valid_va, reloc_count, machine, image_base, mem_end и
// packing_check. Плюс негативные тесты на битых входах.
#include "oxdump/pe/pe.h"
#include <cstdio>
#include <cstring>
#include <vector>

using namespace oxdump;

namespace {

int g_failures = 0;

void check(bool cond, const char* what) {
    std::printf("  [%s] %s\n", cond ? "OK " : "FAIL", what);
    if (!cond) ++g_failures;
}

// ── помощники записи в буфер (little-endian) ─────────────────────────────
void put16(std::vector<u8>& b, std::size_t off, u16 v) {
    b[off] = v & 0xFF; b[off + 1] = (v >> 8) & 0xFF;
}
void put32(std::vector<u8>& b, std::size_t off, u32 v) {
    for (int i = 0; i < 4; ++i) b[off + i] = (v >> (8 * i)) & 0xFF;
}
void put64(std::vector<u8>& b, std::size_t off, u64 v) {
    for (int i = 0; i < 8; ++i) b[off + i] = (v >> (8 * i)) & 0xFF;
}

// Собирает валидный PE64. Возвращает буфер и попутно кладёт «интересные» RVA в
// out-параметры для проверок. RVA и file-offset секций держим совпадающими для
// простоты арифметики; на реальных PE они различаются, парсер к этому готов.
std::vector<u8> build_pe(u64 image_base,
                         u32& text_rva, u32& rdata_rva, u32& reloc_rva,
                         u64& ptr_slot_rva, u64& ptr_slot_value,
                         u32 text_chars, u32 rdata_extra_vsize) {
    // Раскладка файла:
    //   [0x000] DOS header (0x40 байт, e_lfanew=0x40)
    //   [0x040] NT sig(4) + FileHeader(20) + OptHeader64(240) = 264 байта
    //   [0x148] section headers: 3 × 40 = 120 байт  -> конец ~0x1C0
    //   [0x200] .text raw   (file offset = RVA)
    //   [0x400] .rdata raw  (содержит слот указателя для DIR64-релокации)
    //   [0x600] .reloc raw  (один блок релокаций)
    const u32 opt_size = 240;
    const u32 num_sections = 3;

    const std::size_t nt = 0x40;
    const std::size_t fh = nt + 4;
    const std::size_t opt = fh + 20;
    const std::size_t sec_hdrs = opt + opt_size;

    text_rva  = 0x1000;
    rdata_rva = 0x2000;
    reloc_rva = 0x3000;
    const u32 text_fo  = 0x200;
    const u32 rdata_fo = 0x400;
    const u32 reloc_fo = 0x600;
    const u32 text_raw  = 0x200;
    const u32 rdata_raw = 0x200;
    const u32 reloc_raw = 0x200;

    std::vector<u8> b(0x800, 0);

    // ── DOS header ───────────────────────────────────────────────────────
    b[0] = 'M'; b[1] = 'Z';
    put32(b, 0x3C, static_cast<u32>(nt));  // e_lfanew

    // ── NT signature ─────────────────────────────────────────────────────
    b[nt] = 'P'; b[nt + 1] = 'E'; b[nt + 2] = 0; b[nt + 3] = 0;

    // ── IMAGE_FILE_HEADER ────────────────────────────────────────────────
    put16(b, fh + 0, 0x8664);          // Machine = AMD64
    put16(b, fh + 2, num_sections);    // NumberOfSections
    put16(b, fh + 16, opt_size);       // SizeOfOptionalHeader
    // Characteristics (fh+18) оставляем 0 — парсер их не читает.

    // ── IMAGE_OPTIONAL_HEADER64 ──────────────────────────────────────────
    put16(b, opt + 0, 0x020B);         // Magic = PE32+
    put64(b, opt + 24, image_base);    // ImageBase
    put32(b, opt + 108, 16);           // NumberOfRvaAndSizes
    // DataDirectory[5] = BASERELOC -> reloc_rva, покрывает один блок.
    const std::size_t dd5 = opt + 112 + 5 * 8;
    put32(b, dd5 + 0, reloc_rva);
    put32(b, dd5 + 4, 12);             // размер блока релокаций (см. ниже)

    // ── section headers ──────────────────────────────────────────────────
    auto write_section = [&](int i, const char* name, u32 vsize, u32 vaddr,
                             u32 rsize, u32 rptr, u32 chars) {
        const std::size_t o = sec_hdrs + static_cast<std::size_t>(i) * 40;
        std::memcpy(&b[o], name, std::strlen(name));  // Name[8], null-padded
        put32(b, o + 8, vsize);        // VirtualSize
        put32(b, o + 12, vaddr);       // VirtualAddress (RVA)
        put32(b, o + 16, rsize);       // SizeOfRawData
        put32(b, o + 20, rptr);        // PointerToRawData
        put32(b, o + 36, chars);       // Characteristics
    };
    // .text — исполняемая; vsize можно раздуть через rdata_extra_vsize=0 здесь.
    write_section(0, ".text", text_raw, text_rva, text_raw, text_fo, text_chars);
    // .rdata — данные для чтения; при желании раздуваем VirtualSize.
    write_section(1, ".rdata", rdata_raw + rdata_extra_vsize, rdata_rva,
                  rdata_raw, rdata_fo, 0x40000040 /* INIT_DATA|MEM_READ */);
    // .reloc — таблица релокаций.
    write_section(2, ".reloc", reloc_raw, reloc_rva, reloc_raw, reloc_fo,
                  0x42000040 /* INIT_DATA|DISCARDABLE|MEM_READ */);

    // ── содержимое .rdata: слот указателя, на который смотрит DIR64 ───────
    // На диске PE хранит АБСОЛЮТНЫЙ «предпочтительный» адрес (image_base +
    // text_rva). PE::ptr() обязан вернуть его в RVA-мире (text_rva), вычтя
    // ImageBase — это и есть контракт BinaryImage. Поэтому в out-параметр
    // кладём ОЖИДАЕМОЕ RVA-значение, а в файл — абсолютное.
    ptr_slot_rva = rdata_rva + 0x10;
    ptr_slot_value = text_rva;  // ожидаемый результат ptr() (RVA-мир)
    put64(b, rdata_fo + 0x10, image_base + text_rva);  // как лежит в файле

    // ── содержимое .reloc: один блок IMAGE_BASE_RELOCATION ────────────────
    // header{ VirtualAddress = rdata_rva (страница), SizeOfBlock = 12 }
    // entries[1] = (10 << 12) | (ptr_slot_rva - rdata_rva)
    put32(b, reloc_fo + 0, rdata_rva);
    put32(b, reloc_fo + 4, 12);        // 8 (header) + 2 (one entry) -> округлять не нужно
    const u16 entry = static_cast<u16>((10u << 12) |
                      static_cast<u16>(ptr_slot_rva - rdata_rva));
    put16(b, reloc_fo + 8, entry);

    return b;
}

} // namespace

int main() {
    std::printf("=== test_pe: fabricated PE64 ===\n");

    const u64 image_base = 0x180000000ull;
    u32 text_rva = 0, rdata_rva = 0, reloc_rva = 0;
    u64 ptr_slot_rva = 0, ptr_slot_value = 0;

    // ── 1. Здоровый образ ────────────────────────────────────────────────
    {
        auto buf = build_pe(image_base, text_rva, rdata_rva, reloc_rva,
                            ptr_slot_rva, ptr_slot_value,
                            0x60000020 /* .text: CODE|EXECUTE|READ */,
                            0 /* .rdata vsize не раздуваем */);
        ByteView view{buf.data(), buf.size()};
        try {
            pe::PE pe(view);

            check(pe.machine() == 0x8664, "machine == AMD64 (0x8664)");
            check(pe.image_base() == image_base, "image_base совпал");
            check(pe.segments().size() == 3, "разобрано 3 секции");

            // mem_end = максимальный RVA+VirtualSize (тут .reloc @0x3000+0x200).
            check(pe.mem_end() == reloc_rva + 0x200, "mem_end по VirtualSize");

            // va2fo: RVA .rdata-слота -> корректное файловое смещение.
            auto fo = pe.va2fo(ptr_slot_rva);
            check(fo.has_value(), "va2fo для валидного RVA вернул значение");
            check(fo && *fo == 0x400 + 0x10, "va2fo вернул верный file offset");

            // va2fo вне секций -> nullopt.
            check(!pe.va2fo(0x0).has_value(), "va2fo(0) -> nullopt");
            check(!pe.va2fo(0x999999).has_value(), "va2fo вне образа -> nullopt");

            // Ровно одна DIR64-релокация распознана.
            check(pe.reloc_count() == 1, "reloc_count == 1 (одна DIR64-запись)");

            // ptr() по слоту релокации отдаёт значение в RVA-мире (ImageBase
            // вычтен) — то есть валидный va в пространстве сегментов.
            check(pe.ptr(ptr_slot_rva) == ptr_slot_value,
                  "ptr() по слоту релокации == RVA-значение (ImageBase вычтен)");
            check(pe.is_valid_va(pe.ptr(ptr_slot_rva)),
                  "результат ptr() сам является валидным va");

            // ptr() по не-релоцируемому RVA читает сырые байты (тут 0).
            check(pe.ptr(rdata_rva) == 0, "ptr() вне карты релокаций читает файл");

            // reloc_values(): единственное значение — RVA .text, внутри образа.
            auto rv = pe.reloc_values();
            check(rv.size() == 1, "reloc_values() вернул одно значение");
            check(rv.size() == 1 && rv[0] == text_rva,
                  "reloc_values()[0] == RVA .text (кандидат в roots)");

            // is_valid_va.
            check(pe.is_valid_va(text_rva), "is_valid_va(.text RVA) == true");
            check(!pe.is_valid_va(0), "is_valid_va(0) == false");
            check(!pe.is_valid_va(0x999999), "is_valid_va(вне образа) == false");

            // reloc_source описателен.
            check(pe.reloc_source().find("DIR64") != std::string::npos,
                  "reloc_source упоминает DIR64");

            // packing_check: здоровый образ (.text не writable, .rdata не раздут,
            // единственный указатель ведёт внутрь образа) -> packed=false.
            auto pk = pe.packing_check();
            check(!pk.packed, "packing_check: здоровый образ не упакован");
            std::printf("       why: %s\n", pk.why.c_str());
        } catch (const std::exception& e) {
            check(false, (std::string("неожиданное исключение: ") + e.what()).c_str());
        }
    }

    // ── 2. Упаковка: .text одновременно WRITE и EXECUTE ──────────────────
    {
        auto buf = build_pe(image_base, text_rva, rdata_rva, reloc_rva,
                            ptr_slot_rva, ptr_slot_value,
                            0xE0000020 /* CODE|EXECUTE|READ|WRITE */,
                            0);
        ByteView view{buf.data(), buf.size()};
        try {
            pe::PE pe(view);
            auto pk = pe.packing_check();
            check(pk.packed, "packing_check: writable+executable .text -> packed");
            check(pk.why.find("исполняемая") != std::string::npos,
                  "why объясняет W^X-нарушение");
        } catch (const std::exception& e) {
            check(false, (std::string("исключение (W^X тест): ") + e.what()).c_str());
        }
    }

    // ── 3. Упаковка: .rdata раздут в памяти (VirtualSize ≫ SizeOfRawData) ─
    {
        auto buf = build_pe(image_base, text_rva, rdata_rva, reloc_rva,
                            ptr_slot_rva, ptr_slot_value,
                            0x60000020,
                            4u << 20 /* +4 МБ VirtualSize поверх 0x200 raw */);
        ByteView view{buf.data(), buf.size()};
        try {
            pe::PE pe(view);
            auto pk = pe.packing_check();
            check(pk.packed, "packing_check: раздутая секция -> packed");
            check(pk.why.find("раздута") != std::string::npos,
                  "why объясняет раздутую секцию");
        } catch (const std::exception& e) {
            check(false, (std::string("исключение (bloat тест): ") + e.what()).c_str());
        }
    }

    // ── 4. Негативные тесты: битые входы должны бросать BinaryError ───────
    {
        // Пустой буфер.
        try {
            ByteView empty{nullptr, 0};
            pe::PE pe(empty);
            check(false, "пустой буфер должен был бросить");
        } catch (const BinaryError&) {
            check(true, "пустой буфер -> BinaryError");
        } catch (...) {
            check(false, "пустой буфер бросил не BinaryError");
        }

        // Нет сигнатуры MZ.
        {
            std::vector<u8> junk(0x100, 0xCC);
            ByteView view{junk.data(), junk.size()};
            try {
                pe::PE pe(view);
                check(false, "мусор без MZ должен был бросить");
            } catch (const BinaryError&) {
                check(true, "мусор без MZ -> BinaryError");
            } catch (...) {
                check(false, "мусор бросил не BinaryError");
            }
        }

        // MZ есть, но PE-сигнатура битая.
        {
            auto buf = build_pe(image_base, text_rva, rdata_rva, reloc_rva,
                                ptr_slot_rva, ptr_slot_value, 0x60000020, 0);
            buf[0x40] = 'X';  // портим 'P' в "PE\0\0"
            ByteView view{buf.data(), buf.size()};
            try {
                pe::PE pe(view);
                check(false, "битая PE-сигнатура должна была бросить");
            } catch (const BinaryError&) {
                check(true, "битая PE-сигнатура -> BinaryError");
            } catch (...) {
                check(false, "битая PE-сигнатура бросила не BinaryError");
            }
        }

        // Optional header не PE32+ (32-битный магик).
        {
            auto buf = build_pe(image_base, text_rva, rdata_rva, reloc_rva,
                                ptr_slot_rva, ptr_slot_value, 0x60000020, 0);
            const std::size_t opt = 0x40 + 4 + 20;
            put16(buf, opt + 0, 0x010B);  // PE32 (не PE32+)
            ByteView view{buf.data(), buf.size()};
            try {
                pe::PE pe(view);
                check(false, "PE32 (не 64-бит) должен был бросить");
            } catch (const BinaryError&) {
                check(true, "PE32 (не 64-бит) -> BinaryError");
            } catch (...) {
                check(false, "PE32 бросил не BinaryError");
            }
        }
    }

    std::printf("\n=== test_pe: %s (%d failures) ===\n",
                g_failures == 0 ? "PASS" : "FAIL", g_failures);
    return g_failures == 0 ? 0 : 1;
}
