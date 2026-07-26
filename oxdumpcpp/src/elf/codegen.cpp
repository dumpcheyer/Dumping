// oxdump/elf/codegen.cpp — поиск таблицы адресов методов внутри образа.
//
// codeGenModules — массив указателей на Il2CppCodeGenModule; у каждого первое
// поле — указатель на строку с именем ("Assembly-CSharp.dll" и т.д.), следующее
// u32 — число методов, за ним — сам массив адресов.
//
// Модуль находится через список значений релокаций (reloc_values): те, что
// ведут внутрь образа, — единственный дешёвый список кандидатов на roots.
// Правильный определяется по имени: если по адресу читается "*.dll", это
// модуль. Логика форматонезависима — работает и для ELF, и для Mach-O через
// общий интерфейс BinaryImage.
#include "oxdump/elf/codegen.h"
#include <cstring>

namespace oxdump::elf {

namespace {

// Читает нуль-терминированную ASCII-строку по виртуальному адресу.
// Имена ".dll" в rodata не участвуют в релокациях, поэтому идём через va2fo,
// а не ptr().
std::string read_name(const binary::BinaryImage& img, ByteView bin, u64 va) {
    const auto fo = img.va2fo(va);
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

} // namespace

MethodPointers find_method_pointers(ByteView bin, const binary::BinaryImage& img,
                                    u32 image_count) {
    MethodPointers out;
    // Список кандидатов на roots — значения релокаций, ведущие внутрь образа.
    // У ELF это addend'ы RELATIVE-релокаций, у Mach-O — значения из карты rebase;
    // обе стороны отдаёт reloc_values() одинаково.
    const std::vector<u64> vals = img.reloc_values();

    u64 best_arr = 0;
    int best_ok = 0;
    u64 main_module_va = 0;
    std::string main_name;

    const u32 lim = image_count < 64 ? image_count : 64;
    for (u64 val : vals) {
        if (!img.is_valid_va(val)) continue;
        int ok = 0;
        u64 asm_csharp = 0;
        for (u32 i = 0; i < lim; ++i) {
            const u64 p = img.ptr(val + static_cast<u64>(i) * 8);
            if (!img.is_valid_va(p)) break;
            const u64 name_ptr = img.ptr(p);
            if (!img.is_valid_va(name_ptr)) break;
            const std::string nm = read_name(img, bin, name_ptr);
            if (!ends_with(nm, ".dll")) break;
            if (nm == "Assembly-CSharp.dll") asm_csharp = p;
            ++ok;
        }
        if (ok >= 8 && ok > best_ok) {
            best_ok = ok;
            best_arr = val;
            main_module_va = asm_csharp;
            main_name = "Assembly-CSharp.dll";
        }
    }
    if (!best_arr || !main_module_va) return out;

    const auto fo = img.va2fo(main_module_va);
    if (!fo) return out;
    const u32 cnt = bin.read_u32(*fo + 8);
    const u64 arr = img.ptr(main_module_va + 16);
    if (cnt > 2'000'000 || !img.is_valid_va(arr)) return out;
    out.arr = arr;
    out.count = cnt;
    out.module = main_name;
    return out;
}

} // namespace oxdump::elf
