// oxdump/common.h — общие типы и утилиты для всего дампера.
//
// Здесь только то, что нужно ВЕЗДЕ. Ничего специфичного для IL2CPP,
// ELF, шифрования и т.п. — тем модулям принадлежит их территория.
#pragma once
#include <cstdint>
#include <cstddef>
#include <string>
#include <string_view>
#include <vector>
#include <stdexcept>

namespace oxdump {

using u8  = std::uint8_t;
using u16 = std::uint16_t;
using u32 = std::uint32_t;
using u64 = std::uint64_t;
using s8  = std::int8_t;
using s16 = std::int16_t;
using s32 = std::int32_t;
using s64 = std::int64_t;

// Специальные исключения — чтобы CLI мог различать типы ошибок и давать
// правильное сообщение.
struct MetadataError : std::runtime_error {
    using std::runtime_error::runtime_error;
};
struct BinaryError : std::runtime_error {
    using std::runtime_error::runtime_error;
};
struct PairMismatch : std::runtime_error {
    using std::runtime_error::runtime_error;
};

// Явное отделение "raw view" от "owned buffer". mmap-нутый файл живёт
// в ByteView, никаких копий.
struct ByteView {
    const u8* data = nullptr;
    std::size_t size = 0;

    bool valid() const noexcept { return data != nullptr && size > 0; }

    // Проверенное чтение маленьких значений. Возвращает 0 при выходе.
    u32 read_u32(std::size_t off) const noexcept {
        if (off + 4 > size) return 0;
        u32 v;
        __builtin_memcpy(&v, data + off, 4);
        return v;
    }
    u16 read_u16(std::size_t off) const noexcept {
        if (off + 2 > size) return 0;
        u16 v;
        __builtin_memcpy(&v, data + off, 2);
        return v;
    }
    u64 read_u64(std::size_t off) const noexcept {
        if (off + 8 > size) return 0;
        u64 v;
        __builtin_memcpy(&v, data + off, 8);
        return v;
    }
    s32 read_s32(std::size_t off) const noexcept {
        return static_cast<s32>(read_u32(off));
    }
    s64 read_s64(std::size_t off) const noexcept {
        return static_cast<s64>(read_u64(off));
    }
    u8 read_u8(std::size_t off) const noexcept {
        if (off >= size) return 0;
        return data[off];
    }

    // Нуль-терминированная строка от base+idx. Пустая, если выходит.
    std::string cstr(std::size_t base, std::size_t idx,
                     std::size_t max_len = 512) const {
        std::size_t o = base + idx;
        if (o >= size) return {};
        std::size_t e = o;
        std::size_t limit = std::min(o + max_len, size);
        while (e < limit && data[e]) ++e;
        return std::string(reinterpret_cast<const char*>(data + o), e - o);
    }

    ByteView slice(std::size_t off, std::size_t len) const noexcept {
        if (off > size) return {};
        return ByteView{data + off, std::min(len, size - off)};
    }
};

// Утилиты
inline bool is_printable_ascii(u8 c) noexcept {
    return c == 0 || (c >= 32 && c < 127);
}

inline std::size_t count_printable(const u8* p, std::size_t n) noexcept {
    std::size_t c = 0;
    for (std::size_t i = 0; i < n; ++i) if (is_printable_ascii(p[i])) ++c;
    return c;
}

// Форматирование hex — тонкая обёртка, чтобы не тянуть <format> из C++20.
inline std::string hex(u64 v, int width = 0) {
    static const char* digits = "0123456789ABCDEF";
    char buf[24];
    int i = 23;
    buf[i--] = 0;
    if (v == 0) {
        buf[i--] = '0';
    } else {
        while (v) {
            buf[i--] = digits[v & 0xF];
            v >>= 4;
        }
    }
    std::string s = "0x";
    s += (buf + i + 1);
    while (static_cast<int>(s.size()) < width + 2) s = "0x0" + s.substr(2);
    return s;
}

// Форматирование десятичного числа с разделителями тысяч (для отчёта).
inline std::string thousands(u64 v) {
    std::string s = std::to_string(v);
    int insert = static_cast<int>(s.size()) - 3;
    while (insert > 0) { s.insert(insert, ","); insert -= 3; }
    return s;
}

} // namespace oxdump
