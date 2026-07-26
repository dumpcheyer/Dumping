// oxdump/crypto/container.h — распознавание того, ЧТО нам дали.
//
// Обычно на вход прилетают три случая:
//   1. metadata    — начинается с 0xFAB11BAF
//   2. compressed  — gzip/LZ4/zstd/xz, метадаты внутри
//   3. encrypted   — файл целиком под шифром (энтропия близка к 8.0)
//   4. unknown     — ничего из перечисленного
#pragma once
#include "oxdump/common.h"
#include <cmath>

namespace oxdump::crypto {

constexpr u32 IL2CPP_MAGIC = 0xFAB11BAFu;

enum class Container { Metadata, Compressed, Encrypted, Unknown };

struct Signature { const char* magic; std::size_t len; const char* name; };
inline constexpr Signature COMPRESSED_SIGS[] = {
    {"\x1f\x8b", 2, "gzip"},
    {"\x04\x22\x4d\x18", 4, "LZ4 frame"},
    {"\x28\xb5\x2f\xfd", 4, "zstd"},
    {"PK\x03\x04", 4, "zip"},
    {"BZh", 3, "bzip2"},
    {"\xfd""7zXZ", 5, "xz"},
};

inline double shannon_entropy(const u8* p, std::size_t n) {
    if (!n) return 0.0;
    std::size_t freq[256] = {};
    for (std::size_t i = 0; i < n; ++i) ++freq[p[i]];
    double h = 0.0;
    const double inv = 1.0 / static_cast<double>(n);
    for (int i = 0; i < 256; ++i) {
        if (!freq[i]) continue;
        const double q = static_cast<double>(freq[i]) * inv;
        h -= q * std::log2(q);
    }
    return h;
}

struct ContainerResult {
    Container kind = Container::Unknown;
    std::string detail;
};

inline ContainerResult detect_container(ByteView v) {
    if (v.size < 16) return {Container::Unknown, "файл слишком мал"};

    // 1) сигнатура IL2CPP
    if (v.data[0] == 0xAF && v.data[1] == 0x1B &&
        v.data[2] == 0xB1 && v.data[3] == 0xFA) {
        return {Container::Metadata, "сигнатура global-metadata.dat"};
    }
    // 2) сжатые контейнеры
    for (auto& s : COMPRESSED_SIGS) {
        if (v.size >= s.len && std::memcmp(v.data, s.magic, s.len) == 0) {
            return {Container::Compressed,
                    std::string("файл сжат (") + s.name +
                    "). Распакуй и подай сюда распакованное содержимое."};
        }
    }
    // 3) высокоэнтропийные — вероятно AES/RC4-как-был
    const std::size_t probe = std::min<std::size_t>(v.size, 4096);
    double e = shannon_entropy(v.data, probe);
    if (e > 7.5) {
        return {Container::Encrypted,
                "файл выглядит зашифрованным целиком (энтропия " +
                std::to_string(e) + " из 8.0). Из файла на диске тут не "
                "выйти — нужен дамп памяти запущенной игры."};
    }
    return {Container::Unknown,
            "сигнатура не распознана, энтропия " + std::to_string(e)};
}

} // namespace oxdump::crypto
