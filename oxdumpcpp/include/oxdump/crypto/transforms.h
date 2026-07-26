// oxdump/crypto/transforms.h — семейство обратимых преобразований.
//
// Заголовок метадаты может быть зашифрован по-разному. Порядок здесь —
// в убывании частоты в реальных защитах IL2CPP:
//   - XOR32          (текущая схема в игре)
//   - без шифрования (кто-то расшифровал вручную)
//   - ADD32 / SUB32
//   - XOR со сдвигом (ROL/ROR + XOR)
//   - XOR с индексом (ключ зависит от позиции)
//
// Каждый Transform умеет:
//   - decode(v, key, pos)     — расшифровать 32-битное поле
//   - solve(enc, plain, pos)  — вывести ключ из известной пары (или -1)
//   - self_revealing()        — можно ли достать ключ из "0 XOR key = key"
//
// НЕ поддерживаются: AES, RC4 и вообще поточные с состоянием — их ключ
// из структуры заголовка не выводится, а перебор невозможен. Такой случай
// покрывается headerless-режимом: заголовок игнорируем, карту секций
// строим по содержимому.
#pragma once
#include "oxdump/common.h"
#include <optional>
#include <memory>
#include <vector>

namespace oxdump::crypto {

constexpr u32 MASK32 = 0xFFFFFFFFu;

inline u32 rol32(u32 v, u32 n) noexcept {
    n &= 31;
    if (n == 0) return v;
    return (v << n) | (v >> (32 - n));
}
inline u32 ror32(u32 v, u32 n) noexcept {
    n &= 31;
    if (n == 0) return v;
    return (v >> n) | (v << (32 - n));
}

struct Transform {
    virtual ~Transform() = default;
    virtual const char* name() const noexcept = 0;
    // Можно ли собирать кандидаты в ключи прямо из зашифрованных значений
    // (пустая секция даёт "0 xor key == key")?
    virtual bool self_revealing() const noexcept { return false; }
    // Расшифровать 32-битное значение в позиции pos ключом key.
    virtual u32 decode(u32 v, u32 key, u32 pos = 0) const noexcept = 0;
    // Вывести ключ из известной (enc, plain, pos). Возвращает пустой
    // optional, если ключ невыводим для этого преобразования.
    virtual std::optional<u32> solve(u32 enc, u32 plain, u32 pos = 0) const noexcept = 0;
};

struct NoneTransform final : Transform {
    const char* name() const noexcept override { return "без шифрования"; }
    bool self_revealing() const noexcept override { return true; }
    u32 decode(u32 v, u32, u32) const noexcept override { return v; }
    std::optional<u32> solve(u32 enc, u32 plain, u32) const noexcept override {
        return enc == plain ? std::optional<u32>{0} : std::nullopt;
    }
};

struct Xor32 final : Transform {
    const char* name() const noexcept override { return "XOR32"; }
    bool self_revealing() const noexcept override { return true; }
    u32 decode(u32 v, u32 key, u32) const noexcept override { return v ^ key; }
    std::optional<u32> solve(u32 enc, u32 plain, u32) const noexcept override {
        return enc ^ plain;
    }
};

struct Add32 final : Transform {
    const char* name() const noexcept override { return "ADD32"; }
    bool self_revealing() const noexcept override { return true; }
    // decode: plain = v - key   (мод 2^32)
    u32 decode(u32 v, u32 key, u32) const noexcept override {
        return (v - key) & MASK32;
    }
    // key = v - plain
    std::optional<u32> solve(u32 enc, u32 plain, u32) const noexcept override {
        return (enc - plain) & MASK32;
    }
};

struct Sub32 final : Transform {
    const char* name() const noexcept override { return "SUB32"; }
    bool self_revealing() const noexcept override { return true; }
    // decode: plain = key - v
    u32 decode(u32 v, u32 key, u32) const noexcept override {
        return (key - v) & MASK32;
    }
    // key = plain + enc
    std::optional<u32> solve(u32 enc, u32 plain, u32) const noexcept override {
        return (plain + enc) & MASK32;
    }
};

struct XorRol final : Transform {
    u32 shift;
    std::string _name;
    explicit XorRol(u32 s) : shift(s & 31), _name("XOR+ROL" + std::to_string(s & 31)) {}
    const char* name() const noexcept override { return _name.c_str(); }
    u32 decode(u32 v, u32 key, u32) const noexcept override {
        return ror32(v, shift) ^ key;
    }
    std::optional<u32> solve(u32 enc, u32 plain, u32) const noexcept override {
        return ror32(enc, shift) ^ plain;
    }
};

// XOR где ключ зависит от индекса (pos / 4): каждое слово перекодировано
// собственным ключом. Часто применяется, чтобы одинаковые plain-значения
// давали разный шифротекст.
struct XorIndexed final : Transform {
    const char* name() const noexcept override { return "XOR+индекс"; }
    u32 decode(u32 v, u32 key, u32 pos) const noexcept override {
        return v ^ ((key + (pos >> 2)) & MASK32);
    }
    std::optional<u32> solve(u32 enc, u32 plain, u32 pos) const noexcept override {
        return ((enc ^ plain) - (pos >> 2)) & MASK32;
    }
};

// Все преобразования в порядке проверки. XOR32 первый, потому что это
// текущая схема этой игры. NONE второй как дешёвая проверка "вдруг
// файл уже расшифрован".
inline std::vector<std::unique_ptr<Transform>> make_all() {
    std::vector<std::unique_ptr<Transform>> out;
    out.emplace_back(std::make_unique<Xor32>());
    out.emplace_back(std::make_unique<NoneTransform>());
    out.emplace_back(std::make_unique<Add32>());
    out.emplace_back(std::make_unique<Sub32>());
    out.emplace_back(std::make_unique<XorIndexed>());
    for (u32 s : {8, 16, 24, 1, 2, 4}) {
        out.emplace_back(std::make_unique<XorRol>(s));
    }
    return out;
}

} // namespace oxdump::crypto
