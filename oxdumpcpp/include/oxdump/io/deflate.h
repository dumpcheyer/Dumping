// oxdump/io/deflate.h — from-scratch RFC 1951 DEFLATE encoder (single header).
//
// НЕ miniz и не zlib: это самостоятельная учебно-производственная реализация
// DEFLATE, написанная под нужды дампера. Игра пишет мегабайтные ТЕКСТОВЫЕ
// файлы (dump.cs, il2cpp.h, script.json) — сильно повторяющийся C-подобный
// текст, который жмётся в ~3 раза. Нам не нужен идеальный ratio zlib, нам нужен
// корректный поток DEFLATE без внешних зависимостей.
//
// Стратегия: LZ77 (hash-chain, окно 32 КБ) → фиксированные коды Хаффмана
// (BTYPE=1, таблицы из RFC 1951 §3.2.6). Для несжимаемых кусков откатываемся
// на STORED-блок (BTYPE=0), чтобы никогда не раздувать выход.
//
// Формат выхода: «сырой» DEFLATE (RFC 1951) — БЕЗ zlib-заголовка и БЕЗ
// gzip-обёртки. Именно это ждёт ZIP method 8.
//
// Проверка корректности — в tests/test_deflate.cpp через системный zlib
// (raw inflate, windowBits = -15). Основной бинарь zlib не линкует.
#pragma once
#include "oxdump/common.h"
#include <cstddef>
#include <cstring>
#include <vector>

namespace oxdump::io {

// ── контрольные суммы ──────────────────────────────────────────────────────

// CRC-32/IEEE (полином 0xEDB88320, отражённый). ZIP использует именно её.
inline u32 deflate_crc32(const u8* p, std::size_t n) noexcept {
    static u32 table[256];
    static bool built = false;
    if (!built) {
        for (u32 i = 0; i < 256; ++i) {
            u32 c = i;
            for (int k = 0; k < 8; ++k)
                c = (c & 1) ? (0xEDB88320u ^ (c >> 1)) : (c >> 1);
            table[i] = c;
        }
        built = true;
    }
    u32 c = 0xFFFFFFFFu;
    for (std::size_t i = 0; i < n; ++i) c = table[(c ^ p[i]) & 0xFF] ^ (c >> 8);
    return c ^ 0xFFFFFFFFu;
}

// Adler-32 (для zlib-обёртки; ZIP её не использует, но хелпер полезен и
// требуется публичным контрактом заголовка).
inline u32 deflate_adler32(const u8* p, std::size_t n) noexcept {
    const u32 MOD = 65521u;
    u32 a = 1, b = 0;
    // Обрабатываем блоками, чтобы не переполнить до взятия модуля.
    while (n) {
        std::size_t chunk = n < 5552 ? n : 5552;
        n -= chunk;
        while (chunk--) { a += *p++; b += a; }
        a %= MOD;
        b %= MOD;
    }
    return (b << 16) | a;
}

// ── таблицы длин/расстояний (RFC 1951 §3.2.5) ──────────────────────────────
namespace deflate_detail {

// Длины совпадений 3..258 → код 257..285 + доп. биты.
// base[i] — минимальная длина для кода (257+i); extra[i] — число доп. битов.
static const u16 kLenBase[29] = {
    3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31,
    35, 43, 51, 59, 67, 83, 99, 115, 131, 163, 195, 227, 258};
static const u8 kLenExtra[29] = {
    0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2,
    3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0};

// Расстояния 1..32768 → код 0..29 + доп. биты.
static const u16 kDistBase[30] = {
    1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193,
    257, 385, 513, 769, 1025, 1537, 2049, 3073, 4097, 6145,
    8193, 12289, 16385, 24577};
static const u8 kDistExtra[30] = {
    0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6,
    7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13};

// По длине совпадения (3..258) вернуть индекс кода длины 0..28.
inline int len_code_index(u32 len) noexcept {
    // Линейный поиск снизу — таблица короткая, вызывается на матчах.
    int i = 28;
    while (i > 0 && len < kLenBase[i]) --i;
    return i;
}
// По расстоянию (1..32768) вернуть индекс кода расстояния 0..29.
inline int dist_code_index(u32 dist) noexcept {
    int i = 29;
    while (i > 0 && dist < kDistBase[i]) --i;
    return i;
}

// ── битовый писатель: LSB-first по байтам (соглашение DEFLATE) ─────────────
struct BitWriter {
    std::vector<u8>& out;
    u32 bitbuf = 0;   // накопитель битов
    int bitcnt = 0;   // сколько битов в накопителе
    explicit BitWriter(std::vector<u8>& o) : out(o) {}

    // Записать value младшими `n` битами, LSB-first (для доп. битов длины/
    // расстояния и для полей заголовка блока).
    void bits(u32 value, int n) {
        bitbuf |= (value & ((1u << n) - 1u)) << bitcnt;
        bitcnt += n;
        while (bitcnt >= 8) {
            out.push_back(static_cast<u8>(bitbuf & 0xFF));
            bitbuf >>= 8;
            bitcnt -= 8;
        }
    }

    // Записать код Хаффмана: сам КОД хранится MSB-first (канонический
    // порядок Хаффмана), а в поток биты идут LSB-first — поэтому переворачиваем.
    void huff(u32 code, int n) {
        u32 rev = 0;
        for (int i = 0; i < n; ++i) rev |= ((code >> i) & 1u) << (n - 1 - i);
        bits(rev, n);
    }

    // Догнать до границы байта нулями (перед STORED-блоком).
    void align() {
        if (bitcnt > 0) {
            out.push_back(static_cast<u8>(bitbuf & 0xFF));
            bitbuf = 0;
            bitcnt = 0;
        }
    }
};

// Фиксированные коды Хаффмана для литералов/длин (символы 0..287),
// RFC 1951 §3.2.6. Возвращает код и длину для символа.
inline void fixed_lit_code(u32 sym, u32& code, int& len) noexcept {
    if (sym <= 143)      { code = 0x30 + sym;          len = 8; } // 00110000..10111111
    else if (sym <= 255) { code = 0x190 + (sym - 144); len = 9; } // 110010000..111111111
    else if (sym <= 279) { code = 0x00 + (sym - 256);  len = 7; } // 0000000..0010111
    else                 { code = 0xC0 + (sym - 280);  len = 8; } // 11000000..11000111
}

// Один STORED-блок (BTYPE=0). Длина одного куска ≤ 65535.
inline void emit_stored_block(BitWriter& bw, const u8* p, u32 len, bool final) {
    bw.bits(final ? 1u : 0u, 1); // BFINAL
    bw.bits(0u, 2);              // BTYPE = 00 (stored)
    bw.align();                  // выравнивание на байт
    bw.out.push_back(static_cast<u8>(len & 0xFF));
    bw.out.push_back(static_cast<u8>((len >> 8) & 0xFF));
    u16 nlen = static_cast<u16>(~len);
    bw.out.push_back(static_cast<u8>(nlen & 0xFF));
    bw.out.push_back(static_cast<u8>((nlen >> 8) & 0xFF));
    bw.out.insert(bw.out.end(), p, p + len);
}

// Весь вход как последовательность STORED-блоков (запасной путь).
inline std::vector<u8> store_only(const u8* in, std::size_t n) {
    std::vector<u8> out;
    out.reserve(n + n / 65535 + 8);
    BitWriter bw(out);
    if (n == 0) { emit_stored_block(bw, in, 0, true); return out; }
    std::size_t off = 0;
    while (off < n) {
        std::size_t chunk = n - off;
        if (chunk > 65535) chunk = 65535;
        bool final = (off + chunk >= n);
        emit_stored_block(bw, in + off, static_cast<u32>(chunk), final);
        off += chunk;
    }
    return out;
}

} // namespace deflate_detail

// ── основной энкодер ───────────────────────────────────────────────────────

// Сжать `n` байт из `in` алгоритмом DEFLATE (сырой поток RFC 1951).
// Один финальный блок BTYPE=1 (фиксированный Хаффман) поверх LZ77.
// Если результат вышел больше входа (несжимаемые данные) — откат на STORED.
inline std::vector<u8> deflate_compress(const u8* in, std::size_t n) {
    using namespace deflate_detail;

    if (n == 0) return store_only(in, 0);

    // Хеш-цепочки: 15-битный хеш 3 байт.
    constexpr int kHashBits = 15;
    constexpr u32 kHashSize = 1u << kHashBits;   // 32768
    constexpr u32 kWindow   = 32768;             // окно расстояний
    constexpr u32 kWinMask  = kWindow - 1;
    constexpr int kMaxChain = 128;               // предел длины цепочки (скорость)
    constexpr u32 kMinMatch = 3;
    constexpr u32 kMaxMatch = 258;

    std::vector<int> head(kHashSize, -1);
    std::vector<int> chain(kWindow, -1);

    auto hash3 = [](const u8* p) -> u32 {
        // Смешиваем 3 байта в 15 бит.
        u32 h = (static_cast<u32>(p[0]) << 16) |
                (static_cast<u32>(p[1]) << 8)  |
                 static_cast<u32>(p[2]);
        h = (h * 2654435761u) >> (32 - kHashBits);
        return h & (kHashSize - 1);
    };

    std::vector<u8> out;
    out.reserve(n / 2 + 64);
    BitWriter bw(out);

    // Заголовок блока: BFINAL=1, BTYPE=01 (фиксированный Хаффман).
    bw.bits(1u, 1);
    bw.bits(1u, 2);

    auto emit_literal = [&](u8 c) {
        u32 code; int len;
        fixed_lit_code(c, code, len);
        bw.huff(code, len);
    };

    auto emit_match = [&](u32 length, u32 dist) {
        // Символ длины 257..285.
        int li = len_code_index(length);
        u32 sym = 257u + static_cast<u32>(li);
        u32 code; int clen;
        fixed_lit_code(sym, code, clen);
        bw.huff(code, clen);
        int lextra = kLenExtra[li];
        if (lextra) bw.bits(length - kLenBase[li], lextra);
        // Символ расстояния 0..29 — фиксированные коды расстояний = 5 бит,
        // MSB-first (значение самого кода равно индексу).
        int di = dist_code_index(dist);
        bw.huff(static_cast<u32>(di), 5);
        int dextra = kDistExtra[di];
        if (dextra) bw.bits(dist - kDistBase[di], dextra);
    };

    const std::size_t last3 = (n >= (kMinMatch - 1)) ? n - (kMinMatch - 1) : 0;
    std::size_t i = 0;
    while (i < n) {
        u32 best_len = 0;
        u32 best_dist = 0;

        // Ищем совпадение только если впереди есть ≥3 байта.
        if (i < last3) {
            u32 h = hash3(in + i);
            int cand = head[h];
            int chain_left = kMaxChain;
            u32 max_here = static_cast<u32>(n - i);
            if (max_here > kMaxMatch) max_here = kMaxMatch;

            while (cand >= 0 && chain_left-- > 0) {
                std::size_t cpos = static_cast<std::size_t>(cand);
                u32 dist = static_cast<u32>(i - cpos);
                if (dist == 0 || dist > kWindow) break;

                // Быстрая отсечка: сравниваем байт на позиции best_len — если
                // не совпал, совпадение точно не длиннее.
                if (best_len > 0 && best_len < max_here &&
                    in[cpos + best_len] != in[i + best_len]) {
                    cand = chain[cpos & kWinMask];
                    continue;
                }

                u32 l = 0;
                while (l < max_here && in[cpos + l] == in[i + l]) ++l;

                if (l > best_len) {
                    best_len = l;
                    best_dist = dist;
                    if (l >= max_here) break; // дальше некуда
                }
                cand = chain[cpos & kWinMask];
            }
        }

        if (best_len >= kMinMatch) {
            emit_match(best_len, best_dist);
            // Вставляем в хеш-цепочки все позиции покрытые совпадением
            // (кроме тех, где не осталось 3 байт впереди).
            std::size_t end = i + best_len;
            for (std::size_t j = i; j < end; ++j) {
                if (j < last3) {
                    u32 hj = hash3(in + j);
                    chain[j & kWinMask] = head[hj];
                    head[hj] = static_cast<int>(j);
                }
            }
            i = end;
        } else {
            emit_literal(in[i]);
            if (i < last3) {
                u32 hj = hash3(in + i);
                chain[i & kWinMask] = head[hj];
                head[hj] = static_cast<int>(i);
            }
            ++i;
        }
    }

    // Символ конца блока (256) в фиксированной таблице = 7 бит, код 0000000.
    {
        u32 code; int len;
        fixed_lit_code(256, code, len);
        bw.huff(code, len);
    }
    bw.align();

    // Гарантия «никогда не раздуваем»: если сжатый поток оказался не меньше
    // STORED-версии — отдаём STORED. (На несжимаемых данных фикс. Хаффман
    // добавляет накладные расходы.)
    if (out.size() >= n + n / 65535 + 5) {
        return store_only(in, n);
    }
    return out;
}

// Перегрузка для vector.
inline std::vector<u8> deflate_compress(const std::vector<u8>& in) {
    return deflate_compress(in.data(), in.size());
}

} // namespace oxdump::io
