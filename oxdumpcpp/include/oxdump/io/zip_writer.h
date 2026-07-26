// oxdump/io/zip_writer.h — писатель ZIP: STORED (method 0) и DEFLATE (method 8).
//
// Без zlib и внешних зависимостей. STORED оставлен для обратной совместимости и
// для бинарных вложений; DEFLATE (add_deflated) сжимает наши мегабайтные
// текстовые файлы (dump.cs, il2cpp.h, script.json) собственным энкодером из
// oxdump/io/deflate.h — итоговый архив уменьшается с ~99.5 МБ до ~25-30 МБ.
//
// Формат: обычный PKZIP (2.0). Один файл — один local header + payload +
// central directory record. В конце — end-of-central-directory record.
#pragma once
#include "oxdump/common.h"
#include "oxdump/io/deflate.h"
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

namespace oxdump::io {

// CRC-32/IEEE. Однопоточный, без таблицы — файлы у нас крупные,
// но не сотни МБ; накладные расходы приемлемы, зато без глобального состояния.
inline u32 crc32_bytes(const u8* p, std::size_t n) noexcept {
    static u32 table[256];
    static bool built = false;
    if (!built) {
        for (u32 i = 0; i < 256; ++i) {
            u32 c = i;
            for (int k = 0; k < 8; ++k) c = (c & 1) ? (0xEDB88320u ^ (c >> 1)) : (c >> 1);
            table[i] = c;
        }
        built = true;
    }
    u32 c = 0xFFFFFFFFu;
    for (std::size_t i = 0; i < n; ++i) c = table[(c ^ p[i]) & 0xFF] ^ (c >> 8);
    return c ^ 0xFFFFFFFFu;
}

class ZipWriter {
public:
    // Открывает файл на запись. Ничего сжимать не будем.
    explicit ZipWriter(const std::string& path) {
        f_ = std::fopen(path.c_str(), "wb");
    }
    ~ZipWriter() { close(); }
    ZipWriter(const ZipWriter&) = delete;
    ZipWriter& operator=(const ZipWriter&) = delete;

    bool ok() const noexcept { return f_ != nullptr; }

    // Добавить файл БЕЗ сжатия (STORED, method 0).
    // name — путь внутри архива (utf-8). data/size — содержимое.
    void add(const std::string& name, const void* data, std::size_t size) {
        if (!f_) return;
        const u32 crc = crc32_bytes(static_cast<const u8*>(data), size);
        write_entry(name, /*method=*/0, crc,
                    /*comp=*/static_cast<u32>(size), /*uncomp=*/static_cast<u32>(size),
                    data, size);
    }

    void add(const std::string& name, const std::string& data) {
        add(name, data.data(), data.size());
    }

    // Добавить файл СО СЖАТИЕМ (DEFLATE, method 8). CRC-32 считается по
    // исходным (несжатым) байтам — так требует ZIP. Полезная нагрузка —
    // «сырой» DEFLATE-поток из deflate_compress. Если по какой-то причине
    // сжатие не дало выигрыша, add_deflated всё равно корректен: наш
    // deflate_compress сам откатывается на DEFLATE STORED-блоки (method 8
    // при этом остаётся валидным).
    void add_deflated(const std::string& name, const void* data, std::size_t size) {
        if (!f_) return;
        const u8* p = static_cast<const u8*>(data);
        const u32 crc = crc32_bytes(p, size);
        std::vector<u8> comp = deflate_compress(p, size);
        write_entry(name, /*method=*/8, crc,
                    /*comp=*/static_cast<u32>(comp.size()),
                    /*uncomp=*/static_cast<u32>(size),
                    comp.data(), comp.size());
    }

    void add_deflated(const std::string& name, const std::string& data) {
        add_deflated(name, data.data(), data.size());
    }

    // Закрыть архив, записав central directory + EOCD.
    void close() {
        if (!f_) return;
        const u32 cd_off = static_cast<u32>(std::ftell(f_));
        for (auto& e : entries_) {
            u8 rec[46] = {};
            put32(rec + 0, 0x02014b50);
            put16(rec + 4, 20);              // ver made by
            put16(rec + 6, 20);              // ver needed
            put16(rec + 8, 0);               // flags
            put16(rec + 10, e.method);       // method (0=STORED, 8=DEFLATE)
            put16(rec + 12, 0);              // mod time
            put16(rec + 14, 0);              // mod date
            put32(rec + 16, e.crc);
            put32(rec + 20, e.comp_size);    // compressed
            put32(rec + 24, e.size);         // uncompressed
            put16(rec + 28, static_cast<u16>(e.name.size()));
            put16(rec + 30, 0); put16(rec + 32, 0);
            put16(rec + 34, 0); put16(rec + 36, 0);
            put32(rec + 38, 0);
            put32(rec + 42, e.local_off);
            std::fwrite(rec, 1, sizeof(rec), f_);
            std::fwrite(e.name.data(), 1, e.name.size(), f_);
        }
        const u32 cd_size = static_cast<u32>(std::ftell(f_)) - cd_off;

        u8 eocd[22] = {};
        put32(eocd + 0, 0x06054b50);
        put16(eocd + 8, static_cast<u16>(entries_.size()));
        put16(eocd + 10, static_cast<u16>(entries_.size()));
        put32(eocd + 12, cd_size);
        put32(eocd + 16, cd_off);
        std::fwrite(eocd, 1, sizeof(eocd), f_);

        std::fclose(f_);
        f_ = nullptr;
    }

private:
    struct Entry {
        std::string name;
        u32 crc = 0, size = 0, comp_size = 0, local_off = 0;
        u16 method = 0;   // 0 = STORED, 8 = DEFLATE
    };

    // Общая запись: local file header + имя + полезная нагрузка, затем
    // регистрация записи для central directory. payload/payload_size — то, что
    // реально ложится в архив (сырые данные для STORED, сжатые для DEFLATE).
    void write_entry(const std::string& name, u16 method, u32 crc,
                     u32 comp, u32 uncomp,
                     const void* payload, std::size_t payload_size) {
        const u32 local_off = static_cast<u32>(std::ftell(f_));
        u8 hdr[30] = {};
        put32(hdr + 0, 0x04034b50);        // signature
        put16(hdr + 4, 20);                 // version needed
        put16(hdr + 6, 0);                  // flags
        put16(hdr + 8, method);             // method
        put16(hdr + 10, 0);                 // mod time
        put16(hdr + 12, 0);                 // mod date
        put32(hdr + 14, crc);
        put32(hdr + 18, comp);              // compressed size
        put32(hdr + 22, uncomp);            // uncompressed size
        put16(hdr + 26, static_cast<u16>(name.size()));
        put16(hdr + 28, 0);                 // extra len
        std::fwrite(hdr, 1, sizeof(hdr), f_);
        std::fwrite(name.data(), 1, name.size(), f_);
        if (payload_size) std::fwrite(payload, 1, payload_size, f_);

        Entry e;
        e.name = name;
        e.crc = crc;
        e.size = uncomp;
        e.comp_size = comp;
        e.local_off = local_off;
        e.method = method;
        entries_.push_back(std::move(e));
    }

    static void put16(u8* p, u16 v) { p[0]=v; p[1]=v>>8; }
    static void put32(u8* p, u32 v) { p[0]=v; p[1]=v>>8; p[2]=v>>16; p[3]=v>>24; }

    std::FILE* f_ = nullptr;
    std::vector<Entry> entries_;
};

} // namespace oxdump::io
