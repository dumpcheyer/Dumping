// oxdump/metadata/header.h — разбор заголовка global-metadata.dat.
//
// Ключ шифрования нигде не хранится, но выводится из самих данных. Идея —
// опираться не на конкретное значение, а на инварианты формата:
//   1) часть секций пуста (size==0), а «0 xor key == key» — ключ светится;
//   2) секции лежат подряд (конец одной == начало следующей) — стыковка;
//   3) по stringOffset лежат ASCII-строки с якорными именами типов.
//
// Стыковка (2) — самый жёсткий критерий: случайный ключ её не даёт.
#pragma once
#include "oxdump/common.h"
#include "oxdump/crypto/transforms.h"
#include "oxdump/metadata/headerless.h"
#include <vector>
#include <string>
#include <memory>

namespace oxdump::metadata {

// Диапазон полей заголовка. Магия и версия (0x00, 0x04) не шифруются.
constexpr u32 HDR_START   = 0x08;
constexpr u32 HDR_END_MAX = 0x400;   // с запасом: у разных версий длина разная

// Сколько стыков секций считать надёжным подтверждением ключа. Порог не
// «ноль стыков»: на файлах, перешифрованных ДРУГИМ способом, неверный
// XOR-ключ случайно набирает 1-2 стыка. «Мало стыков» — повод перебрать
// другие преобразования, а не признать ключ найденным.
constexpr int MIN_CONFIDENT_JOINS = 3;

// Одна секция заголовка: смещение поля в заголовке + её (offset, size).
struct Section {
    u32 field_off;
    u32 offset;
    u32 size;
};

class Metadata {
public:
    // view — сырые байты файла метадаты. Копий не делаем, время жизни на
    // вызывающем. Кидает MetadataError при неверной магии или неудаче с ключом.
    explicit Metadata(ByteView view);

    // Фабрика для headerless-режима: заголовок НЕ расшифрован. Ключа нет
    // (key=0, transform=null), поля берутся как есть — тело файла не
    // шифровалось, карту секций восстановил headerless::recover() по
    // содержимому. Магия/версия из raw не проверяются заново: сюда попадают
    // только после того, как обычный путь уже отказал.
    static Metadata make_from_headerless(ByteView raw, u32 version,
                                         const headerless::HeaderlessResult& hr);

    // ── публичный доступ ─────────────────────────────────────────────────
    u32 magic() const noexcept { return magic_; }
    u32 version() const noexcept { return version_; }
    u32 key() const noexcept { return key_; }
    std::size_t size() const noexcept { return v_.size; }
    // Сырые байты файла — для сканирования блобов (строковой секции и т.п.).
    ByteView bytes() const noexcept { return v_; }
    // null означает XOR32 — быстрый путь, то что используется в игре сейчас.
    const crypto::Transform* transform() const noexcept { return transform_; }
    const std::string& key_report() const noexcept { return key_report_; }

    // Расшифрованное поле заголовка по смещению.
    u32 field(u32 off) const noexcept;

    // Сырые читатели файла (без расшифровки).
    u32 u32_at(u32 off) const noexcept { return v_.read_u32(off); }
    u16 u16_at(u32 off) const noexcept { return v_.read_u16(off); }
    s32 s32_at(u32 off) const noexcept { return v_.read_s32(off); }

    // Нуль-терминированная строка по смещению от базы.
    std::string cstr(u32 base, u32 idx) const;

    // Все непустые секции в файле, отсортированы по offset.
    std::vector<Section> sections() const;

private:
    // Кандидат в ключ, оценённый по трём инвариантам формата.
    struct KeyCandidate {
        u32 key = 0;
        int joins = 0;    // стыков секций (решающий критерий)
        int anchors = 0;  // найденных якорных строк
        int inrange = 0;  // пар, попадающих в файл
        int zeros = 0;    // пустых секций
        // Преобразование; null означает XOR32.
        const crypto::Transform* transform = nullptr;

        // Стыковка весит больше всего: даёт абсолютный отрыв.
        int score() const noexcept {
            return joins * 100 + anchors * 10 + inrange + zeros;
        }
        std::string describe() const;
    };

    // Тег-конструктор для headerless-пути: заполняет поля напрямую, минуя
    // проверку магии и recover_key(). Тег отличает его от публичного
    // Metadata(ByteView) при том же первом аргументе.
    struct direct_tag {};
    Metadata(direct_tag, ByteView raw, u32 version,
             const headerless::HeaderlessResult& hr);
    // Общая инициализация «без расшифровки»: key=0, transform=null, honest
    // key_report. Вынесена, чтобы фабрика и обычный путь не расходились.
    void init_from_direct_values(u32 version);

    u32 hdr_end() const noexcept;
    std::vector<u32> candidates() const;
    // transform==nullptr — быстрый путь XOR32.
    KeyCandidate evaluate(u32 key, const crypto::Transform* t = nullptr) const;
    std::vector<u32> bruteforce_key() const;
    // Перебор преобразований, отличных от XOR32.
    bool try_other_transforms(KeyCandidate& out) const;
    void recover_key();

    ByteView v_;
    u32 magic_ = 0;
    u32 version_ = 0;
    u32 key_ = 0;
    const crypto::Transform* transform_ = nullptr;
    // Держим владение всеми преобразованиями: transform_ может указывать на
    // один из них дольше, чем живёт recover_key().
    std::vector<std::unique_ptr<crypto::Transform>> transforms_;
    std::string key_report_;
};

} // namespace oxdump::metadata
