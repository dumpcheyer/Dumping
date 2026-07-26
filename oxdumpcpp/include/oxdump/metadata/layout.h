// oxdump/metadata/layout.h — самоопределение назначений секций метадаты.
//
// Позиции полей в заголовке зависят от версии Unity и могут съехать. Вместо
// жёсткой карты «поле 0xE0 = типы» определяем назначение каждой секции по её
// СОДЕРЖИМОМУ: размер записи, диапазоны значений, перекрёстные ссылки. Так
// дампер переживает не только смену ключа, но и перестановку полей.
#pragma once
#include "oxdump/common.h"
#include "oxdump/metadata/header.h"
#include "oxdump/metadata/headerless.h"
#include <string>
#include <functional>

namespace oxdump::metadata {

// sizeof(Il2CppTypeDefinition) в v27..v39 — проверено.
constexpr u32 TYPEDEF_REC = 82;

class Layout {
public:
    // md должен пережить Layout: храним ссылку, копий не делаем.
    explicit Layout(const Metadata& md);

    // Фабрика для headerless-режима: заполняет раскладку напрямую из находок
    // headerless::recover(), минуя detect() (он опирается на секции заголовка,
    // которых тут нет). Вторичные таблицы (образы, параметры, свойства)
    // остаются нулевыми — на dump.cs/il2cpp.h/offsets.h это не влияет.
    static Layout make_from_headerless(const Metadata& md,
                                       const headerless::HeaderlessResult& hr);

    u32 string_offset = 0;
    u32 string_size = 0;
    u32 typedef_offset = 0;
    u32 typedef_count = 0;
    u32 image_offset = 0;
    u32 image_count = 0;
    u32 method_offset = 0;
    u32 method_count = 0;
    u32 field_offset = 0;
    u32 field_count = 0;
    u32 param_offset = 0;
    u32 param_count = 0;
    u32 prop_offset = 0;
    u32 prop_count = 0;

    // Годность: найдены типы, строки и основные таблицы.
    bool ok() const noexcept;
    std::string report() const;

private:
    // Тег-конструктор для headerless-пути: копирует поля из HeaderlessResult
    // и НЕ вызывает detect(). Тег отличает его от публичного Layout(md).
    struct direct_tag {};
    Layout(direct_tag, const Metadata& md,
           const headerless::HeaderlessResult& hr);

    // Все секции, похожие на нуль-терминированный ASCII (печатных ≥ 95%).
    std::vector<Section> ascii_sections() const;
    void detect_strings();
    void detect_typedefs();
    // Ищет секцию, кратную rec_size, чьи записи проходят validator (по
    // равномерной выборке). validator получает смещение записи в файле.
    std::pair<u32, u32> detect_by_record(
        u32 rec_size, const std::function<bool(u32)>& validator) const;
    void detect_images();
    // Максимальный s32-индекс в поле записи typedef.
    s32 index_range(u32 field_off) const;
    // Ищет таблицу по ЧИСЛУ ЗАПИСЕЙ, которое требуют ссылки из typedef.
    std::pair<u32, u32> detect_by_index_range(u32 rec_size, s32 max_index) const;
    void detect_methods();
    void detect_fields();
    void detect();

    const Metadata& md_;
    // Раскладка построена headerless-режимом (без заголовка). Тогда ok()
    // мягче: вторичные таблицы могут не восстановиться, но типы+строки есть —
    // dump.cs соберётся. На обычном пути остаётся false, критерий строгий.
    bool headerless_ = false;
    // Подсказка от detect_strings: (typedef_offset, typedef_count), найденная
    // вместе со строковой секцией по совпадению "<Module>". Сильнее подсчёта
    // имён, поэтому detect_typedefs её не перетирает.
    bool have_td_hint_ = false;
    u32 td_hint_off_ = 0;
    u32 td_hint_cnt_ = 0;
};

} // namespace oxdump::metadata
