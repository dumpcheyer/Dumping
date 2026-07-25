# DERH — Eclips Oxide, полный срез исходника

Снапшот на 2026-07-25. Собран и проверен на устройстве.

## Что здесь

Весь проект целиком: `src/`, `include/`, `lua/`, `Android.mk`, `Application.mk`.
Каталоги `obj/` и `libs/` не заливались — это артефакты сборки.

## Восстановление Font.h

`include/ImGui/font/Font.h` весит 6.89 МБ и не проходит через GitHub Contents API
(лимит 4 МБ на тело запроса). Он лежит рядом как `Font.h.gz.b64`.

```bash
cd include/ImGui/font
base64 -d Font.h.gz.b64 | gunzip > Font.h
md5sum Font.h   # должно быть 7c667be5b679273f9f4a0424c75d7261
rm Font.h.gz.b64
```

Без этого шага сборка упадёт на отсутствующем `OPPOSans_H`.

## Сборка

```bash
ndk-build -j8 \
  NDK_PROJECT_PATH=$(pwd) \
  APP_BUILD_SCRIPT=$(pwd)/Android.mk \
  NDK_APPLICATION_MK=$(pwd)/Application.mk
```

Проверено на NDK r26d. Результат: `libs/arm64-v8a/eclipsoxide` — standalone PIE,
запускается под `su`.

Если распаковывали NDK через `unzip`/Python zipfile — симлинки в тулчейне
превращаются в текстовые файлы и `clang` не находится. Восстанавливать вручную
по флагу `S_ISLNK` в `external_attr`.

## Состояние на момент снапшота

Работает:
- ESP: боксы, скелет по реальным костям, HP-бар, ник, оружие, дистанция
- Броня, флаги состояния (SLEEP / SPEC / PRIME), HP цифрой
- Цвет бокса по дистанции
- Радар-миникарта 360°
- Аимбот с фильтром сокомандников
- Фикс дрейфа ESP после респавна (выбор владельца камеры по геометрии)

Открыто:
- Валл-чек (LOS) — ждём лог с диагностикой `[LOS]`
- ADS-only аим — ждём лог с `[ads]`

## Оффсеты

Все в `include/oxide_offsets.h`. Актуальны для сборки игры от 2026-07-24.
Резолв классов идёт через `s_TypeInfoDefinitionTable[TDI]`, не через
захардкоженные TypeInfo RVA — переживает мелкие обновления.
