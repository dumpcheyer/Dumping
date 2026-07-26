# Eclips (stable)

Внешний чит для Oxide: Survival Island. Одна кодовая база — две сборки:
Android arm64 (обычный телефон) и Android x86_64 (BlueStacks / эмулятор).

Оффсеты полей IL2CPP-классов одинаковые на обеих архитектурах, поэтому
разделять исходники нет смысла — меняется только `APP_ABI` в
`Application.mk`.

## Структура

```
Eclips_stable/
├─ src/         — исходники (C++17)
├─ include/     — заголовки, оффсеты, ImGui, ассеты
├─ lua/         — lua-5.4.7 (amalgamated)
├─ bin/         — готовые бинари обеих сборок
│   ├─ eclipsoxide_arm64      arm64-v8a
│   └─ eclipsoxide_x86_64     x86_64 (BlueStacks)
├─ Android.mk
├─ Application.mk
├─ build_arm64.sh
└─ build_x86.sh
```

## Сборка

Нужен Android NDK r26d (или совместимый).

```sh
NDK=/путь/к/android-ndk ./build_arm64.sh
NDK=/путь/к/android-ndk ./build_x86.sh
```

Результат в `bin/eclipsoxide_arm64` и `bin/eclipsoxide_x86_64`.

## Запуск на устройстве

```sh
adb push bin/eclipsoxide_arm64 /data/local/tmp/eclipsoxide
adb shell su -c "chmod +x /data/local/tmp/eclipsoxide && /data/local/tmp/eclipsoxide"
```

Игра должна быть запущена. Требуется root.

## Известные ограничения (по коду на 2026-07-25)

- **Валл-чек и скрытие тимейтов** отключены в меню: клиентских источников
  геометрии и команды в этой версии игры нет (`saveList` серверный,
  `TeammateStates` пустой).
- **Скелет** отключён: `KCC.head` трансформ не читается.
- **Snapshot HP/inventory** переживает респавн (кэш инвалидируется по
  тухлому PM).

## Совместимость метадаты

Проверено на четырёх сборках игры (v39). Все оффсеты полей одинаковые
на arm64 и x86_64 — см. `TypeDefIndex: 8357 PlayerManager`,
`kccReference` = 0xB0 и т.д.
