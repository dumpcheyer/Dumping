# CURRENT_2026_07_24 — актуальный снимок исходника

Рабочая версия чита на игровой билд от 2026/07/24.

- `UPDATE_GUIDE.md` — **подробная инструкция как обновлять на новую версию игры**
  (снять дамп, расшифровать header, найти TDI/byval, вытащить RVA-слоты
  disasm'ом, перегенерировать dump.cs, сверить field-оффсеты, собрать)
- `src/` + `include/` — исходники этой ревизии
- Остальные модули берутся из основной ветки `proj/`

## Константы этой ревизии

```
IL2CPP_TYPES_RVA         0xB77C750   (104776 entries)
s_TypeInfoTable slot     0xBF80FF0
MetadataCache*           0xBF80FF8
metadata_base            0xBF81008
header ptr               0xBF81010
stride                   0xBF8101C
XOR key                  0xA5C3F19D
typeDefinitionsCount     29486

                     TDI     byval    name_off
PlayerManager        8357    60998    0x171ee6
BuildingPiece        8633    46457    0x10c379
PlayerVitals         8030    61062    0x16aee6
RaycastManager       8155    62232    0x16e16d
MouseLook            8009    58788    0xedbf8
Camera              13810    46796    0x136e5e
EntityVitals         8019    50770    0x16a593
GenericVitals        8021    52632    0x16a67e
FPManager            8123    51358    0x16d0e7
```

## Что починено в этой ревизии

**Резолвер klass — верификация по содержимому строки.**
Прошлая версия сверяла `klass->name` с `metadata_base + hardcoded_offset` и
требовала точного совпадения адресов. Лог показал что это неверно:
```
BuildingPiece klass=0x7c01eebd48 name_ptr=0x7c25fa6d44 ожидали 0x7c40583379
```
`name_ptr` указывает в **libil2cpp .rodata** (base 0x7c21418000 + RVA 0x4b8ed44),
а не в загруженный metadata-блоб (0x7c40477000). В этой сборке строки имён
классов живут в самой либе. Теперь резолвер читает C-строку и сравнивает
содержимое через `ox_asciiEquals` — источник указателя не важен.

**Self-heal при съехавшем TDI.**
Если `table[TDI]` пустой, чит один раз сканирует всю `s_TypeInfoTable`
(29486 слотов, bulk-чтение по 4096 указателей) и находит слот по имени
класса + namespace. Найденный TDI кэшируется на сессию. Лог:
```
[self-heal] PlayerManager: НАЙДЕН на TDI 8412 (был 8357), klass=0x... ns='Oxide'
```
Чтения идут по таблице указателей внутри libil2cpp, не по анон-памяти игры —
watchdog не срабатывает.

**Меню компактнее, модель крупнее.**
```
окно landscape    0.94 -> 0.78 ширины экрана
окно высота       0.88 -> 0.80
uiScale           3.0  -> 2.55
sidebar           188  -> 170 dp
preview           280  -> 320 dp
preview высота    430  -> 520 dp
модель            0.86 -> 0.94 высоты сцены
```
