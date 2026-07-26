# v39 Metadata Layout (Oxide Survival Island)

> Собран из НАШЕГО файла `global-metadata.dat`, без копипаст с чужих
> проектов. Каждая строка имеет статус:
>
> - **VERIFIED** — тип структуры проверен на данных (round-trip,
>   токены CLI, замощение, имена читаются)
> - **PLAUSIBLE** — кратность и косвенный сигнал совпадают, но
>   структура не подтверждена на 100%
> - **UNKNOWN** — назначение секции не установлено
> - **MIRRORED** — `stated size` в заголовке больше настоящего:
>   секция обрезается offset'ом следующей. Это packed-хак игры
>   (реальный размер = ближайший offset справа − наш offset).
>
> Ничего не сочиняется. Что не проверено — то и стоит UNKNOWN.

## Общие цифры

```
magic     = 0xFAB11BAF
version   = 39   (задранный номер: раскладка фактически v27/v29,
                  никаких (offset,size,count)-триплетов Unity 6000.3)
hdr end   = 0x17C  (шифрованная часть — пары offset+size по 4 байта)
xor key   = 0xA5C3F19D  (на этой сборке; авто-восстанавливается дампером)
секций    = 41  непустых пар в заголовке
```

## Карта секций (по полю заголовка)

| поле | offset       | stated size | real size    | статус | что это |
|------|--------------|-------------|--------------|--------|---------|
| 0x008 | 0xDBE2C     |   3,102,018 |      645,424 | VERIFIED + MIRRORED | **string data** — utf-8 nul-terminated |
| 0x020 | 0x3D1370    |      45,024 |       45,024 | PLAUSIBLE | rec=12 count=3,752 (ParameterDefinition или FieldRef) |
| 0x028 | 0x754       |  24,565,820 |          318 | UNKNOWN + MIRRORED |  |
| 0x030 | 0x1228      |       1,162 |        1,162 | UNKNOWN |  |
| 0x038 | 0x13BC73C   |      42,816 |       42,816 | PLAUSIBLE | rec=12 count=3,568 |
| 0x040 | 0x29D0      |   4,047,696 |          328 | UNKNOWN + MIRRORED |  |
| 0x048 | 0x9A90C     |      31,655 |       31,655 | PLAUSIBLE | строки/имена |
| 0x050 | 0xBB2B08    |   3,987,136 |    3,987,136 | PLAUSIBLE | rec=8 count=498,392 (interfaceOffset?) |
| 0x058 | 0x3CD6C0    |  11,920,540 |       15,536 | PLAUSIBLE + MIRRORED | строки/имена |
| 0x060 | 0x1446C     |       6,921 |        6,921 | UNKNOWN |  |
| 0x068 | 0x18E81C0   |     619,760 |      619,760 | PLAUSIBLE | rec=8 count=77,470 |
| 0x080 | 0x176EA64   |   1,546,076 |    1,546,076 | PLAUSIBLE | rec=4 count=386,519 (индексы) |
| 0x088 | 0x17975C    |      96,696 |       96,696 | PLAUSIBLE | строки |
| 0x090 | 0xC4471     |      24,078 |       24,078 | PLAUSIBLE | строки |
| 0x098 | 0x13A4CDC   |      96,864 |       96,864 | PLAUSIBLE | rec=12 count=8,072 |
| 0x0A0 | 0x17A6      |  21,899,344 |        4,650 | UNKNOWN + MIRRORED |  |
| 0x0A8 | 0x35350     |      27,242 |        8,306 | PLAUSIBLE + MIRRORED | строки |
| **0x0B0** | **0x176605C** |   6,804 |        6,804 | **VERIFIED** | **Il2CppImage** (rec=40) — сборки .dll |
| 0x0C0 | 0x269DCC    |     210,897 |      210,897 | PLAUSIBLE | строки |
| **0x0C8** | **0x476C5C** | 7,239,744 |    7,239,744 | **VERIFIED** | **MethodDefinition** (rec=32, 226,242 записей) |
| 0x0D0 | 0x373C2     |  24,541,936 |       36,414 | PLAUSIBLE + MIRRORED | строки |
| 0x0D8 | 0x3234      |         189 |          189 | UNKNOWN |  |
| **0x0E0** | **0x1517BA0** | 2,417,852 |  2,417,852 | **VERIFIED** | **TypeDefinition** (rec=82, 29,486 записей) |
| 0x0E8 | 0x732E      |  20,737,660 |       15,854 | UNKNOWN + MIRRORED |  |
| 0x0F0 | 0xB11C      |      11,335 |       11,335 | UNKNOWN |  |
| 0x0F8 | 0x197F6B0   |     106,376 |      106,376 | PLAUSIBLE | rec=8 count=13,297 |
| 0x100 | 0x67E2      |  26,842,680 |        2,892 | PLAUSIBLE + MIRRORED | rec=12 count=241 |
| 0x108 | 0x12D98     |       9,651 |        5,844 | PLAUSIBLE | rec=12 count=487 |
| 0x110 | 0x17C       |      96,316 |        1,496 | PLAUSIBLE + MIRRORED | rec=8 count=187 |
| 0x118 | 0x5E0F      |  20,430,092 |        2,515 | UNKNOWN + MIRRORED |  |
| 0x120 | 0x26D86     |      11,365 |       11,365 | PLAUSIBLE | строки |
| 0x128 | 0x19AC3D0   |      12,556 |       12,556 | PLAUSIBLE | rec=4 count=3,139 |
| 0x130 | 0xC43       |  24,554,788 |        1,509 | UNKNOWN + MIRRORED |  |
| 0x138 | 0x2B18      |       1,379 |        1,379 | UNKNOWN |  |
| 0x140 | 0x13D1F98   |   1,116,344 |    1,116,344 | PLAUSIBLE | rec=8 count=139,543 |
| 0x148 | 0x4422E     |  16,253,384 |      354,014 | PLAUSIBLE + MIRRORED | строки |
| 0x150 | 0x1B618     |       9,346 |        9,346 | PLAUSIBLE | строки |
| 0x158 | 0x13A2A94   |       8,776 |        8,776 | PLAUSIBLE | rec=8 count=1,097 |
| 0x160 | 0x892       |  12,003,592 |          945 | UNKNOWN + MIRRORED |  |
| 0x168 | 0x40200     |      21,888 |       16,430 | PLAUSIBLE | строки |
| **0x170** | **0x12055AC** | 1,533,792 |  1,533,792 | **VERIFIED** | **FieldDefinition** (rec=12, 127,816 записей) |

## Il2CppTypeDefinition (rec = 82 байт, VERIFIED)

Раскладка выведена замощением: `fieldStart[i] + fieldCount[i] == fieldStart[i+1]`
по отсортированной таблице. Результат: **22 241 совпадений, 0 расхождений**,
9 из 9 полей проверены на 4 разных сборках игры.

| offset | тип | поле | комментарий |
|--------|-----|------|-------------|
| 0x00 | u32 | nameIndex        | индекс в string data |
| 0x04 | u32 | namespaceIndex   | индекс в string data |
| 0x08 | s32 | byvalTypeIndex   | индекс в types[]; **замыкает петлю на этот же typedef** — round-trip 100% |
| 0x0C | s32 | declaringType    | -1 для верхнеуровневых, иначе types[] на объемлющий |
| 0x10 | s32 | parentIndex      | базовый тип через types[]; -1 у System.Object |
| 0x16 | u16 | flags            | TypeAttributes: 0x20 Interface, 0x80 Abstract, 0x100 Sealed |
| 0x1A | s32 | fieldStart       | индекс в FieldDefinition; -1 если полей нет |
| 0x1E | s32 | methodStart      | индекс в MethodDefinition |
| 0x3A | u16 | methodCount      | число методов ЭТОГО типа |
| 0x3E | u16 | fieldCount       | число полей ЭТОГО типа (найдено замощением; раньше считалось что поля нет — из-за этого enum LeanProp получал 42 поля вместо 11) |

## Il2CppFieldDefinition (rec = 12 байт, VERIFIED)

Токен 0x04 в поле token в **1000 из 1000** проверенных записей.

| offset | тип | поле |
|--------|-----|------|
| 0x00 | u32 | nameIndex — индекс имени |
| 0x04 | s32 | typeIndex — индекс в types[] |
| 0x08 | u32 | token — метадата-токен CLI (0x04XXXXXX) |

## Il2CppMethodDefinition (rec = 32 байт, ЧАСТИЧНО)

Полностью проверено только:
- 0x00 u32 **nameIndex** — VERIFIED, разрешается в string data
- 0x14 u32 **token** — VERIFIED, старший байт 0x06 в 100% выборки

Остальное — PLAUSIBLE, ещё не доверифано:
- 0x04 s32 declaringType — индекс в types[]
- 0x08 s32 returnType — индекс в types[], 99.9% разрешается через types[]
- 0x10 s32 parameterStart — индекс в ParameterDefinition
- 0x1C u16 flags
- 0x1E u16 iflags
- 0x20 u16 slot
- 0x22 u16 parameterCount

Из-за того что раскладка Method не финализирована, генератор `dump.cs`
иногда выдаёт мусорные имена параметров вида "ssembly-CSharp" —
это следствие сдвига в парсинге записи метода на 1 байт.

## Il2CppImage (rec = 40 байт)

Не размечал по полям, но:
- 0x00 u32 nameIndex — VERIFIED, читается как "Assembly-CSharp.dll",
  "mscorlib.dll" и т.д.
- размер записи 40 байт стабильно совпадает с (real_size / 6,804 = 40 × 170)

## Как это использовать

Ключ к безболезненному обновлению — использовать не абсолютные
offset'ы, а логические поля таблиц. TDI и type_idx конкретных классов
можно взять из `offsets.h` дампера. Оффсеты полей в объектах (например
`PlayerManager.kccReference = 0xB0`) стабильны между сборками игры,
поскольку определяются раскладкой полей самого класса, а не таблицами
метаданных.

## Что не выведено и почему

- **13 из 41 секций** помечены UNKNOWN. Все они мелкие (`< 20 КБ`), для
  дампа классов и офсетов полей они не нужны — там лежат generic-
  параметры/ограничения, custom attributes ranges и т.п. Без них
  `dump.cs`, `il2cpp.h` и `offsets.h` собираются полностью.
- **Method полностью** — из-за оспариваемого размера записи. Токен 0x06
  и nameIndex подтверждают, что запись сама валидна, а вот
  parameterStart и flags надо ещё сверить на нескольких сборках.

## Что дало это исследование чит-читу

- `fieldCount` (+0x3E) — реальный счётчик полей, а не эвристика.
  Убрал 12.2% лишних полей у типов (заметнее всего у enum'ов).
- Заголовок теперь можно восстанавливать по содержимому файла,
  даже если XOR-заголовок вырезан или заменён на AES/RC4 —
  тело файла не шифруется, все таблицы находятся сканированием
  (см. `oxdumper/headerless.py`).
