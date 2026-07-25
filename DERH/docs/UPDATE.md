# Обновление под новую версию игры

Пошагово, от «вышла обнова» до «собрал и играю». Проверено на трёх апдейтах
подряд (2026/07/23, 07/24, 07/25).

**Время:** 30-50 минут, если ничего не сломалось концептуально.

---

## Что вообще ломается при обновлении

Не всё сразу. Порядок по вероятности:

| Что | Ломается | Почему |
|---|---|---|
| Смещения таблиц метаданных | **Каждый раз** | Пересобирается global-metadata.dat |
| TypeInfo type-index | **Каждый раз** | Сдвигается массив types |
| TypeDefIndex (TDI) | Иногда | Только если добавили/убрали классы |
| Field-оффсеты | **Почти никогда** | Обфускатор рандомизирует ИМЕНА, не раскладку |
| RVA методов | Каждый раз | Но нам они не нужны |

Ключевой факт из практики: за три апдейта подряд **ни один field-оффсет не
изменился**. Менялись только адреса таблиц. Поэтому не начинай с
перепроверки всех полей — начни с таблиц.

---

## Шаг 0. Достать файлы с устройства

Нужны два:

```
libil2cpp.so        из /data/app/.../lib/arm64/
global-metadata.dat из /data/app/.../assets/bin/Data/Managed/Metadata/
```

Проще всего вытащить из APK: это обычный zip.

```bash
unzip -o base.apk 'lib/arm64-v8a/libil2cpp.so' \
                  'assets/bin/Data/Managed/Metadata/global-metadata.dat'
md5sum libil2cpp.so global-metadata.dat   # запиши, пригодится
```

Если APK разбит на split-части, `libil2cpp.so` обычно лежит в
`split_config.arm64_v8a.apk`.

---

## Шаг 1. Найти таблицы в метаданных

```bash
cd Nov
python3 resolver.py --meta /path/global-metadata.dat --so /path/libil2cpp.so
```

Скрипт печатает найденные значения. Перенеси их в шапку `resolver.py`:

```python
STR       = 0x000DBE2C   # header[0x08] ^ KEY   строки
TYPE_OFF  = 0x01517BA0   # header[0xE0] ^ KEY   таблица TypeDefinition
TYPE_CNT  = 29486        # header[0xE8] ^ KEY   сколько их
TYPES_VA  = 0xb75e020    # metadataRegistration->types
TYPES_CNT = 104776
```

### Заголовок зашифрован

С апдейта 2026/07/24 поля заголовка метаданных **XOR-зашифрованы** ключом
`0xA5C3F19D` в диапазоне `[0x08, 0x17C)`. Магия `0xFAB11BAF` при этом лежит
открыто — по ней и находится начало.

Если `resolver.py` выдаёт мусорные смещения (больше размера файла или
отрицательные) — скорее всего сменили ключ. Найти новый:

```python
# magic лежит по смещению 0, версия (39) по 0x04 — оба НЕ шифруются.
# Поле 0x08 (stringLiteralOffset) всегда невелико и выровнено по 4.
raw = open('global-metadata.dat','rb').read()
import struct
enc = struct.unpack_from('<I', raw, 0x08)[0]
# перебираем: реальное значение должно быть < len(raw) и кратно 4
for guess in range(0x100):
    pass  # проще: XOR с ожидаемым диапазоном, см. typeinfo_offline.py
```

Готовая проверка ключа лежит в `Nov/typeinfo_offline.py`.

---

## Шаг 2. Прогнать дампер

```bash
python3 dumpgen.py     # -> dump.cs
python3 il2cppgen.py   # -> il2cpp.h
python3 scriptgen.py   # -> script.json
python3 codereg.py     # -> codereg.json
```

Константы в шапках этих скриптов тоже правятся — их печатает `resolver.py`:

```python
# dumpgen.py / scriptgen.py
IMG_OFF   = 0x0176605C; IMG_CNT = 189    # образы (сборки)
METH_OFF  = 0x00476C5C                    # методы
FLD_OFF   = 0x012055AC                    # поля
PARAM_OFF = 0x00F9B7E0                    # параметры
PROP_OFF  = 0x003DC350                    # свойства
FIELDOFF_VA = 0xbaa2cd8                   # таблица смещений полей

# codereg.py
ASM_SLOT  = 0xb9ab9f0                     # reloc-слот Assembly-CSharp
```

**Известная особенность:** `scriptgen.py` и `il2cppgen.py` пишут в `/data/`.
Создай каталог заранее либо поправь пути в скриптах.

### Проверка что дамп не мусор

```bash
grep -c "^public class" dump.cs        # должно быть ~7000
grep -n "class PlayerManager :" dump.cs # должен найтись
```

Если классов сотни вместо тысяч — смещения неверны, вернись к шагу 1.

---

## Шаг 3. Обновить TypeDefIndex

```bash
grep -n "class PlayerManager :" dump.cs
# public class PlayerManager : Mirror.NetworkBehaviour // TypeDefIndex: 8357
```

Нужны девять:

| Класс | Где искать |
|---|---|
| `Oxide.PlayerManager` | `class PlayerManager :` |
| `Oxide.Building.BuildingPiece` | `class BuildingPiece :` |
| `Oxide.PlayerVitals` | `class PlayerVitals` |
| `Oxide.RaycastManager` | `class RaycastManager` |
| `Oxide.MouseLook` | `class MouseLook` |
| `UnityEngine.Camera` | `class Camera :` |
| `Oxide.EntityVitals` | `class EntityVitals :` |
| `Oxide.GenericVitals` | `class GenericVitals` |
| `Mirror.NetworkClient` | `class NetworkClient` |

Дальше пересчитать type-index (это НЕ то же самое, что TDI):

```bash
python3 typeinfo_offline.py --meta global-metadata.dat --so libil2cpp.so
```

Он печатает готовый блок для `include/oxide_offsets.h` и **сам проверяет**
каждое значение: `types[byval].klassIndex == TDI`, `kind == 0x12 (CLASS)`,
`byref == 0`, `pinned == 0`. Если хоть одна проверка не прошла — не
переноси, разбирайся.

---

## Шаг 4. Обновить рантайм-резолвер

В `src/main.cpp`, блок около строки 1144:

```cpp
// Смещения строк с ИМЕНАМИ классов внутри global-metadata.dat.
// Находятся так: grep -abo "PlayerManager" global-metadata.dat
static constexpr uint64_t OX_META_NAME_OFF_PLAYERMANAGER = 0x171ebc;
static constexpr uint64_t OX_META_NAME_OFF_BUILDINGPIECE = 0x10c433;
static constexpr uint64_t OX_META_NAME_OFF_PLAYERVITALS  = 0x16aebf;

// Адреса в libil2cpp BSS. Печатает resolver.py.
static constexpr uint64_t OX_META_MC_RVA         = 0xbf613f8;
static constexpr uint64_t OX_META_BASE_PTR_RVA   = 0xbf61408;
static constexpr uint64_t OX_META_HEADER_PTR_RVA = 0xbf61410;
static constexpr uint64_t OX_META_STRIDE_RVA     = 0xbf6141c;
static constexpr uint64_t OX_S_TYPEINFO_TABLE_RVA = 0xBF61440ULL;
```

Смещения имён — простым грепом:

```bash
grep -abo "PlayerManager" global-metadata.dat | head
```

Бери то, где сразу после строки идёт `\x00`, а перед ней — тоже `\x00`
(строки в метаданных нуль-терминированы и упакованы вплотную).

---

## Шаг 5. Проверить, что field-оффсеты не поехали

Быстрая сверка старого и нового `il2cpp.h`:

```bash
python3 - << 'EOF'
import re
def fields(path, cls):
    s = open(path, encoding='utf-8', errors='replace').read()
    i = s.index(f'struct {cls}_Fields')
    j = s.index('};', i)
    return re.findall(r'(\w+); // (0x[0-9A-Fa-f]+)', s[i:j])

for cls in ['Oxide_PlayerManager', 'Oxide_Building_BuildingPiece',
            'HyperHug_Games_Oxide_Features_Player_KCC']:
    old = dict((n, o) for n, o in fields('il2cpp_OLD.h', cls))
    new = dict((n, o) for n, o in fields('il2cpp.h', cls))
    # сравниваем ПО СМЕЩЕНИЯМ: имена обфускатор рандомизирует каждый раз
    if sorted(old.values()) == sorted(new.values()):
        print(f'{cls}: раскладка не изменилась')
    else:
        print(f'{cls}: РАСКЛАДКА ПОЕХАЛА, сверяй руками')
EOF
```

Сравнивай именно **множества смещений**, а не имена: обфускатор
переименовывает поля каждый апдейт, но их позиции держит.

---

## Шаг 6. Сборка и проверка

```bash
ndk-build -j8 \
  NDK_PROJECT_PATH=$(pwd) \
  APP_BUILD_SCRIPT=$(pwd)/Android.mk \
  NDK_APPLICATION_MK=$(pwd)/Application.mk \
  APP_CFLAGS=-DOX_ENABLE_LOG          # с логом — для первой проверки
```

Зайди в матч и посмотри лог. Ожидаемое:

```
[seed] NetworkClient klass=0x... (TDI 23916)
[cammat] view-матрица найдена @+0x70
[cammat] proj-матрица найдена @+0xB0
[w2s] matrix=1 cam=1 dead=0 isLocal=1 | anchors=7/9
```

Когда всё сошлось — пересобери без `APP_CFLAGS`, чтобы вырезать логирование.

---

## Если что-то не сошлось

| Симптом в логе | Причина | Куда смотреть |
|---|---|---|
| `klass не похож на указатель` | Неверный `OX_S_TYPEINFO_TABLE_RVA` | Шаг 4 |
| `fast-seed` не проходит | TDI или type-index устарели | Шаги 3-4 |
| `isLocal=-1` | Съехал `NB_NET_IDENTITY` (0x40) | Проверь в il2cpp.h |
| `matrix=0 viewOff=-2` | Матрицы не нашлись по подписи | Расширь окно поиска в `ox_findCameraMatrices` |
| `anchors=0/N`, `stage=2` | Не находится KCC | `KCC_PLAYER` (0x78) съехал |
| Игра падает через ~90 с | Watchdog засёк объём чтений | Ищи добавленный скан памяти |

Подробный разбор каждого — в `TROUBLESHOOTING.md`.
