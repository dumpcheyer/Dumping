# КАК ОБНОВЛЯТЬ ЧИТ НА НОВУЮ ВЕРСИЮ ИГРЫ

Полная пошаговая инструкция. Каждый апдейт Oxide Survival Island сдвигает
метаданные il2cpp — этот документ описывает как пересчитать ВСЕ константы
и собрать рабочий бинарь.

Проверено на апдейте 2026/07/24 (libil2cpp 199 229 776 -> 200 561 288 байт).

---

## 0. Что вообще ломается при апдейте

| Что | Ломается? | Почему |
|---|---|---|
| RVA методов (oxide_rva.h) | ДА | код пересобран, всё поехало |
| TypeDefinitionIndex (TDI) | ДА | классы добавили/убрали, индексы сдвинулись |
| byvalTypeIndex | ДА | следует за TDI |
| IL2CPP_TYPES_RVA | ДА | таблица типов переехала |
| s_TypeInfoTable slot RVA | ДА | BSS-слот переехал |
| MetadataCache / metadata_base / header slots | ДА | там же |
| Оффсеты имён классов в metadata | ДА | строковая таблица пересобрана |
| **Field-оффсеты (PM.mouseLook, BP.health и т.д.)** | **ОБЫЧНО НЕТ** | структуры классов меняются только если разработчик добавил/убрал поле |
| CLASS_NAME / CLASS_STATIC_FIELDS / CLASS_NAMESPACE | НЕТ | это layout самого il2cpp-рантайма, стабилен внутри одной версии Unity |
| HashSet / Dictionary / List layout | НЕТ | это .NET runtime, не игра |

Вывод: обязательно пересчитывать TDI/byval/RVA-слоты. Field-оффсеты
**проверить**, но обычно они не двигаются.

---

## 1. Снять дамп с устройства

Нужны два файла из установленной игры:

```bash
# путь к APK-либам (точный хеш каталога свой у каждой установки)
adb shell "su -c 'ls -d /data/app/*com.catsbit.oxidesurvivalisland*/lib/arm64'"

# libil2cpp.so — прямо из APK-каталога
adb shell "su -c 'cp /data/app/~~*com.catsbit.oxidesurvivalisland*/lib/arm64/libil2cpp.so /sdcard/Download/'"
adb pull /sdcard/Download/libil2cpp.so
```

`global-metadata.dat` лежит в assets и **зашифрован**:

```bash
adb shell "su -c 'find /data/app/*com.catsbit* -name global-metadata.dat'"
adb shell "su -c 'cp <путь>/global-metadata.dat /sdcard/Download/'"
adb pull /sdcard/Download/global-metadata.dat
```

Проверка что файлы те:
```bash
python3 -c "
import struct
b=open('libil2cpp.so','rb').read(20)
print('ELF:', b[:4]==b'\x7fELF', 'arch:', hex(int.from_bytes(b[0x12:0x14],'little')), '(0xb7=arm64)')
m=open('global-metadata.dat','rb').read(8)
print('magic:', hex(int.from_bytes(m[:4],'little')), '(0xfab11baf = ok)')
print('version:', int.from_bytes(m[4:8],'little'), '(39 = ok)')
"
```

Если magic не `0xfab11baf` — metadata зашифрован целиком, нужен
`proj/tools/decrypt_metadata.py`. Если magic правильный, но всё равно
не парсится — зашифрован **только заголовок** (см. шаг 2).

---

## 2. Расшифровать заголовок metadata

В сборках 2026/07+ заголовок XOR-шифруется ключом `0xA5C3F19D` в диапазоне
`[0x08, 0x17C)`. Magic и version остаются открытыми.

Как понять что заголовок шифрован: прочитать поле по 0xE8 (typeDefinitionsCount).
Если получается мусор (миллиарды) — шифрован.

```python
import struct
M = open('global-metadata.dat','rb').read()
XOR = 0xA5C3F19D
def hdr(off):
    return struct.unpack_from('<I', M, off)[0] ^ XOR

STR      = hdr(0x08)   # строковая таблица
TYPE_OFF = hdr(0xE0)   # typeDefinitions offset
TYPE_SZ  = hdr(0xE4)   # размер таблицы в байтах
TYPE_CNT = hdr(0xE8)   # количество типов
REC      = TYPE_SZ // TYPE_CNT   # должно выйти 82

print(f'STR=0x{STR:x} TYPE_OFF=0x{TYPE_OFF:x} cnt={TYPE_CNT} rec={REC}')
```

Sanity: `REC` обязан быть **82**. Если нет — ключ или диапазон другой,
надо искать XOR-константу в libil2cpp:

```python
# ищем movz w?,#<lo16> ; movk w?,#<hi16>,lsl#16 в .text
# для 0xA5C3F19D это lo=0xf19d hi=0xa5c3
```

Проверенный на 2026/07/24 результат:
```
STR      = 0xdbe2c
TYPE_OFF = 0x1523780
TYPE_CNT = 29486
REC      = 82
```

---

## 3. Найти TDI и byvalTypeIndex каждого класса

Полный скрипт (сохрани как `redump_tdi.py`):

```python
import struct
M = open('global-metadata.dat','rb').read()
XOR = 0xA5C3F19D
def hdr(off): return struct.unpack_from('<I', M, off)[0] ^ XOR

STR = hdr(0x08); TYPE_OFF = hdr(0xE0); TYPE_CNT = hdr(0xE8); REC = 82

def cstr(idx):
    o = STR + idx
    return M[o:M.find(b'\x00', o)].decode('utf-8', 'replace')

# что ищем: имя класса -> его namespace
targets = {
    'PlayerManager':  'Oxide',
    'BuildingPiece':  'Oxide.Building',
    'PlayerVitals':   'Oxide',
    'MouseLook':      'Oxide',
    'RaycastManager': 'Oxide',
    'Camera':         'UnityEngine',
    'EntityVitals':   'Oxide',
    'GenericVitals':  'Oxide',
    'FPManager':      'Oxide',
}

for tdi in range(TYPE_CNT):
    rec = TYPE_OFF + tdi * REC
    nm  = cstr(struct.unpack_from('<I', M, rec)[0])
    if nm not in targets: continue
    ns = cstr(struct.unpack_from('<I', M, rec + 4)[0])
    if ns != targets[nm]: continue
    byval    = struct.unpack_from('<i', M, rec + 8)[0]   # byvalTypeIndex
    name_off = STR + struct.unpack_from('<I', M, rec)[0]
    print(f'{ns}.{nm:16s} TDI={tdi:6d} byval={byval:6d} name_off=0x{name_off:x}')
```

Структура записи `Il2CppTypeDefinition`:
```
+0x00 uint32  nameIndex          -> смещение в STR
+0x04 uint32  namespaceIndex     -> смещение в STR
+0x08 int32   byvalTypeIndex     -> индекс в metadataRegistration->types[]
+0x0C int32   byrefTypeIndex     (обычно -1)
... всего 82 байта
```

Результат на 2026/07/24:
```
Oxide.PlayerManager           TDI=  8357 byval= 60998 name_off=0x171ee6
Oxide.Building.BuildingPiece  TDI=  8633 byval= 46457 name_off=0x10c379
Oxide.PlayerVitals            TDI=  8030 byval= 61062 name_off=0x16aee6
Oxide.RaycastManager          TDI=  8155 byval= 62232 name_off=0x16e16d
Oxide.MouseLook               TDI=  8009 byval= 58788 name_off=0xedbf8
UnityEngine.Camera            TDI= 13810 byval= 46796 name_off=0x136e5e
Oxide.EntityVitals            TDI=  8019 byval= 50770 name_off=0x16a593
Oxide.GenericVitals           TDI=  8021 byval= 52632 name_off=0x16a67e
Oxide.FPManager               TDI=  8123 byval= 51358 name_off=0x16d0e7
```

---

## 4. Найти RVA-слоты в libil2cpp (disasm)

Нужны 5 адресов. Все они рядом друг с другом в BSS. Находятся через
disasm функции `GetTypeInfoFromTypeDefinitionIndex`.

Установить capstone: `pip install --user capstone`

### 4.1 Найти кластер MetadataCache по XOR-ключу

```python
import struct
B = open('libil2cpp.so','rb').read()
e_phoff = struct.unpack_from('<Q', B, 0x20)[0]
segs = []
for i in range(struct.unpack_from('<H', B, 0x38)[0]):
    o = e_phoff + i*56
    if struct.unpack_from('<I', B, o)[0] == 1:   # PT_LOAD
        segs.append((struct.unpack_from('<Q', B, o+16)[0],   # vaddr
                     struct.unpack_from('<Q', B, o+8)[0],    # file offset
                     struct.unpack_from('<Q', B, o+32)[0]))  # filesz

tv, tfo, tsz = segs[1]          # сегмент 1 = RX (.text)
blob = B[tfo:tfo+tsz]

# ARM64: movk Wd, #0xa5c3, lsl #16
# encoding: 0 11 100101 01 iiiiiiiiiiiiiiii ddddd
base = (0b11 << 29) | (0b100101 << 23) | (0b01 << 21)
hits = []
for r in range(32):
    t = struct.pack('<I', base | (0xa5c3 << 5) | r)
    st = 0
    while True:
        i = blob.find(t, st)
        if i < 0: break
        if i % 4 == 0: hits.append(tv + i)
        st = i + 4
hits.sort()
print(f'{len(hits)} hits, cluster 0x{hits[0]:x}..0x{hits[-1]:x}')
```

На 2026/07/24: 34 попадания, кластер `0x4dff3a8 .. 0x4e019c8`.

### 4.2 Вытащить слоты из disasm кластера

```python
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)

def va2fo(va):
    for v, o, s in segs:
        if v <= va < v + s: return o + (va - v)
    return None

lo, hi = 0x4dfd000, 0x4e04000      # окно вокруг кластера
code = B[va2fo(lo): va2fo(lo) + (hi - lo)]

adrp = {}; loaded = {}
for ins in md.disasm(code, lo):
    p = [x.strip() for x in ins.op_str.split(',')]
    if ins.mnemonic == 'adrp':
        adrp[p[0]] = int(p[1].lstrip('#'), 0)
    elif ins.mnemonic == 'ldr':
        if len(p) >= 3 and p[1].startswith('[') and 'lsl' not in ins.op_str and 'sxtw' not in ins.op_str:
            br = p[1].lstrip('[')
            if br in adrp:
                loaded[p[0]] = adrp[br] + int(p[2].rstrip(']').lstrip('#'), 0)
        elif 'sxtw #3' in ins.op_str or 'lsl #3' in ins.op_str:
            br = p[1].lstrip('[')
            if br in loaded:
                print(f'0x{ins.address:x}: {ins.mnemonic} {ins.op_str}  <== slot 0x{loaded[br]:x}')
```

Искомая функция выглядит так (2026/07/24, `0x4dff360`):
```
0x4dff360: sub  sp, sp, #0xa0
0x4dff36c: adrp x8, #0xbf80000
0x4dff370: ldr  x21, [x8, #0xff0]           <-- s_TypeInfoTable slot = 0xBF80FF0
0x4dff374: ldr  x20, [x21, w0, sxtw #3]     <-- klass = table[TDI]
0x4dff378: dmb  ishld
0x4dff37c: cbnz x20, ...                    <-- уже закэширован?
...
0x4dff39c: adrp x8, #0xbf81000
0x4dff3a4: ldr  x8, [x8, #0x10]             <-- header ptr = 0xBF81010
0x4dff3a8: movk w11, #0xa5c3, lsl #16       <-- XOR-ключ
0x4dff3ac: ldp  w10, w9, [x8, #0xcc]        <-- header+0xCC/0xD0
0x4dff3b0: ldr  w8, [x8, #0xc8]             <-- header+0xC8
0x4dff3c8: ldr  x10, [x10, #8]              <-- metadata_base = 0xBF81008
0x4dff420: str  x20, [x21, w19, sxtw #3]    <-- запись обратно в таблицу
```

Опознание слотов:
- `s_TypeInfoTable` — тот, из которого читают с `sxtw #3` сразу после `adrp`
- `header ptr` — тот, чьи поля потом XOR'ятся ключом
- `metadata_base` — тот, к которому прибавляют смещение из header
- `MetadataCache*` — обычно `s_TypeInfoTable + 8`

Результат 2026/07/24 (ИСПРАВЛЕНО 2026/07/25 — см. 4.4):
```
s_TypeInfoDefinitionTable  0xBF81040   <- таблица КЛАССОВ (29486, индекс = TDI)
s_MethodInfoDefinitionTable 0xBF80FF0  <- таблица МЕТОДОВ, НЕ ТРОГАТЬ
MetadataCache* / ctx        0xBF80FF8
metadata_base               0xBF81008
header ptr                  0xBF81010
stride                      0xBF8101C
```

### 4.3 Проверить layout Il2CppClass

Экспорты `mono_class_*` — это тонкие обёртки, по ним читаются оффсеты:

```python
# .dynsym -> найти mono_class_get_name / _namespace / _parent / _image
# каждая = b <real>, а real = ldr x0, [x0, #OFF] ; ret
```

Результат 2026/07/24 (не изменился):
```
mono_class_get_image      -> ldr x0, [x0]        => image      @ 0x00
mono_class_get_name       -> ldr x0, [x0, #0x10] => name       @ 0x10
mono_class_get_namespace  -> ldr x0, [x0, #0x18] => namespace  @ 0x18
mono_class_get_parent     -> ldr x0, [x0, #0x58] => parent     @ 0x58
```
`static_fields @ 0xB8` — проверяется через disasm `Class::SetupFields`
(`bl <alloc>; str x0, [klass, #0xB8]`).


### 4.4 ЛОВУШКА: две функции с одинаковой формой

**Это стоило нам целого дня.** В кластере есть ДВЕ функции с идентичной
структурой (XOR-ключ + `sdiv` + cache-write по индексу). Pattern-скан ловит
первую попавшуюся, и она почти всегда НЕ ТА.

```
GetMethodInfoFromMethodDefinitionIndex  @0x4dff360  -> кэш 0xBF80FF0  (226854 слота)
Class::FromTypeDefinition               @0x4e0030c  -> кэш 0xBF81040  (29486 слотов)  <-- НУЖНА ЭТА
```

Обе делают `adrp; ldr xT,[xA,#off]; ldr xK,[xT, wIdx, sxtw #3]; ...; str xK,[xT,...]`.
Отличить можно ТОЛЬКО по тому, какое поле заголовка они делят:

```
методы:  ldp w10,w9,[header,#0xcc]  ldr w8,[header,#0xc8]   -> recsz 32, count 226854
классы:  ldp w10,w9,[header,#0xe4]  ldr w8,[header,#0xe0]   -> recsz 82, count 29486
```

**Надёжный способ — читать `MetadataCache::Initialize`, а не accessor'ы.**
Там обе таблицы аллоцируются подряд и видно какой размер куда идёт:

```
0x4dff5f8: ldr w8,[header,#0xe8]; eor KEY   ; 29486  = typeDefinitionsCount
0x4dff608: bl  alloc(count, 8)
0x4dff618: str x0, [0xBF81040]              ; <- s_TypeInfoDefinitionTable
0x4dff61c: ldr w8,[header,#0xd0]; eor KEY   ; 226854 = methodsCount
0x4dff62c: bl  alloc(count, 8)
0x4dff63c: str x0, [0xBF80FF0]              ; <- s_MethodInfoDefinitionTable
```

Как найти `Initialize`: искать функцию, которая пишет в `metadata_base`
и `header ptr` слоты (`str x?, [0x????008]` / `[0x????010]`), а следом
делает серию `alloc + str` в соседние слоты.

Скрипт-детектор:

```python
# в окне кластера ищем: ldr w?,[x?,#IMM] ; eor ; ... ; bl ; str x0,[global]
# затем расшифровываем header[IMM] ^ 0xA5C3F19D и смотрим что за count:
#   == typeDefinitionsCount (из шага 2) -> это s_TypeInfoDefinitionTable
#   иначе                               -> другая таблица, пропускаем
```

**Мнемоника на будущее:** `s_TypeInfoDefinitionTable = <ctx global> + 0x48`.
```
old: 0xBE3BB10 + 0x48 = 0xBE3BB58   ok
new: 0xBF80FF8 + 0x48 = 0xBF81040   ok
```
Все metadata-глобалы между этими билдами сдвинулись **одинаково на +0x1454E8** —
если нашёл один, остальные считаются вычитанием старой дельты.

### 4.5 Как отличить правильную таблицу на живом устройстве

Прочитать любой заполненный слот и посмотреть `+0x10`:
- указывает на **читаемую C-строку** (имя класса) -> таблица классов, верно
- указывает на **код** (`stp x30,x19,[sp,#-0x10]!` = `fe4fbfa9`) -> таблица методов, неверно

Именно так и вскрылась ошибка: `klass+0x10 = base + 0x4b8ed44`, а по этому
RVA в файле лежит `fe 4f bf a9` — пролог функции, не строка.


---

## 5. Перегенерировать dump.cs / il2cpp.h / script.json

```bash
cd Nov
cp /path/to/new/libil2cpp.so       .
cp /path/to/new/global-metadata.dat .

# скрипты частично хардкодят /data — создать и положить туда же
mkdir -p /data
cp libil2cpp.so global-metadata.dat /data/

python3 test_typeinfo_offline.py            # должно быть 39/39 PASS

OX_LIBIL2CPP=$PWD/libil2cpp.so \
OX_METADATA=$PWD/global-metadata.dat \
OX_CODEREG=$PWD/codereg.json \
python3 -B codereg.py

OX_LIBIL2CPP=$PWD/libil2cpp.so \
OX_METADATA=$PWD/global-metadata.dat \
OX_CODEREG=$PWD/codereg.json \
python3 -B dumpgen.py                        # -> dump.cs

python3 -B scriptgen.py                      # -> /data/script.json
python3 -B il2cppgen.py                      # -> /data/il2cpp.h
```

Известный баг: `scriptgen.py` и `il2cppgen.py` хардкодят пути `/data/`.
Env-var правки из PR #5 их не покрыли. Обход — `mkdir /data` выше.

---

## 6. Сверить field-оффсеты (обычно НЕ меняются)

```bash
grep -A 40 '^struct Oxide_PlayerManager_Fields' /data/il2cpp.h | head -45
grep -A 25 '^struct Oxide_MouseLook_Fields'     /data/il2cpp.h
grep -A 15 '^struct Oxide_RaycastManager_Fields' /data/il2cpp.h
grep -A 40 '^struct Oxide_Building_BuildingPiece_Fields' /data/il2cpp.h | grep -E 'health|Bounds|Grade|\bid\b'
grep -A 6  '^struct Oxide_GenericVitals_Fields' /data/il2cpp.h
```

Эталон (проверен на двух апдейтах подряд, НЕ менялся):
```
PlayerManager:
  worldCameraRoot      0x68     mouseLook           0x70
  raycastManager       0x88     vitals              0xC8
  team (WNn)           0x120    characterModel      0x150
  animator             0x190    lastTickPosition    0x1C8
  lastSavedPosition    0x1D4    lastDeathPosition   0x1E0
  playerFlags          0x250    userID              0x278
  teamName             0x280

MouseLook:
  m_LookRoot           0x28     kqP (Vector2)       0x60
    kqP.x = pitch (град), kqP.y = yaw (град)

RaycastManager:
  player               0x20     m_WorldCamera       0x30
  m_RayLength          0x38     m_AimRayLength      0x3C
  m_LayerMask          0x48     m_AimLayerMask      0x4C

BuildingPiece:
  m_Bounds             0xD0     additionalBounds    0xF8
  m_Grade              0x190    gradeHolder         0x198
  health               0x380    maxHealth           0x384
  id                   0x38C
  static: saveList @ +0x0 (HashSet<T>!), saveLookup @ +0x8 (Dictionary)

GenericVitals:
  m_MaxHealth          0x88

FPManager:
  kYl (текущий vFOV)   0xA0     _kSQ (базовый vFOV) 0xAC
  kSP (вычитаемое)     0xB4
    effective_vFOV = kYl - kSP;  ADS если kYl < _kSQ * 0.90
```

Если что-то съехало — правь `include/oxide_offsets.h`.

Обфускатор рандомизирует ИМЕНА полей каждый апдейт (`kqP` -> `xyZ` и т.п.),
но порядок и смещения держатся. Ориентируйся на **позицию и тип**, не на имя.

---

## 7. Прописать новые константы

### `include/oxide_offsets.h`
```cpp
static constexpr uint64_t IL2CPP_TYPES_RVA               = 0x????????;
static constexpr int32_t  PLAYERMANAGER_TYPEINFO_TYPEIDX  = ?????;  // byval
static constexpr int32_t  BUILDINGPIECE_TYPEINFO_TYPEIDX  = ?????;
static constexpr int32_t  PLAYERVITALS_TYPEINFO_TYPEIDX   = ?????;
static constexpr int32_t  RAYCASTMANAGER_TYPEINFO_TYPEIDX = ?????;
static constexpr int32_t  MOUSELOOK_TYPEINFO_TYPEIDX      = ?????;
static constexpr int32_t  CAMERA_TYPEINFO_TYPEIDX         = ?????;
static constexpr int32_t  ENTITYVITALS_TYPEINFO_TYPEIDX   = ?????;
static constexpr int32_t  GENERICVITALS_TYPEINFO_TYPEIDX  = ?????;
```

### `src/main.cpp` — блок MetadataCache (искать `OX_META_MC_RVA`)
```cpp
static constexpr uint64_t OX_META_MC_RVA         = 0x????????;
static constexpr uint64_t OX_META_BASE_PTR_RVA   = 0x????????;
static constexpr uint64_t OX_META_HEADER_PTR_RVA = 0x????????;
static constexpr uint64_t OX_META_STRIDE_RVA     = 0x????????;
```

### `src/main.cpp` — блок fast-seed (искать `OX_S_TYPEINFO_TABLE_RVA`)
```cpp
static constexpr uint64_t OX_S_TYPEINFO_TABLE_RVA = 0x????????ULL;  // = ctx + 0x48
static constexpr uint32_t OX_TDI_PLAYERMANAGER    = ????;   // TDI, не byval!
static constexpr uint32_t OX_TDI_BUILDINGPIECE    = ????;
static constexpr uint32_t OX_TDI_PLAYERVITALS     = ????;
static constexpr uint32_t OX_TYPEDEF_COUNT        = ?????;
```

ВАЖНО: `s_TypeInfoTable` индексируется по **TDI**, а не по byval.
byval нужен только для `metadataRegistration->types[]`.

### `src/main.cpp` — оффсеты имён (искать `OX_META_NAME_OFF_`)
```cpp
static constexpr uint64_t OX_META_NAME_OFF_PLAYERMANAGER = 0x??????;
static constexpr uint64_t OX_META_NAME_OFF_BUILDINGPIECE = 0x??????;
static constexpr uint64_t OX_META_NAME_OFF_PLAYERVITALS  = 0x??????;
```

Примечание: с версии от 2026/07/24 эти три константы уже НЕ используются для
верификации — резолвер сверяет **содержимое** строки, а не адрес. Оставлены
для справки, потому что в некоторых сборках строки имён лежат в metadata,
а в некоторых — в `.rodata` самой libil2cpp.

---

## 8. Собрать

```bash
export NDK=/path/to/android-ndk-r27
cd proj
$NDK/ndk-build -j$(nproc) NDK_PROJECT_PATH=$PWD \
    NDK_APPLICATION_MK=$PWD/Application.mk APP_BUILD_SCRIPT=$PWD/Android.mk
```

Артефакт: `proj/libs/arm64-v8a/eclipsoxide`.

Нужен `proj/include/ImGui/font/Font.h` (gitignored, ~2.2 МБ). Если нет —
взять из прошлого релиза или сгенерировать через `binary_to_compressed_c`.

---

## 9. Проверить на устройстве

```bash
adb push eclipsoxide /data/local/tmp/
adb shell "su -c 'chmod +x /data/local/tmp/eclipsoxide && /data/local/tmp/eclipsoxide &'"
```

Лог: `/sdcard/Download/EclipsOxide/eclips_oxide_*.log`

Что искать:
```
[fast-seed] s_TypeInfoTable=0x???  meta_base=0x???        <- оба не 0
[fast-seed] PlayerManager: klass=0x??? (..., имя сверено)  <- УСПЕХ
[fast-seed] BuildingPiece: klass=0x??? (..., имя сверено)  <- УСПЕХ
```

Диагностика по симптомам:

| В логе | Значит | Что делать |
|---|---|---|
| `s_TypeInfoTable slot @ RVA ... = 0x0` | слот пустой или RVA неверный | пересчитать шаг 4 |
| `имя=''` при непустом klass | **взята таблица методов вместо классов** | см. 4.4 — нужен `+0x48` от ctx-глобала |
| self-heal обошёл все слоты и не нашёл | та же причина — таблица не та | см. 4.4 |
| `table[NNNN] = 0x0 (класс ещё не резолвен)` | TDI неверный ИЛИ класс не создан | зайти в матч; если не помогло — сработает self-heal |
| `[self-heal] НАЙДЕН на TDI NNNN (был MMMM)` | TDI съехал, автопочинка сработала | вписать найденный TDI в исходник |
| `[self-heal] не найден ни в одном слоте` | таблица не та или имя класса изменилось | пересчитать шаг 4, проверить имя в dump.cs |
| `имя='...' (не совпало)` | слот занят чужим классом | TDI неверный, ждать self-heal |
| `[LOS] building cache: valid=0/0` | стены не приходят на клиент | серверное поведение, оффсетами не лечится |

Self-heal (с версии 2026/07/24): если хардкод TDI промахнулся, чит
**сам просканирует** `s_TypeInfoTable` и найдёт слот по имени класса.
Работает автоматически, но найденный TDI лучше вписать в исходник —
скан выполняется один раз за запуск и стоит ~29k чтений.

---

## 10. Быстрый чеклист

```
[ ] Снял libil2cpp.so + global-metadata.dat с устройства
[ ] Проверил magic 0xfab11baf и version 39
[ ] Расшифровал header XOR 0xA5C3F19D, REC вышло 82
[ ] Нашёл TDI + byval для 9 классов
[ ] Нашёл 5 RVA-слотов через disasm кластера XOR-ключа
[ ] ПРОВЕРИЛ что взял таблицу КЛАССОВ, а не методов (раздел 4.4)
[ ] Сверил Il2CppClass layout (name 0x10, static_fields 0xB8)
[ ] Перегенерировал dump.cs / il2cpp.h / script.json
[ ] Сверил field-оффсеты по эталонной таблице
[ ] Вписал константы в oxide_offsets.h и main.cpp
[ ] Собрал ndk-build
[ ] Проверил лог: два "имя сверено"
```
