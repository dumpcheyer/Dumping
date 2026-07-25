# FULL FORK — рабочая версия, ESP подтверждён

Проверено на устройстве 2026/07/25. ESP отрисовывается, игра не вылетает,
watchdog не срабатывает.

Игровой билд: Oxide Survival Island (com.catsbit), апдейт 2026/07/24
- `libil2cpp.so` md5 `b3a79ff1dcd1f8d97ba237525440f90d` (200 561 288 байт)
- `global-metadata.dat` md5 `52208a1bbb506ab72936c04bfea63f08` (26 980 208 байт)

Бинарь этой ревизии: md5 `b3650c63271cd04f6b347cf0ff121ebb`, 3.5 МБ, arm64-v8a PIE.

---

## Резолв класса — рабочая цепочка

```
tbl   = read_ptr(il2cpp_base + 0xBF81040)   // s_TypeInfoDefinitionTable
klass = read_ptr(tbl + TDI * 8)             // TDI = TypeDefinitionIndex
name  = read_cstr(read_ptr(klass + 0x10))   // верификация по содержимому
```

Два указательных чтения на класс, оба внутри маппингов libil2cpp.
Никакого сканирования памяти игры — watchdog слепой.

### Почему предыдущая версия не работала

`0xBF80FF0` — это **`s_MethodInfoDefinitionTable`** (226 854 слота, индекс =
method index), а не таблица классов. В кластере MetadataCache две функции с
идентичной формой (XOR-ключ + `sdiv` + cache-write по индексу):

```
GetMethodInfoFromMethodDefinitionIndex  @0x4dff360  ->  0xBF80FF0   (226854)
Class::FromTypeDefinition               @0x4e0030c  ->  0xBF81040   (29486)
```

Pattern-скан сел на первую. Различить их можно только по полю заголовка,
которое они делят: методы читают `header[0xcc]/[0xd0]` (recsz 32), классы —
`header[0xe4]/[0xe8]` (recsz 82).

Однозначное доказательство из `MetadataCache::Initialize` @`0x4dff4f8`, где
обе таблицы аллоцируются подряд:

```
0x4dff5f8: ldr w8,[header,#0xe8]; eor KEY   ; 29486  = typeDefinitionsCount
0x4dff608: bl  alloc(count, 8)
0x4dff618: str x0, [0xBF81040]              ; s_TypeInfoDefinitionTable
0x4dff61c: ldr w8,[header,#0xd0]; eor KEY   ; 226854 = methodsCount
0x4dff62c: bl  alloc(count, 8)
0x4dff63c: str x0, [0xBF80FF0]              ; s_MethodInfoDefinitionTable
```

Симптом в логе, который это вскрыл: `klass+0x10` держал `0x7c25fa6d44` =
`base + 0x4b8ed44`, а по этому RVA в файле лежит `fe 4f bf a9` —
`stp x30, x19, [sp, #-0x10]!`, пролог функции. Читался `MethodInfo`.

### Мнемоника для следующего апдейта

```
s_TypeInfoDefinitionTable = <ctx global> + 0x48

old:  0xBE3BB10 + 0x48 = 0xBE3BB58
new:  0xBF80FF8 + 0x48 = 0xBF81040
```

Все metadata-глобалы между этими билдами сдвинулись одинаково на `+0x1454E8`.

---

## Константы

```
IL2CPP_TYPES_RVA            0xB77C750   (104776 entries)
s_TypeInfoDefinitionTable   0xBF81040   <- классы, индекс = TDI
s_MethodInfoDefinitionTable 0xBF80FF0   <- методы, НЕ ТРОГАТЬ
MetadataCache* / ctx        0xBF80FF8
metadata_base               0xBF81008
header ptr                  0xBF81010
stride                      0xBF8101C
XOR key                     0xA5C3F19D  (header [0x08, 0x17C))
typeDefinitionsCount        29486
STR table                   0xdbe2c
typeDefinitions offset      0x1523780   (record 82 байта)

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

Field-оффсеты (не менялись между двумя апдейтами):

```
PlayerManager    worldCameraRoot 0x68   mouseLook       0x70
                 raycastManager  0x88   vitals          0xC8
                 team (WNn)      0x120  characterModel  0x150
                 animator        0x190  lastTickPosition 0x1C8
                 lastSavedPos    0x1D4  playerFlags     0x250
                 userID          0x278  teamName        0x280
MouseLook        m_LookRoot      0x28   kqP (Vector2)   0x60
                   kqP.x = pitch град, kqP.y = yaw град
RaycastManager   player          0x20   m_WorldCamera   0x30
                 m_RayLength     0x38   m_AimRayLength  0x3C
BuildingPiece    m_Bounds        0xD0   m_Grade         0x190
                 health          0x380  maxHealth       0x384  id 0x38C
                 static: saveList +0x0 (HashSet), saveLookup +0x8 (Dictionary)
GenericVitals    m_MaxHealth     0x88
FPManager        kYl 0xA0   _kSQ 0xAC   kSP 0xB4
                   vFOV = kYl - kSP;  ADS если kYl < _kSQ * 0.90
Il2CppClass      image 0x00  name 0x10  namespace 0x18
                 parent 0x58  static_fields 0xB8
```

---

## Что внутри

**Резолв**
- Верификация klass по **содержимому** строки имени, не по адресу. Указатель
  может вести в metadata-блоб или в `.rodata` самой libil2cpp — не важно
- Self-heal: если хардкод TDI промахнулся, один раз сканирует таблицу
  (bulk по 4096 указателей) и ищет слот по имени + namespace
- Слот `0x0` = класс ещё не создан игрой, не ошибка. Retry каждые 3с

**Анти-watchdog**
- Ноль сканов анон-памяти игры. Все резолвы — точечные чтения по фиксированным
  RVA внутри libil2cpp
- Прошлая архитектура делала ~200 МБ `process_vm_readv` за 90с и игра падала

**ESP**
- Позиции через `PM.lastTickPosition` @ 0x1C8 (server-authoritative, работает
  для всех игроков, не только локального)
- Камера: базис из `MouseLook.kqP` (pitch/yaw в градусах, прямая тригонометрия),
  eye position из `worldCameraRoot` Transform с фолбэком на feet + eye height
- Живой vFOV из FPManager, ADS-aware
- Respawn detection: при смерти игра создаёт новый PlayerManager, старый
  указатель протухает — проверка через mouseLook/raycastManager non-null
- `ox_drawEspOverlay` — один общий рендер для боя и для превью в меню

**Меню**
- Трёхпанельная композиция: sidebar 170dp / LIVE PREVIEW 320dp / опции
- Click bar 168x36 в левом верхнем углу, тап открывает меню
- Live color picker (HSV), весь UI перекрашивается включая обводку click bar
- 17 встроенных PNG-ассетов, дизайн-токены, пружинные анимации,
  свайп-скролл с rubber-band, адаптивное качество по frame time

---

## Сборка

```bash
export NDK=/path/to/android-ndk-r27
cd FULL_FORK
$NDK/ndk-build -j$(nproc) NDK_PROJECT_PATH=$PWD \
    NDK_APPLICATION_MK=$PWD/Application.mk APP_BUILD_SCRIPT=$PWD/Android.mk
```

Нужны остальные модули из основной ветки `proj/`: `main.h`, `memory.cpp`,
`oxlog.cpp`, `LuaIntegration.cpp`, `utils.cpp`, `ImGui/`, `oxorany/`,
`Android_draw/`, `Android_touch/`, `lua/lua-5.4.7/`, `include/ox_assets.h`,
`include/ox_preview_dummy.h`, `include/ImGui/font/Font.h`.

## Запуск

```bash
adb push eclipsoxide /data/local/tmp/
adb shell "su -c 'chmod +x /data/local/tmp/eclipsoxide && /data/local/tmp/eclipsoxide &'"
```

Лог: `/sdcard/Download/EclipsOxide/eclips_oxide_*.log`

Признак что всё поднялось:
```
[fast-seed] PlayerManager: klass=0x??? (s_TypeInfoTable[8357], имя сверено)
[fast-seed] BuildingPiece: klass=0x??? (s_TypeInfoTable[8633], имя сверено)
```

## Обновление на новую версию игры

См. `UPDATE_GUIDE.md` — пошагово, со скриптами, включая раздел 4.4 про
ловушку с двумя одинаковыми функциями (именно на ней мы застряли).
