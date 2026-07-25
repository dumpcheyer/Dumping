# EclipsNormal — полный снимок проекта

Рабочее состояние на 2026/07/25. ESP подтверждён на устройстве.

Игровой билд: Oxide Survival Island (com.catsbit), апдейт 2026/07/24
- `libil2cpp.so` md5 `b3a79ff1dcd1f8d97ba237525440f90d`
- `global-metadata.dat` md5 `52208a1bbb506ab72936c04bfea63f08`

Бинарь: md5 `c82d7a8958535f99c237d6b9fd05ab08`, 3.5 МБ, arm64-v8a PIE.

---

## Что в папке

```
EclipsNormal/
├── src/
│   ├── main.cpp                  6406 строк — резолв, ESP, аим, меню
│   ├── menu_bg.cpp               загрузка встроенных PNG-ассетов
│   ├── memory.cpp                process_vm_readv обёртки
│   ├── utils.cpp                 строки/математика
│   ├── oxlog.cpp                 логгер в /sdcard/Download/EclipsOxide
│   ├── LuaIntegration.cpp        Lua 5.4 sandbox (posix_spawn, без shell)
│   ├── lua_all.cpp               амальгама Lua
│   ├── Android_draw/draw.cpp     EGL/GLES3 оверлей
│   ├── Android_touch/            инъекция тача
│   ├── oxorany/                  compile-time обфускация строк
│   ├── Vector2.h / Quaternion.h
├── include/
│   ├── oxide_offsets.h           ВСЕ константы игры
│   ├── main.h / memory.h / utils.h / oxlog.h / menu_bg.h
│   ├── LuaIntegration.h / Vector3.h
│   └── Android_draw/ Android_touch/
├── Android.mk / Application.mk
├── UPDATE_GUIDE.md               как обновляться на новую версию игры
└── README.md
```

Не вошло (берётся из основной ветки `proj/`, слишком объёмное для коммита):
`include/ImGui/`, `lua/lua-5.4.7/`, `include/ox_assets.h`, `include/ox_preview_dummy.h`,
`include/glass_ui_icons.h`, `include/Verdana.h`, `include/stb_image.h`,
`include/ImGui/font/Font.h`, `include/oxide_rva.h`.

---

## Резолв класса

```
tbl   = read_ptr(il2cpp_base + 0xBF81040)   // s_TypeInfoDefinitionTable
klass = read_ptr(tbl + TDI * 8)
name  = read_cstr(read_ptr(klass + 0x10))   // верификация по содержимому
```

Два указательных чтения на класс, оба внутри маппингов libil2cpp.
Сканов памяти игры нет — watchdog не срабатывает.

`0xBF80FF0` — это `s_MethodInfoDefinitionTable` (226854 слота, индекс = method
index), НЕ таблица классов. Обе функции-аксессора имеют одинаковую форму
(XOR-ключ + sdiv + cache-write), поэтому pattern-скан садится не на ту.
Подробности и способ различить — в `UPDATE_GUIDE.md`, раздел 4.4.

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

Field-оффсеты (не менялись между двумя апдейтами подряд):

```
PlayerManager    worldCameraRoot 0x68   mouseLook        0x70
                 raycastManager  0x88   fpManager        0x90
                 kccReference    0xB0   vitals           0xC8
                 team (WNn)      0x120  characterModel   0x150
                 animator        0x190  lastTickPosition 0x1C8
                 lastSavedPos    0x1D4  playerFlags      0x250
                 userID          0x278  teamName         0x280
MouseLook        m_LookRoot      0x28   kqP (Vector2)    0x60
                   kqP.x = pitch град, kqP.y = yaw град
RaycastManager   player          0x20   m_WorldCamera    0x30
                 m_RayLength     0x38   m_AimRayLength   0x3C
BuildingPiece    m_Bounds        0xD0   m_Grade          0x190
                 health          0x380  maxHealth        0x384   id 0x38C
                 static: saveList +0x0 (HashSet), saveLookup +0x8 (Dictionary)
GenericVitals    m_MaxHealth     0x88
FPManager        kYl 0xA0   _kSQ 0xAC   kSP 0xB4
                   vFOV = kYl - kSP;  ADS если kYl < _kSQ * 0.90
KCC              player 0x78   head 0x88   faM 0x108 (CharacterAnimation)
PlayerModelInfo  head 0x20   rightWeaponHolder 0x28
                 leftWeaponHolder 0x30   body 0x40   characterAnimation 0x60
CharacterAnim    playerModelInfo 0x30    ragdoll 0x38
pf (команда)     mYs 0x10 (teamId)  mYo 0x18 (name)  mYK 0x20 (List<TeamMember>)
TeamMember       id 0x10 (== PM.userID)  clanTag 0x18  nick 0x20  lvl 0x28
Il2CppClass      image 0x00  name 0x10  namespace 0x18
                 parent 0x58  static_fields 0xB8
```

---

## Ключевые фиксы этой ревизии

**Респавн: ESP уезжал за камерой.**
Симптом: после смерти боксы держатся верно пока не двигаешь камеру, при
повороте остаются на месте экрана. Причина — читали `kqP` у мёртвого
MouseLook: игра пишет углы в НОВЫЙ объект, старый застывает. Статически
труп неотличим (указатели валидны, углы конечны), поэтому детект сделан
по ДИНАМИКЕ: следим меняются ли углы между кадрами, порог 1e-4 градуса.
Не менялись дольше 2.5 с — объект мёртвый. Плюс выбор локального игрока
теперь идёт по свежести среди всех кандидатов (после респавна их два —
труп и новый), и страховка в рендере: базис заморожен дольше 3 с и замены
нет — ESP не рисуется вообще.

Второй слой: в `ox_buildCameraFromPlayer` стояло безусловное
`cam.valid = true` даже без собранного базиса — рендер получал
identity-forward `(0,0,1)`. Теперь `cam.valid = haveDir`.

**Вертикальная привязка бокса.**
`lastTickPosition` — не позиция ног, pivot контроллера выше. Статически
уровень не определить, поэтому вынесено в слайдер
`ESP -> BOX -> Vertical offset`, дефолт `-1.84`. Привязка применяется
единообразно: 2D-бокс, 3D-бокс, LOS-лучи, точки аима.

**Скелет по реальным костям.**
`PM.kccReference (0xB0)` -> `KCC.head (0x88)` для головы,
`KCC.faM (0x108)` -> `CharacterAnimation` -> `PlayerModelInfo (0x30)` ->
`head/body/rightWeaponHolder/leftWeaponHolder`. Читаем 4 реальные кости,
остальные 11 суставов достраиваем интерполяцией — ~10 vm_readv на игрока
вместо ~45. Валидация: голова в 0.4..2.6 м над ногами, не дальше 1.5 м
по горизонтали. Рисуется только при включённом тумблере и дистанции < 220 м.

**Скрытие тимейтов.**
Было две проблемы: `g_localTeamName` брался только при смене локального PM,
а команда собирается уже в матче (кэшировалась пустая строка навсегда);
и строковые team-поля часто пусты у обоих. Теперь ключ обновляется каждый
резолв камеры, плюс прямая проверка по составу:
`WNn -> pf -> List<TeamMember> -> TeamMember.id == PM.userID`.
Работает и в ESP, и в аиме.

**Диагностика ADS и wall check.**
`[ads]` раз в 2 с печатает `kYl / kSP / base / ratio / aiming` — видно
срабатывает ли порог `kYl < base * 0.90`.
`[LOS]` при пустом кэше печатает сырое состояние контейнеров
(`saveList` count/lastIdx/slots, `saveLookup`) — это разделяет
«не тот layout HashSet» и «сервер не присылает постройки клиенту».

---

## Сборка

```bash
export NDK=/path/to/android-ndk-r27
cd proj
$NDK/ndk-build -j$(nproc) NDK_PROJECT_PATH=$PWD \
    NDK_APPLICATION_MK=$PWD/Application.mk APP_BUILD_SCRIPT=$PWD/Android.mk
```

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
