# DESIGN_V2 — полный редизайн меню

Меню Eclips Oxide NEW переписано с нуля по референсу (трёхпанельная композиция).
Работу вели 6 субагентов в 4 волны. Игровая логика не тронута вообще.

## Композиция

Одно окно, три колонки под breadcrumb-шапкой:

```
+--------------------------------------------------------------+
|  ESP / LIVE                                                  |
|  Realtime overlay preview                                    |
+-----------+---------------------+----------------------------+
| [mark]    | +- LIVE PREVIEW -+  |  ENTITY OVERLAYS           |
| ECLIPS    | |                |  |  ----------------          |
| OXIDE NEW | |  [model + ESP  |  |  Corner boxes        [on]  |
| -----     | |   overlay]     |  |  Skeleton ESP        [on]  |
|           | |                |  |  Health bar          [on]  |
| > ESP     | |                |  |                            |
|   Aim     | | 42 m  VISIBLE  |  |  DISPLAY                   |
|   Camera  | +----------------+  |  ----------------          |
|   Settings|                     |  [====] 120 m   Max range  |
| -----     |                     |  [====]   1 %   Overlay    |
| STATUS    |                     |                            |
| Resolved  |                     |                            |
| 3 enemies |                     |                            |
+-----------+---------------------+----------------------------+
```

Ландшафт: sidebar 188dp | preview 280dp | options (остаток).
Портрет: bottom tab bar, preview полной шириной сверху вкладки ESP.

## Волна 1 — фундамент

### Ассеты (include/ox_assets.h, 20 945 байт)
17 ассетов, все 96x96 RGBA белый line-art кроме брендинга и текстуры:
eye, crosshair, lens, gear, shield, heart, ruler, skeleton, cube, palette,
lock, bolt, flag, marker, target, brand_mark (240x240), tex_grain (128x128,
GL_REPEAT, сгенерён процедурно для настоящей бесшовности).

Прирост бинаря +14 КБ (старый glass_ui_icons.h выпал из сборки).

### Дизайн-токены (oxui::Tokens, глобал g_tk)
- Поверхности: bgDeep / bgBase / bgRaised (HSV-тонированы под акцент)
- Панели: panel0..panel3 (alpha 8/12/22/34)
- Обводки: strokeSoft / strokeBase / strokeStrong
- Текст: textHi / textBase / textDim / textFaint / textOnAccent
- Акцент: accent / accentHi / accentGlow / accentPress
- Семантика: good / warn / danger / info
- Типографика: fsDisplay 1.35 / fsHeading 0.95 / fsBody 0.72 / fsLabel 0.62 /
  fsCaption 0.50 / fsMicro 0.42 (от rem = FontSize * 0.75 * uiScale)
- Spacing: sp1=4 sp2=8 sp3=12 sp4=16 sp5=24 sp6=32 dp
- Радиусы: rSm=8 rMd=12 rLg=16 rXl=22 dp + RPill(h)
- Elevation: elev1 {blur 8, a .30} / elev2 {14, .42} / elev3 {22, .55}
- Motion: mFast 16.7 / mBase 8.3 / mSlow 5.0 / springSoft 10 / springSnappy 18
- Hit targets: hitMin 44dp / rowH 52dp

Вывод акцента через HSV: accentHi = H, S*0.82, V += (1-V)*0.60;
accentPress = V*0.78; textOnAccent по WCAG-яркости (порог L 0.1925).
Всё пересчитывается каждый кадр — color picker меняет и фон, и панели.

## Волна 2 — композиция

- Превью сложено внутрь основного окна: oxDrawEspPreviewPane(dl, a, b)
  вместо отдельного ImGui-окна. Рендер ESP идёт через общий
  ox_drawEspOverlay() — тот же код что в бою, 1:1
- Sidebar: brand mark + wordmark, 4 nav-строки с иконками, активная —
  заполненная плашка + 3dp акцентная кромка слева, снизу блок STATUS
  (klass resolved / enemy count / FPS — чтение существующих глобалов)
- Breadcrumb-шапка на всю ширину, hairline-разделители между колонками
- Options — единственная скроллящаяся область

## Волна 3 — моторика

- AnimAsym(id, target, rateIn, rateOut) — быстрый вход, медленный выход
- Spring(id, target, stiffness, damping): omega 32 rad/s, zeta 0.68 —
  один овершут ~5.4%, settle ~180ms. Semi-implicit Euler, substep <=8ms,
  damping через expf(-damping*h) — независимо от FPS
- Toggle: knob на spring, трек крос-фейдит медленнее (rate 12.5) — читается
  физично, не в унисон
- Slider: drag 1:1 без сглаживания, glow гаснет 200ms, knob растёт на драге
- Переходы вкладок: направленный слайд 12dp по направлению навигации +
  каскад секций (+40ms на секцию, первые 3), общий бюджет 220ms
- Скролл: rubber-band 48dp с прогрессивным сопротивлением
  (over += excess / (1 + |over|/24dp)), кламп fling-скорости,
  edge-fade маски сверху/снизу
- Click bar: пульс из двух синусов (0.7 Hz * 0.62 + 1.1 Hz * 0.38),
  press attack 45ms / release 260ms, шеврон вращается через угол
- Все инкременты переведены на dt, dt клампится 50ms

## Волна 4 — оптимизация

Замеры (2400x1080 landscape, ImGui 1.90.1):

| Сцена | Вершины до | после | дельта |
|---|---|---|---|
| меню закрыто | 1876 | 1772 | -6% |
| ESP tab | 11736 | 6508 | -45% |
| Settings tab | 8308 | 6496 | -22% |

Texture binds 21 -> 18. Draw cmds -3 на обеих открытых сценах.

Что сделано:
- CalcTextSizeCached — кэш размеров статичных строк в ImGuiStorage,
  ключ = hash(ptr) ^ hash(font size)
- oxorany hoisted: ~128 вызовов за кадр -> static const char* через
  ox_persist() (strdup один раз). Строки байт-идентичны, ID не поехали
- IsRectVisible early-out внутри всех виджетов — off-screen строки не
  эмитят геометрию (layout-резервирование остаётся, скролл не ломается)
- SoftShadow 7 -> 6 слоёв (7-й был alpha 0.02, невидим)
- Схлопнут двойной rounded-rect в preview pane в один pre-composited fill
- Nav-циклы переупорядочены: сначала все иконки, потом все подписи —
  текстовые дро merge'атся в одну команду
- Адаптивное качество ox_uiQuality() 0/1/2 по EMA frame time:
  q0->q1 при >22ms, q1->q2 при >33ms, откат при <27ms / <17ms
  (dead-band 5ms против осцилляции). Режет только количество слоёв
  glow/shadow/aura, grain, subdivisions сетки. Layout не трогает,
  виджеты не скрывает
- Опциональный perf-HUD по env OX_UI_PERF_HUD=1, по умолчанию выключен

Рекомендация на будущее: texture atlas. 18 binds на 10 текстур —
упаковка иконок в один атлас срежет до 3-4.

## Что НЕ тронуто

Оффсеты, RVA, TDI, s_TypeInfoTable, fast-seed, LOS, aimbot, player-cache,
ox_drawEspOverlay, все игровые глобалы (esp*, aim*, cam*, g_cacheInterval,
g_positionInterval, main_thread_flag). Ни один диапазон слайдера, ни один
дефолт тумблера, ни один набор вкладок не изменён.

## Сборка

```bash
export NDK=/path/to/android-ndk-r27
cd DESIGN_V2
$NDK/ndk-build -j$(nproc) NDK_PROJECT_PATH=$PWD \
    NDK_APPLICATION_MK=$PWD/Application.mk APP_BUILD_SCRIPT=$PWD/Android.mk
```

Нужны остальные модули из основной ветки proj/: main.h, memory.cpp, oxlog.cpp,
LuaIntegration.cpp, utils.cpp, ImGui/, oxorany/, Android_draw/, Android_touch/,
lua/lua-5.4.7/, include/glass_ui_icons.h (legacy), include/ox_assets.h,
include/ox_preview_dummy.h, include/ImGui/font/Font.h.

Полная чистая сборка (ndk-build -B) проходит, ноль warning'ов из нашего кода.
