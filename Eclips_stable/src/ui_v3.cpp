// ============================================================================
//  ui_v3.cpp — меню "Eclips Oxide", построенное с нуля от физики устройства.
//
//  МЕТОДИКА. Размеры не подбирались на глаз — они выведены из измерений:
//
//    экран      2400 x 1080 (из лога устройства), ~6.7", ≈395 ppi
//    1 мм       = 15.5 px
//    палец      подушечка большого ≈ 11 мм; минимальная надёжная цель 7 мм;
//               комфортная 9 мм; зазор между целями от 2 мм
//    дуга       большого пальца ≈ 75 мм = 1162 px от нижнего угла, поэтому
//               центр экрана (1162..1238 по X) в ландшафте достаётся только
//               указательным — туда нельзя класть частые действия
//
//  СЛЕДСТВИЯ, которые и определили эту раскладку:
//
//    * строка контрола 8 мм — выше минимума 7 мм, но не раздута
//    * ВЫСОТА ПАНЕЛИ ВЫВЕДЕНА ИЗ СТРОКИ, а не задана процентом. Панель = шапка
//      8 мм + ровно 5 строк + поля. Получается ≈82% высоты. Если задать высоту
//      произвольно (как делало прошлое меню), снизу остаётся мёртвая полоса в
//      пару сантиметров — это было видно на пробном рендере раскладки
//    * контролы идут В ДВЕ КОЛОНКИ: в ландшафте по горизонтали места вдвое
//      больше, чем требуется, а по вертикали его нет. 5 строк x 2 = 10
//      контролов видно разом, без скролла
//    * навигация — вертикальный рельс 14 мм слева, у самой кромки: это зона
//      левого большого пальца, попадание без промаха и без перекрытия центра
//    * клик-бар — квадрат 11 мм в левом верхнем углу, без текста: подпись на
//      таком размере всё равно нечитаема, а знак опознаётся мгновенно
//
//  МАТЕРИАЛ. Настоящего backdrop-blur в ImGui нет — кадр под окном недоступен.
//  Стекло собирается слоями, каждый отвечает за отдельный физический эффект:
//  ореол, подложка, свет сверху, цветная дымка, зерно, кромка преломления.
//  Все цветные слои читают один акцент, поэтому подсветка меняет весь
//  материал разом.
// ============================================================================

#include <cmath>
#include <cstdio>
#include <cstring>
#include <ctime>

#include "imgui.h"
#include "imgui_internal.h"

// ── Мост к состоянию чита (объявлено в main.cpp) ────────────────────────────
extern bool  espdraw, espbox, espfill, esphealth, espname, espweapon, espdist;
extern bool  ESP3D, esplines_enabled, espCornerBox, espgradient, esphpgradient;
extern bool  espModelAnchor, espMatrixW2S, espDistColor, espArmor, espFlags, espHpNumber;
extern bool  radarEnabled;
extern bool  aimm, aimDrawFov, aimPrediction, aimvisible, aimOnlyADS;
extern float espboxcolor[3], esplines_color[3];
extern float espstroke, espfillp, esphpsize, espCornerLength, espMaxDistance;
extern float esplines_thickness, espBoxYOffset;
extern float aimFovPixels, aimSmooth, aimMaxDistance;
extern float aimProjectileSpeed, aimLatencyMs, aimMaxLeadTime;
extern float radarRange, radarSize, radarPos[2], radarAlpha;
extern float glowIntensity;
extern int   aimcurbone, esplines_position;
extern int   g_cacheInterval, g_positionInterval;
extern bool  g_menuOpen;
extern float g_uiScale;

extern ImTextureID g_iconTexEye, g_iconTexTarget, g_iconTexGear, g_iconTexPalette;
extern ImTextureID g_iconTexMarker, g_texBrandMark, g_texGrain;
extern ImTextureID g_texMenuArt;    extern int g_texMenuArtW, g_texMenuArtH;
extern ImTextureID g_texPreviewFig; extern int g_texPreviewFigW, g_texPreviewFigH;

extern void oxLoadIcons();

namespace uiv3 {

// ── Физические константы устройства ─────────────────────────────────────────
// Базис: 2400x1080 @ ~395 ppi. На других экранах всё масштабируется через
// коэффициент, вычисленный из фактической высоты вьюпорта, поэтому реальный
// размер в миллиметрах сохраняется.
static constexpr float kRefH   = 1080.0f;   // высота, под которую считано
static constexpr float kPxPerMm = 15.5f;    // при этой высоте

static float g_k = 1.0f;                    // масштаб под текущий экран
static inline float MM(float v) { return v * kPxPerMm * g_k; }

// ── Палитра ─────────────────────────────────────────────────────────────────
struct Theme {
    ImU32 accent, accentHi, accentDim;
    ImU32 text, textDim, textFaint;
    ImU32 glass, stroke, strokeHi;
};
static Theme T;

static ImU32 Mix(ImU32 a, ImU32 b, float t) {
    int ar= a     &0xFF, ag=(a>> 8)&0xFF, ab=(a>>16)&0xFF, aa=(a>>24)&0xFF;
    int br= b     &0xFF, bg=(b>> 8)&0xFF, bb=(b>>16)&0xFF, ba=(b>>24)&0xFF;
    return IM_COL32(int(ar+(br-ar)*t), int(ag+(bg-ag)*t),
                    int(ab+(bb-ab)*t), int(aa+(ba-aa)*t));
}
static ImU32 Alpha(ImU32 c, float a) {
    int v = int(((c>>24)&0xFF) * a);
    if (v < 0) v = 0; if (v > 255) v = 255;
    return (c & 0x00FFFFFF) | ((ImU32)v << 24);
}

// Пресеты подсветки. Названия — для человека, не для рендера.
struct Preset { const char* name; ImU32 lo, hi; };
static const Preset kPresets[] = {
    // Зелёный первым и по умолчанию. Пара тонов подобрана так, чтобы hi был
    // заметно светлее и чуть желтее — тогда свечение читается как свет, а не
    // как плоская заливка тем же цветом.
    { "GREEN",  IM_COL32( 46,222,118,255), IM_COL32(150,255,186,255) },
    { "CYAN",   IM_COL32(  0,214,232,255), IM_COL32(120,240,255,255) },
    { "VIOLET", IM_COL32(124, 77,255,255), IM_COL32(168,130,255,255) },
    { "AMBER",  IM_COL32(255,168, 40,255), IM_COL32(255,206,120,255) },
    { "ROSE",   IM_COL32(255, 72,132,255), IM_COL32(255,150,190,255) },
};
static constexpr int kPresetCount = (int)(sizeof(kPresets)/sizeof(kPresets[0]));

// Настройки фонового арта. Пользователь может приглушить или усилить как сам
// арт, так и цветную подсветку поверх него.
static float g_artOpacity = 0.55f;   // видимость арта
static float g_artTint    = 0.35f;   // окраска арта в цвет подсветки
static bool  g_artEnabled = true;
static bool  g_artAnimate = true;    // медленный дрейф + дыхание масштаба
static float g_artAnimAmount = 1.0f; // сила движения

static int   g_preset = 0;
static float g_custom[3] = { 0.180f, 0.871f, 0.463f };  // тот же зелёный
static bool  g_useCustom = false;

static void BuildTheme() {
    if (g_useCustom) {
        T.accent   = IM_COL32(int(g_custom[0]*255), int(g_custom[1]*255), int(g_custom[2]*255), 255);
        T.accentHi = Mix(T.accent, IM_COL32(255,255,255,255), 0.34f);
    } else {
        int i = g_preset < 0 ? 0 : (g_preset >= kPresetCount ? kPresetCount-1 : g_preset);
        T.accent   = kPresets[i].lo;
        T.accentHi = kPresets[i].hi;
    }
    T.accentDim = Alpha(T.accent, 0.28f);
    T.text      = IM_COL32(240,240,248,255);
    T.textDim   = IM_COL32(150,152,168,255);
    T.textFaint = IM_COL32(102,104,120,255);
    T.glass     = IM_COL32( 13, 13, 22,236);
    T.stroke    = IM_COL32(255,255,255, 22);
    T.strokeHi  = IM_COL32(255,255,255, 52);
}

// ── Анимация ────────────────────────────────────────────────────────────────
static float Approach(float cur, float tgt, float rate, float dt) {
    float t = 1.0f - expf(-rate * dt);
    return cur + (tgt - cur) * t;
}
static float Spring(ImGuiID id, float target, float rate) {
    ImGuiStorage* st = ImGui::GetStateStorage();
    float v = st->GetFloat(id, target);
    v = Approach(v, target, rate, ImGui::GetIO().DeltaTime);
    st->SetFloat(id, v);
    return v;
}
static float EaseOut(float t) { float u = 1.0f - t; return 1.0f - u*u*u; }

// Градиентная заливка ПО СКРУГЛЁННОЙ форме.
//
// ImGui::AddRectFilledMultiColor радиуса НЕ ПРИНИМАЕТ — она всегда рисует
// острый прямоугольник. Накладываясь на скруглённую подложку, её углы
// выпирают за скругление, и панель выглядит так, будто углы срезаны. Именно
// это и было видно как «обрезанные углы».
//
// Здесь строим скруглённый путь, а затем красим ЕГО вершины вертикальным
// градиентом. PathFillConvex кладёт вершины в буфер — после вызова проходим
// по свежедобавленным и присваиваем каждой цвет по её高 позиции.
static void GradRounded(ImDrawList* dl, ImVec2 a, ImVec2 b, float r,
                        ImU32 top, ImU32 bot) {
    int v0 = dl->VtxBuffer.Size;
    dl->PathRect(a, b, r);
    dl->PathFillConvex(IM_COL32_WHITE);
    int v1 = dl->VtxBuffer.Size;
    float h = b.y - a.y;
    if (h < 0.001f) return;

    int tr= top     &0xFF, tg=(top>> 8)&0xFF, tb=(top>>16)&0xFF, ta=(top>>24)&0xFF;
    int br= bot     &0xFF, bg=(bot>> 8)&0xFF, bb=(bot>>16)&0xFF, ba=(bot>>24)&0xFF;
    for (int i = v0; i < v1; ++i) {
        ImDrawVert& v = dl->VtxBuffer[i];
        float t = (v.pos.y - a.y) / h;
        t = t < 0.f ? 0.f : (t > 1.f ? 1.f : t);
        v.col = IM_COL32(int(tr+(br-tr)*t), int(tg+(bg-tg)*t),
                         int(tb+(bb-tb)*t), int(ta+(ba-ta)*t));
    }
}

// То же, но градиент по ДИАГОНАЛИ (из верхнего-левого угла). Для цветной
// дымки: свет у нас всегда исходит оттуда, где стоит брендовая метка.
static void GradRoundedDiag(ImDrawList* dl, ImVec2 a, ImVec2 b, float r,
                            ImU32 near_, ImU32 far_) {
    int v0 = dl->VtxBuffer.Size;
    dl->PathRect(a, b, r);
    dl->PathFillConvex(IM_COL32_WHITE);
    int v1 = dl->VtxBuffer.Size;
    float w = b.x - a.x, h = b.y - a.y;
    if (w < 0.001f || h < 0.001f) return;

    int nr= near_     &0xFF, ng=(near_>> 8)&0xFF, nb=(near_>>16)&0xFF, na=(near_>>24)&0xFF;
    int fr= far_      &0xFF, fg=(far_ >> 8)&0xFF, fb=(far_ >>16)&0xFF, fa=(far_ >>24)&0xFF;
    for (int i = v0; i < v1; ++i) {
        ImDrawVert& v = dl->VtxBuffer[i];
        float t = (((v.pos.x - a.x) / w) + ((v.pos.y - a.y) / h)) * 0.5f;
        t = t < 0.f ? 0.f : (t > 1.f ? 1.f : t);
        v.col = IM_COL32(int(nr+(fr-nr)*t), int(ng+(fg-ng)*t),
                         int(nb+(fb-nb)*t), int(na+(fa-na)*t));
    }
}

// ── Стеклянная поверхность ──────────────────────────────────────────────────
// Семь слоёв. Порядок важен: каждый следующий читается поверх предыдущего,
// а свет всегда идёт из верхнего-левого угла — оттуда же, где брендовая метка.
static void Glass(ImDrawList* dl, ImVec2 a, ImVec2 b, float r,
                  float haloScale = 1.0f, bool drawHalo = true, bool withArt = false) {
    ImVec2 sz(b.x - a.x, b.y - a.y);

    if (drawHalo && glowIntensity > 0.01f) {
        float t = (float)ImGui::GetTime();
        float breath = 0.5f + 0.5f * sinf(t * 1.15f);
        // Радиус колец растёт ВМЕСТЕ со смещением (r + ex), иначе внешние
        // кольца получаются «квадратнее» внутренних и на углах вылезают
        // ступеньки. Сегментацию тоже наращиваем: у большего радиуса при
        // дефолтном числе сегментов грани видны как фаски.
        for (int i = 6; i >= 1; --i) {
            float f = (float)i / 6.0f;
            float ex = (MM(0.4f) + f * MM(2.6f)) * haloScale;
            float al = (1.0f - f*0.86f) * (0.058f + 0.022f*breath) * glowIntensity;
            dl->PathRect(ImVec2(a.x-ex, a.y-ex), ImVec2(b.x+ex, b.y+ex), r + ex);
            dl->PathFillConvex(Alpha(T.accentHi, al));
        }
    }

    dl->AddRectFilled(a, b, T.glass, r);                       // подложка

    // Фоновый арт под стеклом. Cover-fit: масштабируем по той стороне, где
    // не хватает, и обрезаем по UV — иначе картинка растянется.
    if (withArt && g_artEnabled && g_texMenuArt && g_texMenuArtW > 0 && g_texMenuArtH > 0
        && g_artOpacity > 0.01f) {
        float pr = sz.x / sz.y;
        float ir = (float)g_texMenuArtW / (float)g_texMenuArtH;
        ImVec2 uv0(0,0), uv1(1,1);
        if (ir > pr) { float t = (pr/ir)*0.5f; uv0.x = 0.5f-t; uv1.x = 0.5f+t; }
        else         { float t = (ir/pr)*0.5f; uv0.y = 0.5f-t; uv1.y = 0.5f+t; }

        // ── ЖИВОЙ ФОН ──────────────────────────────────────────────────────
        // Медленный дрейф UV плюс лёгкое «дыхание» масштаба. Двигаем ОКНО
        // выборки, а не саму картинку: изображение не выходит за края панели,
        // швов не появляется, лишних draw-call нет — тот же один AddImage.
        //
        // Два несинхронных синуса на осях (0.037 и 0.029 Гц) дают траекторию
        // Лиссажу: движение не зацикливается на глаз и не выглядит маятником.
        if (g_artAnimate) {
            float t = (float)ImGui::GetTime();
            float uw = uv1.x - uv0.x, uh = uv1.y - uv0.y;

            // Запас на сдвиг: сколько UV осталось за кадром с каждой стороны.
            float slackX = (1.0f - uw) * 0.5f;
            float slackY = (1.0f - uh) * 0.5f;
            // Если картинка ровно по кадру, запаса нет — берём его из зума.
            float zoom = 1.0f + 0.045f * g_artAnimAmount
                       + 0.018f * g_artAnimAmount * sinf(t * 0.21f);
            float cu = (uv0.x + uv1.x) * 0.5f, cv = (uv0.y + uv1.y) * 0.5f;
            uw /= zoom; uh /= zoom;
            slackX = (1.0f - uw) * 0.5f;
            slackY = (1.0f - uh) * 0.5f;

            float dx = sinf(t * 0.2325f) * slackX * 0.75f * g_artAnimAmount;
            float dy = sinf(t * 0.1822f + 1.3f) * slackY * 0.75f * g_artAnimAmount;

            uv0 = ImVec2(cu - uw*0.5f + dx, cv - uh*0.5f + dy);
            uv1 = ImVec2(cu + uw*0.5f + dx, cv + uh*0.5f + dy);
            // Страховка от выхода за текстуру (иначе CLAMP размажет кромку).
            if (uv0.x < 0.f) { uv1.x -= uv0.x; uv0.x = 0.f; }
            if (uv0.y < 0.f) { uv1.y -= uv0.y; uv0.y = 0.f; }
            if (uv1.x > 1.f) { uv0.x -= (uv1.x - 1.f); uv1.x = 1.f; }
            if (uv1.y > 1.f) { uv0.y -= (uv1.y - 1.f); uv1.y = 1.f; }
        }

        int av = (int)(255.f * g_artOpacity);
        dl->AddImageRounded(g_texMenuArt, a, b, uv0, uv1,
                            IM_COL32(255,255,255,av), r);
        // Окраска арта в цвет подсветки — арт вливается в тему, а не спорит с ней.
        if (g_artTint > 0.01f) {
            int cr= T.accent     &0xFF, cg=(T.accent>>8)&0xFF, cb=(T.accent>>16)&0xFF;
            dl->AddRectFilled(a, b, IM_COL32(cr,cg,cb,(int)(70.f*g_artTint)), r);
        }
        // Затемнение обратно к подложке, чтобы текст оставался читаемым.
        dl->AddRectFilled(a, b, IM_COL32(13,13,22,(int)(150.f*g_artOpacity)), r);

        // Второй слой движения: световая полоса, медленно проходящая слева
        // направо. Рисуется как вертикальные ленты с колоколообразной
        // яркостью — вместе они читаются как мягкий блик по стеклу, а не как
        // резкая полоска. Одна текстура не нужна, всё на заливках.
        if (g_artAnimate && g_artAnimAmount > 0.01f) {
            float t = (float)ImGui::GetTime();
            float cyc = fmodf(t * 0.085f, 1.6f);      // пауза между проходами
            if (cyc < 1.0f) {
                float head = -0.25f + cyc * 1.5f;      // центр блика в долях
                const int BANDS = 16;
                float bw = sz.x / (float)BANDS;
                for (int i = 0; i < BANDS; ++i) {
                    float u = (i + 0.5f) / (float)BANDS;
                    float d = (u - head) / 0.16f;
                    float k = expf(-d*d);              // колокол
                    if (k < 0.02f) continue;
                    int al = (int)(26.f * k * g_artAnimAmount);
                    if (al <= 0) continue;
                    // Клипуем по скруглению: крайние ленты подрезаем внутрь,
                    // иначе блик выступает за углы панели.
                    float x0 = a.x + bw*i, x1 = x0 + bw;
                    float inset = 0.f;
                    if (x0 < a.x + r) inset = r - (x0 - a.x);
                    if (x1 > b.x - r) inset = r - (b.x - x1);
                    if (inset < 0.f) inset = 0.f;
                    dl->AddRectFilled(ImVec2(x0, a.y + inset*0.5f),
                                      ImVec2(x1, b.y - inset*0.5f),
                                      IM_COL32(255,255,255,al), 0.f);
                }
            }
        }
    }

    // Свет сверху — по скруглённой форме, иначе его острые углы вылезают
    // за скругление подложки (это и читалось как «обрезанные углы»).
    GradRounded(dl, a, ImVec2(b.x, a.y + sz.y*0.60f), r,
                IM_COL32(255,255,255,22), IM_COL32(255,255,255,0));

    {                                                          // цветная дымка
        int cr= T.accentHi     &0xFF, cg=(T.accentHi>>8)&0xFF, cb=(T.accentHi>>16)&0xFF;
        int h = (int)(34.f * glowIntensity); if (h > 92) h = 92;
        GradRoundedDiag(dl, a, b, r,
                        IM_COL32(cr,cg,cb,h), IM_COL32(cr,cg,cb,0));
    }

    if (g_texGrain)                                            // матовость
        dl->AddImageRounded(g_texGrain, a, b, ImVec2(0,0),
            ImVec2(sz.x / MM(6.2f), sz.y / MM(6.2f)),
            IM_COL32(255,255,255,12), r);

    dl->AddRect(a, b, Alpha(T.accent, 0.50f), r, 0, MM(0.10f)); // контур

    // Кромка преломления. Раньше она обрывалась ровно посреди верхнего-правого
    // угла — прямая упиралась в начало скругления и заканчивалась «обрубком».
    // Именно это читалось как мусор на углах. Теперь световая линия проходит
    // ПОЛНЫЙ путь: левый нижний -> левый верхний угол -> верх -> правый верхний
    // угол -> вниз, и на концах гаснет, а не отрезается.
    {
        // Число сегментов ОТ РАДИУСА, а не фиксированное. При жёстких 14 дуга
        // радиуса 42 px разбивалась на грани по 4.7 px — углы получались
        // гранёными, и это читалось как «рубленые». Держим шаг ~1.5 px.
        int SEG = (int)(1.5708f * r / 1.5f);
        if (SEG < 8)  SEG = 8;
        if (SEG > 48) SEG = 48;
        const float w2 = MM(0.09f);
        // Верхняя дуга левого угла + верхняя грань + дуга правого угла.
        dl->PathArcTo(ImVec2(a.x + r, a.y + r), r, IM_PI * 0.86f, IM_PI * 1.5f, SEG);
        dl->PathArcTo(ImVec2(b.x - r, a.y + r), r, IM_PI * 1.5f, IM_PI * 1.64f, SEG);
        dl->PathStroke(T.strokeHi, 0, w2);

        // Затухающие хвосты: короткие отрезки с падающей альфой вместо резкого
        // обрыва линии. Глаз читает это как плавный сход блика, а не как дефект.
        const int TAIL = 5;
        for (int i = 0; i < TAIL; ++i) {
            float t0 = (float)i / TAIL, t1 = (float)(i + 1) / TAIL;
            float al = (1.0f - t0) * 0.42f;
            // левый хвост вниз по левой грани
            float aStart = IM_PI * 0.86f, aEnd = IM_PI * 0.62f;
            float A0 = aStart + (aEnd - aStart) * t0;
            float A1 = aStart + (aEnd - aStart) * t1;
            dl->AddLine(ImVec2(a.x + r + cosf(A0)*r, a.y + r + sinf(A0)*r),
                        ImVec2(a.x + r + cosf(A1)*r, a.y + r + sinf(A1)*r),
                        Alpha(T.strokeHi, al), w2);
            // правый хвост вниз по правой грани
            float bStart = IM_PI * 1.64f, bEnd = IM_PI * 1.88f;
            float B0 = bStart + (bEnd - bStart) * t0;
            float B1 = bStart + (bEnd - bStart) * t1;
            dl->AddLine(ImVec2(b.x - r + cosf(B0)*r, a.y + r + sinf(B0)*r),
                        ImVec2(b.x - r + cosf(B1)*r, a.y + r + sinf(B1)*r),
                        Alpha(T.strokeHi, al), w2);
        }
    }
}

// ── Контролы ────────────────────────────────────────────────────────────────
// Каждый занимает ровно ROW по высоте. Вся зона строки кликабельна, а не
// только сам виджет: на 8.5 мм промахнуться по маленькой мишени слишком легко.

static float ROW, GAP, PAD;   // задаются в Draw() от физики

static bool RowToggle(const char* label, bool* v) {
    ImGuiWindow* win = ImGui::GetCurrentWindow();
    ImVec2 p = ImGui::GetCursorScreenPos();
    float w = ImGui::GetContentRegionAvail().x;
    ImGui::InvisibleButton(label, ImVec2(w, ROW));
    bool clicked = ImGui::IsItemClicked();
    if (clicked) *v = !*v;

    ImDrawList* dl = ImGui::GetWindowDrawList();
    ImGuiID id = win->GetID(label);
    float on = Spring(id, *v ? 1.0f : 0.0f, 16.0f);

    // Подложка строки. Отступаем от краёв колонки: колонка — дочернее окно со
    // своим клипом, и подложка вплотную к его границе срезается по прямой,
    // теряя скругление. Небольшой инсет решает это и заодно даёт воздух.
    if (on > 0.01f) {
        float ins = MM(0.25f);
        dl->AddRectFilled(ImVec2(p.x + ins, p.y + ins),
                          ImVec2(p.x + w - ins, p.y + ROW - ins),
                          Alpha(T.accent, 0.09f * on), MM(0.55f));
    }

    // Переключатель справа: капсула 4.6 x 2.6 мм — крупнее стандартной,
    // чтобы состояние читалось боковым зрением во время боя.
    float tw = MM(4.6f), th = MM(2.6f);
    ImVec2 ta(p.x + w - tw - MM(0.8f), p.y + ROW*0.5f - th*0.5f);
    ImVec2 tb(ta.x + tw, ta.y + th);
    float tr = th * 0.5f;
    dl->AddRectFilled(ta, tb, Mix(IM_COL32(38,38,52,255), T.accent, on), tr);
    if (on > 0.02f)
        dl->AddRect(ImVec2(ta.x-MM(0.1f), ta.y-MM(0.1f)),
                    ImVec2(tb.x+MM(0.1f), tb.y+MM(0.1f)),
                    Alpha(T.accentHi, 0.5f*on*glowIntensity), tr, 0, MM(0.08f));
    float kx = ta.x + tr + (tw - th) * EaseOut(on);
    dl->AddCircleFilled(ImVec2(kx, ta.y + tr), tr - MM(0.22f),
                        IM_COL32(255,255,255,255), 0);

    ImFont* f = ImGui::GetFont();
    float fs = MM(2.5f);
    dl->AddText(f, fs, ImVec2(p.x + MM(0.8f), p.y + ROW*0.5f - fs*0.5f),
                *v ? T.text : T.textDim, label);
    return clicked;
}

static void RowSlider(const char* label, float* v, float lo, float hi, const char* fmt) {
    ImGuiWindow* win = ImGui::GetCurrentWindow();
    ImVec2 p = ImGui::GetCursorScreenPos();
    float w = ImGui::GetContentRegionAvail().x;
    ImGui::InvisibleButton(label, ImVec2(w, ROW));
    bool active = ImGui::IsItemActive();
    if (active) {
        float mx = ImGui::GetIO().MousePos.x;
        float t = (mx - (p.x + MM(0.8f))) / (w - MM(1.6f));
        t = t < 0.f ? 0.f : (t > 1.f ? 1.f : t);
        *v = lo + (hi - lo) * t;
    }
    float t01 = (hi > lo) ? (*v - lo) / (hi - lo) : 0.f;
    t01 = t01 < 0.f ? 0.f : (t01 > 1.f ? 1.f : t01);

    ImDrawList* dl = ImGui::GetWindowDrawList();
    ImFont* f = ImGui::GetFont();
    float fs = MM(2.3f);

    // Подпись и значение в одну строку над дорожкой — так на 8.5 мм помещается
    // и текст, и сама дорожка, не наезжая друг на друга.
    dl->AddText(f, fs, ImVec2(p.x + MM(0.8f), p.y + MM(0.5f)), T.textDim, label);
    char buf[32]; snprintf(buf, sizeof(buf), fmt, *v);
    ImVec2 vs = f->CalcTextSizeA(fs, FLT_MAX, 0, buf);
    dl->AddText(f, fs, ImVec2(p.x + w - vs.x - MM(0.8f), p.y + MM(0.5f)),
                active ? T.accentHi : T.text, buf);

    float ty = p.y + ROW - MM(2.2f);
    float tx0 = p.x + MM(0.8f), tx1 = p.x + w - MM(0.8f);
    float th = MM(0.55f);
    dl->AddRectFilled(ImVec2(tx0, ty), ImVec2(tx1, ty+th),
                      IM_COL32(255,255,255,20), th*0.5f);
    float fx = tx0 + (tx1-tx0) * t01;
    dl->AddRectFilled(ImVec2(tx0, ty), ImVec2(fx, ty+th), T.accent, th*0.5f);
    if (glowIntensity > 0.01f)
        dl->AddRectFilled(ImVec2(tx0, ty-MM(0.12f)), ImVec2(fx, ty+th+MM(0.12f)),
                          Alpha(T.accentHi, 0.30f*glowIntensity), th);
    // Рукоятка 3 мм — попадается пальцем, но не закрывает дорожку.
    float kr = MM(1.5f) * (active ? 1.15f : 1.0f);
    dl->AddCircleFilled(ImVec2(fx, ty+th*0.5f), kr, IM_COL32(255,255,255,255), 0);
    dl->AddCircleFilled(ImVec2(fx, ty+th*0.5f), kr*0.42f, T.accent, 0);
}

static void RowSliderI(const char* label, int* v, int lo, int hi) {
    float fv = (float)*v;
    RowSlider(label, &fv, (float)lo, (float)hi, "%.0f");
    *v = (int)(fv + 0.5f);
}

static void RowColor(const char* label, float col[3]) {
    ImVec2 p = ImGui::GetCursorScreenPos();
    float w = ImGui::GetContentRegionAvail().x;
    ImDrawList* dl = ImGui::GetWindowDrawList();
    ImFont* f = ImGui::GetFont();
    float fs = MM(2.5f);
    dl->AddText(f, fs, ImVec2(p.x + MM(0.8f), p.y + ROW*0.5f - fs*0.5f), T.textDim, label);

    float sw = MM(5.0f), sh = MM(3.0f);
    ImVec2 a(p.x + w - sw - MM(0.8f), p.y + ROW*0.5f - sh*0.5f);
    ImVec2 b(a.x+sw, a.y+sh);
    ImGui::SetCursorScreenPos(a);
    ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding, MM(0.5f));
    ImGui::ColorEdit3(label, col,
        ImGuiColorEditFlags_NoInputs | ImGuiColorEditFlags_NoLabel |
        ImGuiColorEditFlags_NoBorder);
    ImGui::PopStyleVar();
    ImGui::SetCursorScreenPos(ImVec2(p.x, p.y));
    ImGui::Dummy(ImVec2(w, ROW));
}

static void Caption(const char* s) {
    ImVec2 p = ImGui::GetCursorScreenPos();
    ImDrawList* dl = ImGui::GetWindowDrawList();
    ImFont* f = ImGui::GetFont();
    float fs = MM(1.9f);
    float h = MM(4.0f);
    dl->AddText(f, fs, ImVec2(p.x + MM(0.8f), p.y + h - fs - MM(0.6f)), T.textFaint, s);
    float ty = p.y + h - MM(0.3f);
    dl->AddLine(ImVec2(p.x + MM(0.8f), ty), ImVec2(p.x + MM(6.0f), ty),
                Alpha(T.accent, 0.55f), MM(0.08f));
    ImGui::Dummy(ImVec2(ImGui::GetContentRegionAvail().x, h));
}

// ── Вкладки ─────────────────────────────────────────────────────────────────
enum Tab { TAB_ESP = 0, TAB_AIM, TAB_RADAR, TAB_LOOK, TAB_COUNT };
static int g_tab = TAB_ESP;
static const char* kTabName[TAB_COUNT] = { "ESP", "AIM", "RADAR", "LOOK" };

static ImTextureID TabIcon(int i) {
    switch (i) {
        case TAB_ESP:   return g_iconTexEye;
        case TAB_AIM:   return g_iconTexTarget;
        case TAB_RADAR: return g_iconTexMarker;
        default:        return g_iconTexPalette;
    }
}

// ── Клик-бар ────────────────────────────────────────────────────────────────
// Квадрат 11 мм в левом верхнем углу. Без текста: на таком размере подпись
// нечитаема, а знак затмения опознаётся мгновенно. 11 мм — размер подушечки
// большого пальца, попадание гарантировано.
static void DrawClickBar(const ImVec2& ds) {
    (void)ds;
    // Теперь это не квадрат, а информационная плашка: знак + часы + FPS.
    // Ширина выведена из содержимого — 11 мм на знак плюс место под "00:00"
    // и "000 fps" шрифтом 2.2 мм. Высота 11 мм осталась: это размер подушечки
    // большого пальца, вся плашка остаётся одной надёжной целью.
    // 22 x 8.5 мм. Высота 8.5 мм остаётся надёжной целью (минимум 7 мм), но
    // плашка занимает 1.7% экрана вместо прежних 3.1% — почти вдвое меньше.
    // Ширина выведена из содержимого: знак 8.5 + часы ~5.5 + fps ~5 + поля.
    const float H  = MM(8.5f);
    const float W  = MM(22.0f);
    const float M  = MM(3.5f);

    ImGui::PushStyleColor(ImGuiCol_WindowBg, ImVec4(0,0,0,0));
    ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(0,0));
    // Как и у панели: окно начинается ЛЕВЕЕ и ВЫШЕ плашки, иначе ореол
    // срезается по границе окна с двух сторон, и углы выглядят рублеными.
    const float CB_BLEED = MM(3.6f);
    ImGui::SetNextWindowPos(ImVec2(M - CB_BLEED, M - CB_BLEED), ImGuiCond_Always);
    ImGui::SetNextWindowSize(ImVec2(W + CB_BLEED*2.0f, H + CB_BLEED*2.0f), ImGuiCond_Always);
    ImGui::Begin("##v3cb", nullptr,
        ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoResize |
        ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoScrollbar |
        ImGuiWindowFlags_NoCollapse | ImGuiWindowFlags_NoBackground |
        ImGuiWindowFlags_NoSavedSettings);

    // Возвращаем плашку на её место: окно сдвинуто на BLEED, курсор — тоже.
    ImGui::SetCursorScreenPos(ImVec2(M, M));
    ImVec2 p = ImGui::GetCursorScreenPos();
    ImGui::InvisibleButton("##v3cbhit", ImVec2(W, H));
    bool clicked = ImGui::IsItemClicked();
    if (clicked) g_menuOpen = !g_menuOpen;

    ImDrawList* dl = ImGui::GetWindowDrawList();
    ImGuiWindow* win = ImGui::GetCurrentWindow();
    float press = Spring(win->GetID("##v3cbp"), clicked ? 1.0f : 0.0f, 12.0f);
    float open  = Spring(win->GetID("##v3cbo"), g_menuOpen ? 1.0f : 0.0f, 13.0f);

    ImVec2 a = p, b(p.x + W, p.y + H);
    float r = H * 0.32f;

    Glass(dl, a, b, r, 1.0f + press * 0.4f);

    ImFont* f = ImGui::GetFont();

    // ── Знак слева ──────────────────────────────────────────────────────────
    float g = H * 0.52f;
    ImVec2 c(p.x + H*0.52f, p.y + H*0.5f);
    if (g_texBrandMark) {
        if (glowIntensity > 0.01f) {
            float gs = g * 1.55f;
            dl->AddImage(g_texBrandMark,
                ImVec2(c.x-gs*0.5f, c.y-gs*0.5f), ImVec2(c.x+gs*0.5f, c.y+gs*0.5f),
                ImVec2(0,0), ImVec2(1,1), Alpha(T.accentHi, 0.28f*glowIntensity));
        }
        dl->AddImage(g_texBrandMark,
                     ImVec2(c.x - g*0.5f, c.y - g*0.5f),
                     ImVec2(c.x + g*0.5f, c.y + g*0.5f),
                     ImVec2(0,0), ImVec2(1,1), Mix(T.accent, T.accentHi, open));
    }
    // Кольцо-индикатор: замыкается когда меню открыто.
    {
        // Полное кольцо: сегменты по радиусу, шаг ~1.2 px. На маленькой плашке
        // фиксированные 40 давали заметный многоугольник.
        float rr = H * 0.40f;
        int seg = (int)(6.2832f * rr / 1.2f);
        if (seg < 24)  seg = 24;
        if (seg > 128) seg = 128;
        int arcSeg = (int)(seg * (open < 0.02f ? 0.02f : open));
        if (arcSeg < 3) arcSeg = 3;
        dl->PathArcTo(c, rr, -IM_PI*0.5f, -IM_PI*0.5f + IM_PI*2.0f*open, arcSeg);
        dl->PathStroke(Alpha(T.accentHi, 0.85f), 0, MM(0.13f));
    }

    // ── Разделитель ─────────────────────────────────────────────────────────
    float sepX = p.x + H * 1.06f;
    dl->AddLine(ImVec2(sepX, p.y + H*0.24f), ImVec2(sepX, p.y + H*0.76f),
                T.stroke, MM(0.07f));

    // ── Часы: локальное время устройства ────────────────────────────────────
    // time()+localtime вместо счётчика кадров — нужно РЕАЛЬНОЕ время, чтобы
    // не отсчитывать сессию в уме. Форматируем раз в секунду, а не в кадр.
    static char clockBuf[8] = "--:--";
    static int  lastMin = -1;
    {
        time_t now = time(nullptr);
        struct tm tmv;
        localtime_r(&now, &tmv);
        if (tmv.tm_min != lastMin) {
            lastMin = tmv.tm_min;
            snprintf(clockBuf, sizeof(clockBuf), "%02d:%02d", tmv.tm_hour, tmv.tm_min);
        }
    }
    float fsClock = MM(2.4f);
    float tx = sepX + MM(1.1f);
    dl->AddText(f, fsClock, ImVec2(tx, p.y + H*0.5f - fsClock*0.68f), T.text, clockBuf);

    // ── FPS: сглаженный, обновляется 4 раза в секунду ───────────────────────
    // Мгновенное значение дёргается и нечитаемо. EMA плюс редкий пересчёт
    // строки — цифра стоит на месте достаточно, чтобы её успеть прочесть.
    static float fpsEma = 60.0f;
    static char  fpsBuf[16] = "-- fps";
    static double lastFpsUpd = 0.0;
    {
        float dt = ImGui::GetIO().DeltaTime;
        if (dt > 0.0001f) {
            float inst = 1.0f / dt;
            if (inst > 500.f) inst = 500.f;
            fpsEma += (inst - fpsEma) * 0.06f;
        }
        double nowT = ImGui::GetTime();
        if (nowT - lastFpsUpd > 0.25) {
            lastFpsUpd = nowT;
            snprintf(fpsBuf, sizeof(fpsBuf), "%d fps", (int)(fpsEma + 0.5f));
        }
    }
    float fsFps = MM(1.6f);
    // Цвет по значению: зелёный >50, янтарный >30, красный ниже. Считывается
    // боковым зрением, без чтения самой цифры.
    ImU32 fpsCol = fpsEma > 50.f ? IM_COL32(120,230,140,255)
                 : (fpsEma > 30.f ? IM_COL32(255,190, 90,255)
                                  : IM_COL32(255,110,110,255));
    ImVec2 clkSz = f->CalcTextSizeA(fsClock, FLT_MAX, 0, clockBuf);
    dl->AddText(f, fsFps, ImVec2(tx + clkSz.x + MM(1.0f), p.y + H*0.5f - fsFps*0.55f),
                fpsCol, fpsBuf);

    ImGui::End();
    ImGui::PopStyleVar();
    ImGui::PopStyleColor();
}

// ── ESP-ПРЕВЬЮ ──────────────────────────────────────────────────────────────
// Отдельная стеклянная панель СЛЕВА от меню, появляется только на вкладке ESP.
// Рисует ровно тот же оверлей, что видно в бою: те же цвета, те же пропорции
// бокса, тот же порядок подписей. Смысл в том, чтобы настраивать ESP не
// вслепую по названиям тогглов, а глядя на результат.
static void DrawEspPreview(ImVec2 slotA, ImVec2 slotB, float alpha) {
    if (alpha < 0.01f) return;

    const float PW = slotB.x - slotA.x;
    float ph = slotB.y - slotA.y;
    if (PW < MM(12.0f) || ph < MM(20.0f)) return;   // слишком тесно — не рисуем
    ImVec2 a = slotA, b(slotA.x + PW, slotA.y + ph);
    float rnd = MM(2.4f);

    ImGui::PushStyleColor(ImGuiCol_WindowBg, ImVec4(0,0,0,0));
    ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(0,0));
    const float PV_BLEED = MM(3.6f);
    ImGui::SetNextWindowPos(ImVec2(a.x - PV_BLEED, a.y - PV_BLEED), ImGuiCond_Always);
    ImGui::SetNextWindowSize(ImVec2(PW + PV_BLEED*2.0f, ph + PV_BLEED*2.0f), ImGuiCond_Always);
    ImGui::Begin("##v3prev", nullptr,
        ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoResize |
        ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoScrollbar |
        ImGuiWindowFlags_NoCollapse | ImGuiWindowFlags_NoBackground |
        ImGuiWindowFlags_NoSavedSettings | ImGuiWindowFlags_NoInputs);

    ImDrawList* dl = ImGui::GetWindowDrawList();
    ImFont* f = ImGui::GetFont();

    Glass(dl, a, b, rnd, 1.0f, true, /*withArt=*/true);

    // Заголовок панели.
    {
        float fs = MM(1.9f);
        dl->AddText(f, fs, ImVec2(a.x + MM(2.0f), a.y + MM(2.0f)), T.textFaint, "PREVIEW");
        dl->AddLine(ImVec2(a.x + MM(2.0f), a.y + MM(4.6f)),
                    ImVec2(a.x + MM(7.0f), a.y + MM(4.6f)), Alpha(T.accent, 0.55f), MM(0.08f));
    }

    // ── Фигура ──────────────────────────────────────────────────────────────
    // Вписываем по высоте с полями, сохраняя пропорции: искажённая фигура
    // сделала бы бокс вокруг неё бессмысленным как образец.
    float stageTop = a.y + MM(6.5f);
    float stageBot = b.y - MM(5.0f);
    float stageH   = stageBot - stageTop;
    float figH = stageH * 0.82f;
    float figW = figH * (g_texPreviewFigH > 0
                 ? (float)g_texPreviewFigW / (float)g_texPreviewFigH : 0.667f);
    if (figW > PW * 0.62f) { figW = PW * 0.62f; figH = figW / ((g_texPreviewFigH > 0)
                 ? (float)g_texPreviewFigW / (float)g_texPreviewFigH : 0.667f); }
    float figCx = a.x + PW * 0.5f;
    float figTop = stageTop + (stageH - figH) * 0.5f;
    float figBot = figTop + figH;

    // Пятно света под ногами — фигура не висит в пустоте.
    dl->AddCircleFilled(ImVec2(figCx, figBot), figW * 0.42f,
                        Alpha(T.accent, 0.10f), 0);

    if (g_texPreviewFig) {
        dl->AddImage(g_texPreviewFig,
                     ImVec2(figCx - figW*0.5f, figTop),
                     ImVec2(figCx + figW*0.5f, figBot),
                     ImVec2(0,0), ImVec2(1,1), IM_COL32(255,255,255,235));
    }

    // ── Оверлей 1:1 с боевым ────────────────────────────────────────────────
    // Габариты бокса берутся от фигуры, как в бою они берутся от якорей модели.
    float bx0 = figCx - figW*0.42f, bx1 = figCx + figW*0.42f;
    float by0 = figTop + figH*0.02f, by1 = figBot;

    ImU32 accentBox = espDistColor
        ? IM_COL32(255, 190, 70, 255)          // образец «средняя дистанция»
        : IM_COL32(int(espboxcolor[0]*255), int(espboxcolor[1]*255),
                   int(espboxcolor[2]*255), 255);

    if (espdraw && espbox) {
        if (espfill) {
            int fa = (int)(espfillp * 2.2f); if (fa > 200) fa = 200;
            dl->AddRectFilled(ImVec2(bx0, by0), ImVec2(bx1, by1),
                              Alpha(accentBox, fa/255.0f), MM(0.3f));
        }
        float th = espstroke < 0.6f ? MM(0.10f) : MM(0.10f) * espstroke;
        if (espCornerBox) {
            float L = (by1-by0) * espCornerLength;
            float Lx = (bx1-bx0) * espCornerLength;
            dl->AddLine(ImVec2(bx0,by0), ImVec2(bx0+Lx,by0), accentBox, th);
            dl->AddLine(ImVec2(bx0,by0), ImVec2(bx0,by0+L),  accentBox, th);
            dl->AddLine(ImVec2(bx1,by0), ImVec2(bx1-Lx,by0), accentBox, th);
            dl->AddLine(ImVec2(bx1,by0), ImVec2(bx1,by0+L),  accentBox, th);
            dl->AddLine(ImVec2(bx0,by1), ImVec2(bx0+Lx,by1), accentBox, th);
            dl->AddLine(ImVec2(bx0,by1), ImVec2(bx0,by1-L),  accentBox, th);
            dl->AddLine(ImVec2(bx1,by1), ImVec2(bx1-Lx,by1), accentBox, th);
            dl->AddLine(ImVec2(bx1,by1), ImVec2(bx1,by1-L),  accentBox, th);
        } else {
            dl->AddRect(ImVec2(bx0,by0), ImVec2(bx1,by1), accentBox, MM(0.2f), 0, th);
        }
    }

    if (espdraw && esphealth) {
        float bar = MM(0.55f) * (esphpsize < 3.f ? 3.f : esphpsize) * 0.33f;
        float hx1 = bx0 - MM(0.9f), hx0 = hx1 - bar;
        float hp01 = 0.72f;                                   // образец: 72 HP
        dl->AddRectFilled(ImVec2(hx0-MM(0.1f), by0-MM(0.1f)),
                          ImVec2(hx1+MM(0.1f), by1+MM(0.1f)),
                          IM_COL32(6,5,12,220), bar*0.6f);
        float top = by1 - (by1-by0)*hp01;
        ImU32 hpc = IM_COL32(120, 210, 90, 255);
        dl->AddRectFilled(ImVec2(hx0, top), ImVec2(hx1, by1), hpc, bar*0.5f);
        if (espHpNumber) {
            float fs = MM(1.5f);
            ImVec2 ts = f->CalcTextSizeA(fs, FLT_MAX, 0, "72");
            dl->AddText(f, fs, ImVec2(hx0 - ts.x - MM(0.4f), top - fs*0.5f),
                        IM_COL32(255,255,255,255), "72");
        }
        if (espArmor) {
            float fs = MM(1.5f);
            ImVec2 ts = f->CalcTextSizeA(fs, FLT_MAX, 0, "45");
            dl->AddText(f, fs, ImVec2(hx0 - ts.x - MM(0.4f), by1 - fs),
                        IM_COL32(120,190,255,255), "45");
        }
    }

    // Чип: тот же приём, что в бою — текст на полупрозрачной таблетке.
    auto chip = [&](float cx, float y, ImU32 col, ImU32 edge, const char* txt) {
        float fs = MM(1.7f);
        ImVec2 ts = f->CalcTextSizeA(fs, FLT_MAX, 0, txt);
        float padx = MM(0.6f), pady = MM(0.25f);
        ImVec2 ca(cx - ts.x*0.5f - padx, y - pady);
        ImVec2 cb(cx + ts.x*0.5f + padx, y + ts.y + pady);
        dl->AddRectFilled(ca, cb, IM_COL32(8,8,14,190), MM(0.35f));
        if (edge) dl->AddRect(ca, cb, Alpha(edge, 0.55f), MM(0.35f), 0, MM(0.05f));
        dl->AddText(f, fs, ImVec2(cx - ts.x*0.5f, y), col, txt);
        return cb.y;
    };

    if (espdraw) {
        float cx = (bx0+bx1)*0.5f;
        float upY = by0 - MM(1.2f);
        if (espFlags) {
            float fs = MM(1.7f);
            upY -= fs + MM(0.9f);
            chip(cx, upY, IM_COL32(255,205,90,255), IM_COL32(255,205,90,255), "PRIME");
            upY -= MM(0.4f);
        }
        if (espname) {
            float fs = MM(1.7f);
            chip(cx, upY - fs - MM(0.5f), IM_COL32(255,255,255,255), accentBox, "Rem");
            dl->AddLine(ImVec2(bx0, by0-MM(0.15f)), ImVec2(bx1, by0-MM(0.15f)),
                        Alpha(accentBox, 0.55f), MM(0.09f));
        }
        float infoY = by1 + MM(0.5f);
        if (espweapon) infoY = chip(cx, infoY, IM_COL32(235,235,245,255), 0, "ak47") + MM(0.25f);
        if (espdist)   chip(cx, infoY, IM_COL32(170,205,235,255), accentBox, "42 m");
    }

    if (espdraw && esplines_enabled) {
        ImU32 lc = IM_COL32(int(esplines_color[0]*255), int(esplines_color[1]*255),
                            int(esplines_color[2]*255), 220);
        ImVec2 from = (esplines_position == 1)
                    ? ImVec2(a.x + PW*0.5f, b.y - MM(1.0f))   // от «прицела»
                    : ImVec2(a.x + PW*0.5f, b.y - MM(1.0f));
        dl->AddLine(from, ImVec2((bx0+bx1)*0.5f, by1),
                    lc, MM(0.06f) * esplines_thickness);
    }

    ImGui::End();
    ImGui::PopStyleVar();
    ImGui::PopStyleColor();
}

// ── Содержимое вкладок ──────────────────────────────────────────────────────
// Колонки задаются вызывающим кодом; каждая функция просто сыплет строки.

static void ContentESP(int col) {
    if (col == 0) {
        Caption("OVERLAY");
        RowToggle("Enable ESP", &espdraw);
        RowToggle("Box", &espbox);
        RowToggle("Corner box", &espCornerBox);
        RowToggle("Filled", &espfill);
        Caption("SOURCE");
        RowToggle("Bind to model", &espModelAnchor);
        RowToggle("Camera matrix", &espMatrixW2S);
    } else {
        Caption("INFO");
        RowToggle("Health bar", &esphealth);
        RowToggle("HP number", &espHpNumber);
        RowToggle("Name", &espname);
        RowToggle("Weapon", &espweapon);
        RowToggle("Distance", &espdist);
        RowToggle("State tags", &espFlags);
        RowToggle("Armor", &espArmor);
        Caption("STYLE");
        RowToggle("Color by distance", &espDistColor);
        if (!espDistColor) RowColor("Box color", espboxcolor);
        RowSlider("Stroke", &espstroke, 0.0f, 5.0f, "%.1f");
        RowSlider("Max distance", &espMaxDistance, 0.0f, 1000.0f, "%.0f m");
    }
}

static void ContentAim(int col) {
    if (col == 0) {
        Caption("AIMBOT");
        RowToggle("Enable", &aimm);
        RowToggle("Only when scoped", &aimOnlyADS);
        RowToggle("Visible only", &aimvisible);
        RowToggle("Show FOV circle", &aimDrawFov);
        Caption("TARGET");
        static const char* bones[] = { "Head", "Neck", "Body" };
        // Сегмент-контрол: три цели в одну строку, каждая ≈ 4.5 мм шириной.
        {
            ImVec2 p = ImGui::GetCursorScreenPos();
            float w = ImGui::GetContentRegionAvail().x;
            ImGui::InvisibleButton("##bone", ImVec2(w, ROW));
            if (ImGui::IsItemClicked()) {
                float mx = ImGui::GetIO().MousePos.x - p.x;
                int idx = (int)(mx / (w / 3.0f));
                aimcurbone = idx < 0 ? 0 : (idx > 2 ? 2 : idx);
            }
            ImDrawList* dl = ImGui::GetWindowDrawList();
            ImFont* f = ImGui::GetFont();
            float fs = MM(2.3f);
            float segW = w / 3.0f;
            float y0 = p.y + MM(0.6f), y1 = p.y + ROW - MM(0.6f);
            dl->AddRectFilled(ImVec2(p.x, y0), ImVec2(p.x+w, y1),
                              IM_COL32(255,255,255,14), MM(0.6f));
            ImGuiID pid = ImGui::GetCurrentWindow()->GetID("##bonepill");
            float pos = Spring(pid, (float)aimcurbone, 18.0f);
            ImVec2 pa(p.x + segW*pos + MM(0.15f), y0 + MM(0.15f));
            ImVec2 pb(pa.x + segW - MM(0.3f), y1 - MM(0.15f));
            dl->AddRectFilled(pa, pb, T.accent, MM(0.5f));
            if (glowIntensity > 0.01f)
                dl->AddRect(ImVec2(pa.x-MM(0.1f), pa.y-MM(0.1f)),
                            ImVec2(pb.x+MM(0.1f), pb.y+MM(0.1f)),
                            Alpha(T.accentHi, 0.45f*glowIntensity), MM(0.6f), 0, MM(0.08f));
            for (int i = 0; i < 3; ++i) {
                ImVec2 ts = f->CalcTextSizeA(fs, FLT_MAX, 0, bones[i]);
                dl->AddText(f, fs,
                    ImVec2(p.x + segW*i + segW*0.5f - ts.x*0.5f,
                           p.y + ROW*0.5f - fs*0.5f),
                    i == aimcurbone ? IM_COL32(255,255,255,255) : T.textDim,
                    bones[i]);
            }
        }
    } else {
        Caption("TUNING");
        RowSlider("FOV", &aimFovPixels, 20.0f, 600.0f, "%.0f px");
        RowSlider("Smoothing", &aimSmooth, 1.0f, 20.0f, "%.1f");
        RowSlider("Max distance", &aimMaxDistance, 0.0f, 500.0f, "%.0f m");
        Caption("PREDICTION");
        RowToggle("Movement lead", &aimPrediction);
        if (aimPrediction) {
            RowSlider("Projectile", &aimProjectileSpeed, 10.0f, 500.0f, "%.0f m/s");
            RowSlider("Latency", &aimLatencyMs, 0.0f, 300.0f, "%.0f ms");
        }
    }
}

static void ContentRadar(int col) {
    if (col == 0) {
        Caption("RADAR");
        RowToggle("Enable", &radarEnabled);
        RowSlider("Range", &radarRange, 30.0f, 500.0f, "%.0f m");
        RowSlider("Size", &radarSize, 110.0f, 400.0f, "%.0f px");
    } else {
        Caption("PLACEMENT");
        RowSlider("Position X", &radarPos[0], 0.0f, 1600.0f, "%.0f");
        RowSlider("Position Y", &radarPos[1], 0.0f, 900.0f, "%.0f");
        RowSlider("Opacity", &radarAlpha, 0.05f, 1.0f, "%.2f");
    }
}

static void ContentLook(int col) {
    if (col == 0) {
        Caption("ACCENT");
        // Пресеты: пять свотчей 9x6 мм в ряд — крупные цели, промахнуться
        // нельзя, и цвет виден без подписи.
        {
            ImVec2 p = ImGui::GetCursorScreenPos();
            float w = ImGui::GetContentRegionAvail().x;
            float h = MM(6.0f);
            ImGui::InvisibleButton("##presets", ImVec2(w, h));
            if (ImGui::IsItemClicked()) {
                float mx = ImGui::GetIO().MousePos.x - p.x;
                int idx = (int)(mx / (w / (kPresetCount + 1)));
                if (idx >= 0 && idx < kPresetCount) { g_preset = idx; g_useCustom = false; }
                else if (idx == kPresetCount) g_useCustom = true;
            }
            ImDrawList* dl = ImGui::GetWindowDrawList();
            float cellW = w / (kPresetCount + 1);
            for (int i = 0; i <= kPresetCount; ++i) {
                bool isCustom = (i == kPresetCount);
                bool sel = isCustom ? g_useCustom : (!g_useCustom && i == g_preset);
                ImVec2 a(p.x + cellW*i + MM(0.3f), p.y + MM(0.3f));
                ImVec2 b(p.x + cellW*(i+1) - MM(0.3f), p.y + h - MM(0.3f));
                ImU32 lo = isCustom
                    ? IM_COL32(int(g_custom[0]*255), int(g_custom[1]*255), int(g_custom[2]*255), 255)
                    : kPresets[i].lo;
                ImU32 hi = isCustom ? Mix(lo, IM_COL32(255,255,255,255), 0.34f) : kPresets[i].hi;
                if (sel)
                    dl->AddRectFilled(ImVec2(a.x-MM(0.25f), a.y-MM(0.25f)),
                                      ImVec2(b.x+MM(0.25f), b.y+MM(0.25f)),
                                      Alpha(hi, 0.45f), MM(0.8f));
                // Свотч тоже по скруглённой форме: острый градиент вылезал
                // за рамку и углы выглядели рваными.
                GradRoundedDiag(dl, a, b, MM(0.6f), lo, hi);
                dl->AddRect(a, b, sel ? IM_COL32(255,255,255,255) : T.stroke,
                            MM(0.6f), 0, sel ? MM(0.14f) : MM(0.07f));
                if (isCustom) {
                    ImVec2 c((a.x+b.x)*0.5f, (a.y+b.y)*0.5f);
                    dl->AddCircle(c, MM(1.0f), IM_COL32(255,255,255,200), 0, MM(0.09f));
                    dl->AddCircleFilled(c, MM(0.4f), IM_COL32(255,255,255,230), 0);
                }
            }
            ImGui::Dummy(ImVec2(w, h + MM(1.0f)));
        }
        if (g_useCustom) {
            ImGui::PushItemWidth(ImGui::GetContentRegionAvail().x - MM(1.6f));
            ImGui::SetCursorPosX(ImGui::GetCursorPosX() + MM(0.8f));
            ImGui::ColorPicker3("##v3pick", g_custom,
                ImGuiColorEditFlags_NoSidePreview | ImGuiColorEditFlags_NoSmallPreview |
                ImGuiColorEditFlags_NoInputs | ImGuiColorEditFlags_NoLabel |
                ImGuiColorEditFlags_PickerHueBar);
            ImGui::PopItemWidth();
        }
    } else {
        Caption("LIGHT");
        RowSlider("Glow", &glowIntensity, 0.0f, 2.0f, "%.2f");
        // Живой образец материала: те же слои, что у панели. Цвет подбирается
        // по нему, а не вслепую по числу на ползунке.
        {
            ImVec2 p = ImGui::GetCursorScreenPos();
            float w = ImGui::GetContentRegionAvail().x - MM(1.6f);
            float h = MM(9.0f);
            ImVec2 a(p.x + MM(0.8f), p.y);
            ImVec2 b(a.x + w, a.y + h);
            Glass(ImGui::GetWindowDrawList(), a, b, MM(1.6f));
            if (g_texBrandMark) {
                float g = h * 0.50f;
                ImVec2 c(a.x + h*0.55f, a.y + h*0.5f);
                ImGui::GetWindowDrawList()->AddImage(g_texBrandMark,
                    ImVec2(c.x-g*0.5f, c.y-g*0.5f), ImVec2(c.x+g*0.5f, c.y+g*0.5f),
                    ImVec2(0,0), ImVec2(1,1), T.accent);
            }
            ImGui::Dummy(ImVec2(w, h + MM(1.5f)));
        }
        Caption("BACKGROUND");
        RowToggle("Show artwork", &g_artEnabled);
        if (g_artEnabled) {
            RowSlider("Art opacity", &g_artOpacity, 0.0f, 1.0f, "%.2f");
            RowSlider("Art tint", &g_artTint, 0.0f, 1.0f, "%.2f");
            RowToggle("Animate", &g_artAnimate);
            if (g_artAnimate)
                RowSlider("Motion", &g_artAnimAmount, 0.0f, 2.0f, "%.2f");
        }
        Caption("PERFORMANCE");
        RowSliderI("Heavy scan", &g_cacheInterval, 4, 30);
        RowSliderI("Position rate", &g_positionInterval, 1, 4);
    }
}

static void Content(int tab, int col) {
    switch (tab) {
        case TAB_ESP:   ContentESP(col);   break;
        case TAB_AIM:   ContentAim(col);   break;
        case TAB_RADAR: ContentRadar(col); break;
        default:        ContentLook(col);  break;
    }
}

// ── Главная отрисовка ───────────────────────────────────────────────────────
void Draw() {
    // Загрузка встроенных PNG в GL-текстуры. Раньше этот вызов жил внутри
    // Layout_tick_UI, которая после перехода на ui_v3 больше не выполняется —
    // поэтому НИ ОДНА текстура не грузилась: ни фон, ни фигура превью, ни
    // иконки. GL-контекст здесь уже активен (мы внутри кадра ImGui).
    oxLoadIcons();

    ImGuiIO& io = ImGui::GetIO();
    ImVec2 ds = io.DisplaySize;
    if (ds.x < 1.f || ds.y < 1.f) return;

    // Масштаб: держим физический размер в миллиметрах на любом экране.
    // Опорная величина — МЕНЬШАЯ сторона: в ландшафте это высота, и именно она
    // ограничивает, сколько строк поместится.
    float shortSide = ds.x < ds.y ? ds.x : ds.y;
    g_k = shortSide / kRefH;
    if (g_k < 0.55f) g_k = 0.55f;
    if (g_k > 2.20f) g_k = 2.20f;

    BuildTheme();

    // Точность скруглений. По умолчанию ImGui считает сегменты от радиуса при
    // допуске 1.25 px — на панели с радиусом ~37 px и на кольцах ореола это
    // даёт заметные фаски по углам. Ужесточаем допуск: углы становятся
    // гладкими, прирост вершин на десяток скруглённых элементов ничтожен.
    ImGui::GetStyle().CircleTessellationMaxError = 0.18f;
    ImGui::GetStyle().CurveTessellationTol       = 0.85f;

    // Решение подбора: 5 строк по 8 мм + шапка 8 мм дают панель ровно 82%
    // высоты. Высота панели ВЫВЕДЕНА из строки, а не наоборот — поэтому снизу
    // не остаётся мёртвой полосы, как было бы при произвольных 78%.
    ROW = MM(8.0f);
    GAP = MM(1.5f);
    PAD = MM(4.0f);

    DrawClickBar(ds);

    static float openAnim = 0.0f;
    openAnim = Approach(openAnim, g_menuOpen ? 1.0f : 0.0f,
                        g_menuOpen ? 13.0f : 16.0f, io.DeltaTime);
    if (openAnim < 0.002f) return;

    // Превью занимает место СЛЕВА, поэтому его состояние нужно знать до того,
    // как считается позиция меню: иначе панель остаётся по центру и превью
    // уезжает за левый край экрана (проверено расчётом раскладки).
    static float prevAnim = 0.0f;
    prevAnim = Approach(prevAnim, (g_tab == TAB_ESP) ? 1.0f : 0.0f, 14.0f, io.DeltaTime);

    // Панель. Сверху и снизу остаётся запас — прицел и нижний HUD игры не
    // перекрываются.
    const float HEAD_MM = 8.0f;
    const int   ROWS     = 5;
    float bodyNeed = ROWS * (ROW + GAP) - GAP;
    float phNeed   = MM(HEAD_MM) + MM(1.2f) + bodyNeed + MM(2.0f);
    const float PREV_W = MM(30.0f);
    const float PREV_GAP = MM(2.5f);
    const float PREV_LEFT = MM(3.0f);

    float ph = phNeed;
    if (ph > ds.y * 0.90f) ph = ds.y * 0.90f;

    // Когда превью открыто, панель сужается и уезжает вправо — ровно на
    // ширину превью с зазором. Интерполируем по той же анимации, поэтому
    // меню плавно расступается, а не прыгает.
    float pwWide = ds.x * 0.72f;
    float pwNarrow = ds.x * 0.64f;
    float pw = pwWide + (pwNarrow - pwWide) * prevAnim;
    float pxCenter = (ds.x - pw) * 0.5f;
    float pxShift  = PREV_LEFT + PREV_W + PREV_GAP;
    float px = pxCenter + (pxShift - pxCenter) * prevAnim;
    float py = (ds.y - ph) * 0.5f;
    float rnd = MM(2.4f);

    ImDrawList* bg = ImGui::GetBackgroundDrawList();
    bg->AddRectFilled(ImVec2(0,0), ds, IM_COL32(4,4,9, (int)(168*openAnim)));

    // Появление: лёгкий подъём снизу + масштаб. Без «прыжка» — палец уже
    // на экране, резкое движение сбивает прицеливание следующего тапа.
    float e = EaseOut(openAnim);
    float sc = 0.965f + 0.035f * e;
    float dy = (1.0f - e) * MM(4.0f);
    float cx = px + pw*0.5f, cy = py + ph*0.5f;
    pw *= sc; ph *= sc;
    px = cx - pw*0.5f; py = cy - ph*0.5f + dy;

    ImGui::PushStyleColor(ImGuiCol_WindowBg, ImVec4(0,0,0,0));
    ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(0,0));
    ImGui::PushStyleVar(ImGuiStyleVar_ScrollbarSize, MM(1.2f));
    // Окно ШИРЕ панели на величину ореола. ImGui клипует drawlist по границам
    // окна: если сделать окно ровно по панели, свечение обрежется прямой
    // линией точно по её краю — и на скруглённых углах это читается как
    // «углы обрезаны». BLEED — запас под самое дальнее кольцо ореола.
    const float BLEED = MM(3.6f);
    ImGui::SetNextWindowPos(ImVec2(px - BLEED, py - BLEED), ImGuiCond_Always);
    ImGui::SetNextWindowSize(ImVec2(pw + BLEED*2.0f, ph + BLEED*2.0f), ImGuiCond_Always);
    ImGui::Begin("##v3menu", nullptr,
        ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoResize |
        ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoScrollbar |
        ImGuiWindowFlags_NoCollapse | ImGuiWindowFlags_NoBackground |
        ImGuiWindowFlags_NoSavedSettings | ImGuiWindowFlags_NoBringToFrontOnFocus);

    ImDrawList* dl = ImGui::GetWindowDrawList();
    ImVec2 a(px, py), b(px+pw, py+ph);
    Glass(dl, a, b, rnd, 1.0f, true, /*withArt=*/true);

    ImFont* f = ImGui::GetFont();

    // ── Шапка 11 мм: метка, имя, статус вкладки ─────────────────────────────
    const float HEAD = MM(HEAD_MM);
    {
        float bs = MM(5.0f);
        ImVec2 bc(a.x + PAD + bs*0.5f, a.y + HEAD*0.5f);
        // Метка со свечением: сначала размытая копия акцентом, сверху резкая.
        if (g_texBrandMark) {
            if (glowIntensity > 0.01f) {
                float gs = bs * 1.5f;
                dl->AddImage(g_texBrandMark,
                    ImVec2(bc.x-gs*0.5f, bc.y-gs*0.5f), ImVec2(bc.x+gs*0.5f, bc.y+gs*0.5f),
                    ImVec2(0,0), ImVec2(1,1), Alpha(T.accentHi, 0.30f*glowIntensity));
            }
            dl->AddImage(g_texBrandMark,
                ImVec2(bc.x-bs*0.5f, bc.y-bs*0.5f), ImVec2(bc.x+bs*0.5f, bc.y+bs*0.5f),
                ImVec2(0,0), ImVec2(1,1), T.accent);
        }

        // Полное имя, как просил: "Eclips Oxide". Первое слово белым, второе
        // акцентом — так читается и как один знак, и как два слова.
        float fs = MM(3.2f);
        float tx = a.x + PAD + bs + MM(2.2f);
        float ty = a.y + HEAD*0.5f - fs*0.62f;
        if (glowIntensity > 0.01f)
            dl->AddText(f, fs, ImVec2(tx+MM(0.08f), ty+MM(0.08f)),
                        Alpha(T.accentHi, 0.25f*glowIntensity), "Eclips");
        dl->AddText(f, fs, ImVec2(tx, ty), T.text, "Eclips");
        ImVec2 w1 = f->CalcTextSizeA(fs, FLT_MAX, 0, "Eclips ");
        dl->AddText(f, fs, ImVec2(tx + w1.x, ty), T.accent, "Oxide");
        float fs2 = MM(1.7f);
        dl->AddText(f, fs2, ImVec2(tx + MM(0.15f), a.y + HEAD*0.5f + fs*0.34f),
                    T.textFaint, kTabName[g_tab]);

        // Индикатор готовности справа.
        float dr = MM(0.7f);
        ImVec2 dc(b.x - PAD - dr, a.y + HEAD*0.5f);
        float t = (float)ImGui::GetTime();
        float pulse = 0.55f + 0.45f * sinf(t*2.4f);
        dl->AddCircleFilled(dc, dr*2.2f, Alpha(T.accent, 0.20f*pulse), 0);
        dl->AddCircleFilled(dc, dr, T.accentHi, 0);

        dl->AddLine(ImVec2(a.x + PAD, a.y + HEAD), ImVec2(b.x - PAD, a.y + HEAD),
                    T.stroke, MM(0.07f));
    }

    // ── Рельс навигации 14 мм слева ─────────────────────────────────────────
    // Вертикальный, у самой кромки: зона левого большого пальца. Иконки без
    // подписей — на 14 мм текст читался бы хуже, чем узнаваемый знак.
    const float RAIL = MM(14.0f);
    {
        float railTop = a.y + HEAD + MM(1.2f);
        float railH   = (b.y - MM(2.0f)) - railTop;
        float cell    = railH / (float)TAB_COUNT;

        ImGui::SetCursorScreenPos(ImVec2(a.x, railTop));
        ImGui::InvisibleButton("##v3rail", ImVec2(RAIL, railH));
        if (ImGui::IsItemClicked()) {
            float my = ImGui::GetIO().MousePos.y - railTop;
            int idx = (int)(my / cell);
            g_tab = idx < 0 ? 0 : (idx >= TAB_COUNT ? TAB_COUNT-1 : idx);
        }

        ImGuiID sid = ImGui::GetCurrentWindow()->GetID("##v3railsel");
        float selPos = Spring(sid, (float)g_tab, 17.0f);

        // Едущая подсветка активной вкладки.
        ImVec2 sa(a.x + MM(0.6f), railTop + cell*selPos + MM(0.5f));
        ImVec2 sb(a.x + RAIL - MM(0.6f), sa.y + cell - MM(1.0f));
        dl->AddRectFilled(sa, sb, Alpha(T.accent, 0.16f), MM(1.4f));
        dl->AddRectFilled(ImVec2(a.x, sa.y + (sb.y-sa.y)*0.22f),
                          ImVec2(a.x + MM(0.35f), sb.y - (sb.y-sa.y)*0.22f),
                          T.accent, MM(0.2f));
        if (glowIntensity > 0.01f)
            dl->AddRect(sa, sb, Alpha(T.accentHi, 0.40f*glowIntensity), MM(1.4f), 0, MM(0.08f));

        for (int i = 0; i < TAB_COUNT; ++i) {
            float cyi = railTop + cell*(i+0.5f);
            bool on = (i == g_tab);
            float is = MM(4.4f);
            ImTextureID tex = TabIcon(i);
            ImU32 tint = on ? T.accentHi : T.textFaint;
            if (tex) {
                dl->AddImage(tex,
                    ImVec2(a.x + RAIL*0.5f - is*0.5f, cyi - is*0.5f - MM(1.0f)),
                    ImVec2(a.x + RAIL*0.5f + is*0.5f, cyi + is*0.5f - MM(1.0f)),
                    ImVec2(0,0), ImVec2(1,1), tint);
            }
            float fs = MM(1.7f);
            ImVec2 ts = f->CalcTextSizeA(fs, FLT_MAX, 0, kTabName[i]);
            dl->AddText(f, fs, ImVec2(a.x + RAIL*0.5f - ts.x*0.5f, cyi + is*0.5f - MM(0.6f)),
                        on ? T.text : T.textFaint, kTabName[i]);
        }
        dl->AddLine(ImVec2(a.x + RAIL, railTop), ImVec2(a.x + RAIL, b.y - MM(2.0f)),
                    T.stroke, MM(0.07f));
    }

    // ── Две колонки контента ────────────────────────────────────────────────
    // По вертикали помещается всего 3-4 строки, по горизонтали места вдвое
    // больше нужного — поэтому контролы идут в две колонки, и почти всё
    // видно без скролла.
    {
        float bodyX = a.x + RAIL + PAD;
        float bodyY = a.y + HEAD + MM(1.2f);
        float bodyW = (b.x - PAD) - bodyX;
        float bodyH = (b.y - MM(2.0f)) - bodyY;
        float colGap = MM(4.0f);
        float colW = (bodyW - colGap) * 0.5f;

        ImGui::PushStyleVar(ImGuiStyleVar_ItemSpacing, ImVec2(0, GAP));
        for (int c = 0; c < 2; ++c) {
            char cid[16]; snprintf(cid, sizeof(cid), "##v3col%d", c);
            ImGui::SetCursorScreenPos(ImVec2(bodyX + (colW+colGap)*c, bodyY));
            ImGui::BeginChild(cid, ImVec2(colW, bodyH), false,
                ImGuiWindowFlags_NoBackground | ImGuiWindowFlags_NoScrollbar);
            // Инерционный скролл пальцем: на телефоне тянут содержимое, а не
            // ползунок. Ползунок оставлен скрытым, чтобы не есть ширину.
            if (ImGui::IsWindowHovered() && ImGui::IsMouseDragging(0, 0.0f))
                ImGui::SetScrollY(ImGui::GetScrollY() - io.MouseDelta.y);
            Content(g_tab, c);
            ImGui::EndChild();
        }
        ImGui::PopStyleVar();
    }

    ImGui::End();
    ImGui::PopStyleVar(2);
    ImGui::PopStyleColor();

    if (prevAnim > 0.01f) {
        // Превью начинается НИЖЕ клик-бара: тот живёт в левом верхнем углу, и
        // при центрированной панели их прямоугольники пересекались (проверено
        // расчётом: низ клик-бара y=232, верх панели y=97). Низ выравниваем
        // по меню, поэтому превью просто короче на высоту клик-бара.
        float prevTop = MM(4.0f) + MM(11.0f) + MM(2.5f);
        if (prevTop < py) prevTop = py;
        DrawEspPreview(ImVec2(PREV_LEFT, prevTop),
                       ImVec2(PREV_LEFT + PREV_W, py + ph),
                       prevAnim * openAnim);
    }
}

} // namespace uiv3

// Точка входа для main.cpp.
void OxDrawUiV3() { uiv3::Draw(); }
