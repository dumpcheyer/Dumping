// Загрузка фоновой картинки меню в GL-текстуру (ленивая, один раз).
// Декодирование встроенного JPEG через stb_image. Вызывать только когда
// активен GL-контекст (во время кадра ImGui) — так и есть в Layout_tick_UI.
#include <GLES3/gl3.h>
#include <cstdint>

#include "imgui.h"

#define STB_IMAGE_IMPLEMENTATION
// JPEG for the menu background art; PNG for the embedded icon/asset set
// (ox_assets.h). This is the single stb_image implementation TU in the
// project, so both decoders must be enabled here.
#define STBI_ONLY_JPEG
#define STBI_ONLY_PNG
#define STBI_NO_STDIO
#define STBI_NO_FAILURE_STRINGS
#include "stb_image.h"

#include "menu_bg.h"
#include "ox_assets.h"
#include "ox_assets2.h"
#include "ox_assets3.h"
#include "ox_preview_dummy.h"

// Возвращает ImTextureID фоновой картинки (0 если не удалось). Размер — в out.
ImTextureID oxGetMenuBg(int* outW, int* outH) {
    static bool         tried = false;
    static ImTextureID  tex   = (ImTextureID)0;
    static int          W = 0, H = 0;

    if (!tried) {
        tried = true;
        int n = 0;
        unsigned char* px = stbi_load_from_memory(
            menu_bg_jpg, (int)menu_bg_jpg_len, &W, &H, &n, 4);
        if (px) {
            GLuint id = 0;
            glGenTextures(1, &id);
            glBindTexture(GL_TEXTURE_2D, id);
            glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_LINEAR);
            glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_LINEAR);
            glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_S, GL_CLAMP_TO_EDGE);
            glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_T, GL_CLAMP_TO_EDGE);
            glTexImage2D(GL_TEXTURE_2D, 0, GL_RGBA, W, H, 0,
                         GL_RGBA, GL_UNSIGNED_BYTE, px);
            glBindTexture(GL_TEXTURE_2D, 0);
            stbi_image_free(px);
            tex = (ImTextureID)(intptr_t)id;
        }
    }

    if (outW) *outW = W;
    if (outH) *outH = H;
    return tex;
}

// ============================================================================
//  GLASS UI — embedded PNG icon textures ("Eclips Oxide" precision line set).
//  Decoded from ox_assets.h via stb_image (PNG) and uploaded to GL
//  textures exactly once. Must be called while a GL context is current
//  (i.e. from inside the ImGui frame in Layout_tick_UI). RGBA / alpha-blended.
//  Glyphs are pure white on transparent — tint freely at draw time.
// ============================================================================

// Legacy icon texture handles (0 until oxLoadIcons() runs). Consumed in
// main.cpp. Kept intact; art regenerated — each now points at the matching
// glyph of the new ox_assets.h set (some aliases share one GL texture).
ImTextureID g_iconTexESP       = (ImTextureID)0;   // -> icon_eye
ImTextureID g_iconTexAim       = (ImTextureID)0;   // -> icon_target (alias)
ImTextureID g_iconTexCrosshair = (ImTextureID)0;   // -> icon_crosshair
ImTextureID g_iconTexHud       = (ImTextureID)0;   // -> icon_lens (alias)
ImTextureID g_iconTexPalette   = (ImTextureID)0;   // -> icon_palette
ImTextureID g_iconTexHealth    = (ImTextureID)0;   // -> icon_heart (alias)
ImTextureID g_iconTexDistance  = (ImTextureID)0;   // -> icon_ruler (alias)
ImTextureID g_iconTexShield    = (ImTextureID)0;   // -> icon_shield
ImTextureID g_iconTexTarget    = (ImTextureID)0;   // -> icon_target
ImTextureID g_iconTexBrandBadge = (ImTextureID)0;  // -> brand_mark (alias)

// New icon texture handles (ox_assets.h set). Consumed by the menu layout.
ImTextureID g_iconTexEye      = (ImTextureID)0;  // eye + pupil (ESP)
ImTextureID g_iconTexLens     = (ImTextureID)0;  // aperture iris (camera/W2S)
ImTextureID g_iconTexGear     = (ImTextureID)0;  // settings gear
ImTextureID g_iconTexHeart    = (ImTextureID)0;  // heart (health bar)
ImTextureID g_iconTexRuler    = (ImTextureID)0;  // ruler (distance)
ImTextureID g_iconTexSkeleton = (ImTextureID)0;  // skeleton ESP
ImTextureID g_iconTexCube     = (ImTextureID)0;  // wireframe cube (3D box)
ImTextureID g_iconTexLock     = (ImTextureID)0;  // padlock
ImTextureID g_iconTexBolt     = (ImTextureID)0;  // lightning bolt
ImTextureID g_iconTexFlag     = (ImTextureID)0;  // flag (teammates)
ImTextureID g_iconTexMarker   = (ImTextureID)0;  // map pin / marker
ImTextureID g_texBrandMark    = (ImTextureID)0;  // 240x240 eclipsed-ring monogram
ImTextureID g_texGrain        = (ImTextureID)0;  // 128x128 film grain, GL_REPEAT
// ESP live-preview dummy character (anime model shown inside the preview pane).
// Фон меню (присланный арт) и фигура для ESP-превью.
ImTextureID g_texMenuArt     = (ImTextureID)0;
int         g_texMenuArtW    = 0;
int         g_texMenuArtH    = 0;
ImTextureID g_texPreviewFig  = (ImTextureID)0;
int         g_texPreviewFigW = 0;
int         g_texPreviewFigH = 0;
ImTextureID g_texPreviewDummy   = (ImTextureID)0;
int         g_texPreviewDummyW  = 0;
int         g_texPreviewDummyH  = 0;

// Decode one embedded PNG (RGBA) and upload it to a fresh GL texture.
// Returns the ImTextureID (0 on failure). Linear filtering; wrap mode is
// clamp-to-edge for icons, GL_REPEAT for tileable textures (tex_grain).
static ImTextureID ox_uploadIconTexture(const unsigned char* png, unsigned int size,
                                        GLenum wrap = GL_CLAMP_TO_EDGE) {
    int w = 0, h = 0, n = 0;
    unsigned char* px = stbi_load_from_memory(png, (int)size, &w, &h, &n, 4);
    if (!px) return (ImTextureID)0;
    GLuint id = 0;
    glGenTextures(1, &id);
    glBindTexture(GL_TEXTURE_2D, id);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_LINEAR);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_LINEAR);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_S, (GLint)wrap);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_T, (GLint)wrap);
    glTexImage2D(GL_TEXTURE_2D, 0, GL_RGBA, w, h, 0,
                 GL_RGBA, GL_UNSIGNED_BYTE, px);
    glBindTexture(GL_TEXTURE_2D, 0);
    stbi_image_free(px);
    return (ImTextureID)(uintptr_t)id;
}

// Decode + upload every embedded icon/asset once. Guarded so repeated calls
// (once per frame from Layout_tick_UI) are no-ops after the first success.
void oxLoadIcons() {
    static bool loaded = false;
    if (loaded) return;
    loaded = true;

    // New "Eclips Oxide" precision line set (ox_assets.h), one upload each.
    g_iconTexEye        = ox_uploadIconTexture(icon_eye_png,       icon_eye_png_size);
    g_iconTexCrosshair  = ox_uploadIconTexture(icon_crosshair_png, icon_crosshair_png_size);
    g_iconTexLens       = ox_uploadIconTexture(icon_lens_png,      icon_lens_png_size);
    g_iconTexGear       = ox_uploadIconTexture(icon_gear_png,      icon_gear_png_size);
    g_iconTexShield     = ox_uploadIconTexture(icon_shield_png,    icon_shield_png_size);
    g_iconTexHeart      = ox_uploadIconTexture(icon_heart_png,     icon_heart_png_size);
    g_iconTexRuler      = ox_uploadIconTexture(icon_ruler_png,     icon_ruler_png_size);
    g_iconTexSkeleton   = ox_uploadIconTexture(icon_skeleton_png,  icon_skeleton_png_size);
    g_iconTexCube       = ox_uploadIconTexture(icon_cube_png,      icon_cube_png_size);
    g_iconTexPalette    = ox_uploadIconTexture(icon_palette_png,   icon_palette_png_size);
    g_iconTexLock       = ox_uploadIconTexture(icon_lock_png,      icon_lock_png_size);
    g_iconTexBolt       = ox_uploadIconTexture(icon_bolt_png,      icon_bolt_png_size);
    g_iconTexFlag       = ox_uploadIconTexture(icon_flag_png,      icon_flag_png_size);
    g_iconTexMarker     = ox_uploadIconTexture(icon_marker_png,    icon_marker_png_size);
    g_iconTexTarget     = ox_uploadIconTexture(icon_target_png,    icon_target_png_size);
    g_texBrandMark      = ox_uploadIconTexture(brand_mark_png,     brand_mark_png_size);
    // Film-grain overlay tile: GL_REPEAT so panels can tile it at any size.
    g_texGrain          = ox_uploadIconTexture(tex_grain_png,      tex_grain_png_size,
                                               GL_REPEAT);

    // Legacy handles: regenerated art, same globals. Aliases reuse the GL
    // texture uploaded above (read-only usage; nothing ever deletes them).
    g_iconTexESP        = g_iconTexEye;      // ESP tab      -> eye
    g_iconTexAim        = g_iconTexTarget;   // Aim tab      -> concentric target
    g_iconTexHud        = g_iconTexLens;     // Camera / W2S -> aperture iris
    g_iconTexHealth     = g_iconTexHeart;    // health bar   -> heart
    g_iconTexDistance   = g_iconTexRuler;    // distance     -> ruler
    g_iconTexBrandBadge = g_texBrandMark;    // brand badge  -> eclipsed-ring mark

    // ── Новый набор глифов (ox_assets2.h) ──────────────────────────────────
    // Перекрывают старые хендлы: везде, где меню рисует иконку, теперь
    // подтягивается процедурно сгенерированный глиф со встроенным свечением.
    {
        ImTextureID t;
        t = ox_uploadIconTexture(brand_mark2_png,  brand_mark2_png_size);  if (t) { g_texBrandMark = t; g_iconTexBrandBadge = t; }
        t = ox_uploadIconTexture(icon_eye2_png,    icon_eye2_png_size);    if (t) { g_iconTexEye = t; g_iconTexESP = t; }
        t = ox_uploadIconTexture(icon_target2_png, icon_target2_png_size); if (t) { g_iconTexTarget = t; g_iconTexAim = t; }
        t = ox_uploadIconTexture(icon_gear2_png,   icon_gear2_png_size);   if (t) g_iconTexGear = t;
        t = ox_uploadIconTexture(icon_palette2_png,icon_palette2_png_size);if (t) g_iconTexPalette = t;
        t = ox_uploadIconTexture(icon_radar2_png,  icon_radar2_png_size);  if (t) { g_iconTexMarker = t; g_iconTexLens = t; g_iconTexHud = t; }
        t = ox_uploadIconTexture(icon_cube2_png,   icon_cube2_png_size);   if (t) g_iconTexCube = t;
        t = ox_uploadIconTexture(icon_heart2_png,  icon_heart2_png_size);  if (t) { g_iconTexHeart = t; g_iconTexHealth = t; }
        t = ox_uploadIconTexture(icon_ruler2_png,  icon_ruler2_png_size);  if (t) { g_iconTexRuler = t; g_iconTexDistance = t; }
        t = ox_uploadIconTexture(icon_bolt2_png,   icon_bolt2_png_size);   if (t) g_iconTexBolt = t;
        t = ox_uploadIconTexture(icon_shield2_png, icon_shield2_png_size); if (t) g_iconTexShield = t;
    }

    // ── Фон меню и фигура превью (ox_assets3.h) ────────────────────────────
    {
        int w = 0, h = 0, n = 0;
        unsigned char* px = stbi_load_from_memory(menu_art_jpg, (int)menu_art_jpg_size,
                                                  &w, &h, &n, 4);
        if (px) {
            GLuint id = 0;
            glGenTextures(1, &id);
            glBindTexture(GL_TEXTURE_2D, id);
            glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_LINEAR);
            glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_LINEAR);
            glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_S, GL_CLAMP_TO_EDGE);
            glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_T, GL_CLAMP_TO_EDGE);
            glTexImage2D(GL_TEXTURE_2D, 0, GL_RGBA, w, h, 0, GL_RGBA, GL_UNSIGNED_BYTE, px);
            glBindTexture(GL_TEXTURE_2D, 0);
            stbi_image_free(px);
            g_texMenuArt  = (ImTextureID)(uintptr_t)id;
            g_texMenuArtW = w; g_texMenuArtH = h;
        }
    }
    {
        int w = 0, h = 0, n = 0;
        unsigned char* px = stbi_load_from_memory(preview_figure_png,
                                                  (int)preview_figure_png_size, &w, &h, &n, 4);
        if (px) {
            GLuint id = 0;
            glGenTextures(1, &id);
            glBindTexture(GL_TEXTURE_2D, id);
            glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_LINEAR);
            glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_LINEAR);
            glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_S, GL_CLAMP_TO_EDGE);
            glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_T, GL_CLAMP_TO_EDGE);
            glTexImage2D(GL_TEXTURE_2D, 0, GL_RGBA, w, h, 0, GL_RGBA, GL_UNSIGNED_BYTE, px);
            glBindTexture(GL_TEXTURE_2D, 0);
            stbi_image_free(px);
            g_texPreviewFig  = (ImTextureID)(uintptr_t)id;
            g_texPreviewFigW = w; g_texPreviewFigH = h;
        }
    }

    // ESP-preview dummy: нужен размер, чтобы держать aspect-ratio в панели.
    {
        int w = 0, h = 0, n = 0;
        unsigned char* px = stbi_load_from_memory(preview_dummy_png,
                                                  (int)preview_dummy_png_size, &w, &h, &n, 4);
        if (px) {
            GLuint id = 0;
            glGenTextures(1, &id);
            glBindTexture(GL_TEXTURE_2D, id);
            glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_LINEAR);
            glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_LINEAR);
            glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_S, GL_CLAMP_TO_EDGE);
            glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_T, GL_CLAMP_TO_EDGE);
            glTexImage2D(GL_TEXTURE_2D, 0, GL_RGBA, w, h, 0, GL_RGBA, GL_UNSIGNED_BYTE, px);
            glBindTexture(GL_TEXTURE_2D, 0);
            stbi_image_free(px);
            g_texPreviewDummy  = (ImTextureID)(uintptr_t)id;
            g_texPreviewDummyW = w;
            g_texPreviewDummyH = h;
        }
    }
}
