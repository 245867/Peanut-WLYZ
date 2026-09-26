// ============================================================
// Peanut WLYZ — 运行时 UI 皮肤引擎
// 3 套完全不同的视觉风格，命令行 --skin=N 选择
//   skin 1 = 极夜霓虹 Aurora   深蓝黑 + 青紫霓虹
//   skin 2 = 晨曦白   Daylight 明亮简约 + 克莱因蓝
//   skin 3 = 熔岩黑   Magma    纯黑硬朗 + 熔岩橙红
// ============================================================
#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <objidl.h>   // gdiplus 需要 IStream
#include <propidl.h>  // gdiplus 需要 PROPID
#include <gdiplus.h>

namespace peanut { namespace ui {

enum NavStyle {
    NAV_UNDERLINE = 0,
    NAV_PILL      = 1,
    NAV_LEFTMARK  = 2
};

struct UiSkin {
    const wchar_t* key;
    const wchar_t* name;
    const wchar_t* family;
    const wchar_t* mono;
    bool  light;

    COLORREF bgDeep, bgDeep2, bgTopNav, bgTopNav2, bgLog;
    COLORREF bgCard, bgCard2, bgInput, bgHeader, bgHover;
    COLORREF accent, accentDim, accentGlow, accent2;
    COLORREF textPrimary, textSecondary, textMuted;
    COLORREF success, warning, danger, info;
    COLORREF border, divider;

    float cardRadius;
    float btnRadius;
    int   navStyle;
    int   navBtnHeight;
    bool  navDivider;
    int   accentBarW;
    bool  softShadow;

    // ── 设计 token（v8）────────────────────────────────────
    // 这三组值决定了"层次感"，比单纯的颜色更重要
    COLORREF bgElevated;      // 抬升面：内嵌块 / 次级容器
    COLORREF accentSoft;      // 强调色柔和底：图标容器 / 选中态底
    float    cardBorderAlpha; // 卡片描边强度（浅色皮肤需要更实）
    int      navHeight;       // 顶部导航栏高度
    float    navItemRadius;   // 导航项高亮圆角
    float    shadowAlpha;     // 阴影基准不透明度，0 = 关闭
    int      shadowSpread;    // 阴影扩散半径(px)
    int      shadowOffsetY;   // 阴影垂直偏移(px)
};

extern UiSkin g_skin;

int UiSkin_Load(int id);
int UiSkin_ParseCommandLine(const wchar_t* cmdLine);
int UiSkin_ParseEnv();

inline Gdiplus::Color Gp(COLORREF c) {
    return Gdiplus::Color(GetRValue(c), GetGValue(c), GetBValue(c));
}
inline Gdiplus::Color Gp(COLORREF c, BYTE alpha) {
    return Gdiplus::Color(alpha, GetRValue(c), GetGValue(c), GetBValue(c));
}
inline COLORREF MixColor(COLORREF a, COLORREF b, float t) {
    if (t < 0.0f) t = 0.0f;
    if (t > 1.0f) t = 1.0f;
    auto lerp = [&](int x, int y) { return (int)(x + (y - x) * t + 0.5f); };
    return RGB(lerp(GetRValue(a), GetRValue(b)),
               lerp(GetGValue(a), GetGValue(b)),
               lerp(GetBValue(a), GetBValue(b)));
}
// amount > 0 提亮，amount < 0 压暗
inline COLORREF ShadeColor(COLORREF c, float amount) {
    if (amount > 0.0f) return MixColor(c, RGB(255, 255, 255), amount);
    if (amount < 0.0f) return MixColor(c, RGB(0, 0, 0), -amount);
    return c;
}

// 返回在给定底色上可读性最好的文字色
inline COLORREF ContrastTextOn(COLORREF bg) {
    int lum = (GetRValue(bg) * 299 + GetGValue(bg) * 587 + GetBValue(bg) * 114) / 1000;
    return lum > 150 ? RGB(16, 18, 24) : RGB(255, 255, 255);
}

}} // namespace peanut::ui
