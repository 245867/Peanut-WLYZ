// ============================================================
// Peanut WLYZ — 主窗口实现 v7.0
// 暗黑主题 · 顶部导航 · 全局底部日志
// ============================================================

#include "main_window.h"
#include "win32_controls.h"
#include "card_dialogs.h"
#include "tcp_server.h"
#include "ui_icons.h"
#include "../PeanutClient/sdk/anti_debug.h"

#include <windowsx.h>
#include <commctrl.h>
#include <richedit.h>
#include <commdlg.h>
#include <shellapi.h>
#include <uxtheme.h>
#include <dwmapi.h>
#include <sstream>
#include <iomanip>
#include <ctime>
#include <cstdlib>
#include <algorithm>
#include <fstream>
#include <thread>
#include <memory>
#include <filesystem>

#include <nlohmann/json.hpp>
#include <wy_cipher.h>
#include <wy_hash.h>
#include <wy_random.h>
#include <wy_rsa.h>
#include <key_files.h>
#include <util.h>

#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "uxtheme.lib")
#pragma comment(lib, "gdiplus.lib")

#pragma comment(lib, "dwmapi.lib")
#pragma comment(linker,"\"/manifestdependency:type='win32' \
name='Microsoft.Windows.Common-Controls' version='6.0.0.0' \
processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'\"")

using namespace peanut::psp;
using namespace Gdiplus;
using namespace peanut_theme;

// ═══════════════════════════════════════════════════════════
//  全局实例 & 静态成员
// ═══════════════════════════════════════════════════════════
MainWindow* g_pMainWindow = nullptr;
// ═══════════════════════════════════════════════════════════
//  辅助函数: UTF-8 ? Wide
// ═══════════════════════════════════════════════════════════
static std::string wstring_to_utf8(const std::wstring& ws) {
    if (ws.empty()) return {};
    int len = WideCharToMultiByte(CP_UTF8, 0, ws.c_str(), (int)ws.size(), nullptr, 0, nullptr, nullptr);
    std::string s(len, 0);
    WideCharToMultiByte(CP_UTF8, 0, ws.c_str(), (int)ws.size(), &s[0], len, nullptr, nullptr);
    return s;
}
static std::wstring wstring_from_utf8(const std::string& s) {
    if (s.empty()) return L"";
    int len = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, nullptr, 0);
    if (len <= 0) return L"";
    std::vector<wchar_t> buf(len);
    MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, buf.data(), len);
    return buf.data();
}

static std::string utf8_from_wstring(const std::wstring& s) {
    if (s.empty()) return "";
    int len = WideCharToMultiByte(CP_UTF8, 0, s.c_str(), -1, nullptr, 0, nullptr, nullptr);
    if (len <= 0) return "";
    std::vector<char> buf(len);
    WideCharToMultiByte(CP_UTF8, 0, s.c_str(), -1, buf.data(), len, nullptr, nullptr);
    return buf.data();
}

namespace {
// (local plugin scanning is synchronous, no async messages needed)
} // namespace

// ═══════════════════════════════════════════════════════════
//  辅助: 创建控件并设置字体
// ═══════════════════════════════════════════════════════════
static HWND CreateControl(const wchar_t* className, const wchar_t* text,
                          DWORD style,
                          int x, int y, int w, int h,
                          HWND parent, HMENU id,
                          HFONT font = nullptr) {
    HWND hwnd = CreateWindowExW(0, className, text, style,
                                 x, y, w, h, parent, id,
                                 GetModuleHandle(nullptr), nullptr);
    if (hwnd && font) SendMessage(hwnd, WM_SETFONT, reinterpret_cast<WPARAM>(font), TRUE);
    return hwnd;
}

// ═══════════════════════════════════════════════════════════
//  美化绘制辅助 (GDI+ 圆角 / 渐变)
// ═══════════════════════════════════════════════════════════
namespace {

// 生成圆角矩形路径
void GpRoundPath(GraphicsPath& path, const RectF& r, float radius) {
    float d = radius * 2.0f;
    if (d > r.Width)  d = r.Width;
    if (d > r.Height) d = r.Height;
    if (d < 2.0f) { path.AddRectangle(r); return; }
    path.AddArc(r.X, r.Y, d, d, 180.0f, 90.0f);
    path.AddArc(r.X + r.Width - d, r.Y, d, d, 270.0f, 90.0f);
    path.AddArc(r.X + r.Width - d, r.Y + r.Height - d, d, d, 0.0f, 90.0f);
    path.AddArc(r.X, r.Y + r.Height - d, d, d, 90.0f, 90.0f);
    path.CloseFigure();
}

// 圆角矩形填充（top==bottom 时纯色，否则垂直渐变）+ 可选描边
void FillRoundRect(HDC hdc, const RECT& rc, float radius,
                   COLORREF top, COLORREF bottom,
                   bool border, COLORREF borderColor, float borderW) {
    RectF r((REAL)rc.left, (REAL)rc.top,
            (REAL)(rc.right - rc.left), (REAL)(rc.bottom - rc.top));
    if (r.Width <= 0.0f || r.Height <= 0.0f) return;

    Graphics g(hdc);
    g.SetSmoothingMode(SmoothingModeAntiAlias);
    GraphicsPath path;
    GpRoundPath(path, r, radius);

    Color c1 = peanut::ui::Gp(top), c2 = peanut::ui::Gp(bottom);
    if (top == bottom) {
        SolidBrush b(c1);
        g.FillPath(&b, &path);
    } else {
        LinearGradientBrush b(r, c1, c2, LinearGradientModeVertical);
        g.FillPath(&b, &path);
    }
    if (border) {
        Pen p(peanut::ui::Gp(borderColor), borderW);
        g.DrawPath(&p, &path);
    }
}

// 垂直渐变填充（直角）
void FillVGradient(HDC hdc, const RECT& rc, COLORREF top, COLORREF bottom) {
    RectF r((REAL)rc.left, (REAL)rc.top,
            (REAL)(rc.right - rc.left), (REAL)(rc.bottom - rc.top));
    if (r.Width <= 0.0f || r.Height <= 0.0f) return;
    Graphics g(hdc);
    if (top == bottom) {
        SolidBrush b(peanut::ui::Gp(top));
        g.FillRectangle(&b, r);
        return;
    }
    LinearGradientBrush b(r, peanut::ui::Gp(top), peanut::ui::Gp(bottom),
                          LinearGradientModeVertical);
    g.FillRectangle(&b, r);
}

// 水平渐变细线（用于强调分隔线）
void FillHGradientLine(HDC hdc, const RECT& rc, COLORREF left, COLORREF right) {
    RectF r((REAL)rc.left, (REAL)rc.top,
            (REAL)(rc.right - rc.left), (REAL)(rc.bottom - rc.top));
    if (r.Width <= 0.0f || r.Height <= 0.0f) return;
    Graphics g(hdc);
    LinearGradientBrush b(r, peanut::ui::Gp(left), peanut::ui::Gp(right),
                          LinearGradientModeHorizontal);
    g.FillRectangle(&b, r);
}

// ── 顶部导航栏高度（随皮肤变化）──────────────────────────
inline int NavH() { return peanut::ui::g_skin.navHeight; }

// 品牌区宽度：导航项从这里之后开始排布
const int kNavBrandW = 166;

// 展示型卡片为落影预留的内边距（卡片窗口比视觉卡片每侧大这么多）
const int kCardPad = 16;

// ── 柔和投影 ──────────────────────────────────────────────
// 由外向内叠加低透明度圆角矩形，形成自然衰减的落影。
// spread=扩散半径 dy=下偏移 alpha=边缘最大不透明度(0..1)
void DrawSoftShadow(HDC hdc, const RECT& rc, float radius,
                    int spread, int dy, float alpha) {
    if (spread <= 0 || alpha <= 0.004f) return;
    if (rc.right <= rc.left || rc.bottom <= rc.top) return;

    Graphics g(hdc);
    g.SetSmoothingMode(SmoothingModeAntiAlias);
    for (int i = spread; i >= 1; --i) {
        const float t = (float)i / (float)spread;      // 0=贴边 1=最外
        const float a = alpha * (1.0f - t) * (1.0f - t);
        if (a <= 0.004f) continue;

        RECT r = rc;
        r.left -= i; r.right += i;
        r.top  -= i; r.bottom += i;
        r.top  += dy; r.bottom += dy;

        RectF rf((REAL)r.left, (REAL)r.top,
                 (REAL)(r.right - r.left), (REAL)(r.bottom - r.top));
        GraphicsPath path;
        GpRoundPath(path, rf, radius + (float)i);
        SolidBrush b(Color((BYTE)(a * 255.0f + 0.5f), 0, 0, 0));
        g.FillPath(&b, &path);
    }
}

// ── 卡片面（投影 + 圆角面 + 主题描边）────────────────────
// elevated=true 使用抬升色（用于面板内的次级容器）
void DrawCardFace(HDC hdc, const RECT& rcFull, float radius,
                  bool shadow, bool elevated) {
    const auto& sk = peanut::ui::g_skin;
    if (radius < 0.0f) radius = sk.cardRadius;

    RECT card = rcFull;
    InflateRect(&card, -1, -1);
    if (card.right <= card.left || card.bottom <= card.top) return;

    if (shadow && sk.softShadow && sk.shadowAlpha > 0.004f)
        DrawSoftShadow(hdc, card, radius, sk.shadowSpread, sk.shadowOffsetY, sk.shadowAlpha);

    const COLORREF topC = elevated ? sk.bgElevated : sk.bgCard;
    const COLORREF botC = elevated ? sk.bgElevated : sk.bgCard2;
    const COLORREF brd  = peanut::ui::MixColor(sk.border, topC, 1.0f - sk.cardBorderAlpha);
    FillRoundRect(hdc, card, radius, topC, botC, true, brd, 1.0f);
}

// ── 卡片强调条（在卡片圆角内裁切）────────────────────────
// side: 0=顶部 1=左侧
void DrawCardAccentBar(HDC hdc, const RECT& rcFull, float radius,
                       int side, COLORREF c1, COLORREF c2, int thickness) {
    RECT card = rcFull;
    InflateRect(&card, -1, -1);
    if (card.right <= card.left || card.bottom <= card.top) return;

    Graphics g(hdc);
    g.SetSmoothingMode(SmoothingModeAntiAlias);
    RectF rf((REAL)card.left, (REAL)card.top,
             (REAL)(card.right - card.left), (REAL)(card.bottom - card.top));
    GraphicsPath clip;
    GpRoundPath(clip, rf, radius);
    g.SetClip(&clip);

    if (side == 0) {
        RectF bar(rf.X, rf.Y, rf.Width, (REAL)thickness);
        LinearGradientBrush lb(bar, peanut::ui::Gp(c1), peanut::ui::Gp(c2),
                               LinearGradientModeHorizontal);
        g.FillRectangle(&lb, bar);
    } else {
        RectF bar(rf.X, rf.Y, (REAL)thickness, rf.Height);
        LinearGradientBrush lb(bar, peanut::ui::Gp(c1), peanut::ui::Gp(c2, 70),
                               LinearGradientModeVertical);
        g.FillRectangle(&lb, bar);
    }
    g.ResetClip();
}

// ── 图标容器：柔光底 + 居中矢量图标 ──────────────────────
void DrawIconChip(HDC hdc, const RECT& rc, const wchar_t* icon,
                  float radius, float iconScale = 0.52f) {
    const auto& sk = peanut::ui::g_skin;
    FillRoundRect(hdc, rc, radius, sk.accentSoft, sk.accentSoft, false, 0, 0);

    const int w = rc.right - rc.left, h = rc.bottom - rc.top;
    const float side = (std::min)(w, h) * iconScale;
    const float cx = rc.left + (w - side) * 0.5f;
    const float cy = rc.top  + (h - side) * 0.5f;
    Graphics g(hdc);
    peanut::ui::DrawIcon(g, icon, RectF(cx, cy, side, side),
                         peanut::ui::Gp(sk.accent), 1.9f);
}

// ═══════════════════════════════════════════════════════════
//  按钮角色体系
//  形状/颜色不再由单个控件决定，而是由"语义角色"决定：
//    primary   主操作，一屏最多一个 → 实心强调色 + 反白字
//    secondary 常规操作             → 卡片面 + 细描边
//    ghost     辅助/工具按钮        → 无底无框，悬停才出现柔光底
//    danger    破坏性操作           → 危险色浅底，悬停加深
//    toggle    开关                 → 胶囊 + 状态圆点
// ═══════════════════════════════════════════════════════════
enum BtnRole {
    BTN_SECONDARY = 0,
    BTN_PRIMARY   = 1,
    BTN_DANGER    = 2,
    BTN_GHOST     = 3,
    BTN_TOGGLE    = 4
};

inline void SetBtnRole(HWND h, int role) {
    if (h) SetPropW(h, L"ph_role",
                    reinterpret_cast<HANDLE>(static_cast<INT_PTR>(role)));
}
inline int GetBtnRole(HWND h) {
    if (!h) return BTN_SECONDARY;
    return static_cast<int>(reinterpret_cast<INT_PTR>(GetPropW(h, L"ph_role")));
}
inline void SetBtnAccent(HWND h, COLORREF c) {
    if (h) SetPropW(h, L"ph_accent",
                    reinterpret_cast<HANDLE>(static_cast<INT_PTR>(c)));
}
inline COLORREF GetBtnAccent(HWND h, COLORREF def) {
    HANDLE v = h ? GetPropW(h, L"ph_accent") : nullptr;
    return v ? static_cast<COLORREF>(reinterpret_cast<INT_PTR>(v)) : def;
}
// toggle 角色的选中态（BS_PUSHBUTTON 无内建 check 状态，用属性承载）
inline void SetBtnChecked(HWND h, bool on) {
    if (!h) return;
    if (on) SetPropW(h, L"ph_checked", reinterpret_cast<HANDLE>(1));
    else    RemovePropW(h, L"ph_checked");
}
// 按钮左侧矢量图标（name 为字面量，生命周期同进程）
inline void SetBtnIcon(HWND h, const wchar_t* name) {
    if (h) SetPropW(h, L"ph_icon",
                    reinterpret_cast<HANDLE>(const_cast<wchar_t*>(name)));
}
inline const wchar_t* GetBtnIcon(HWND h) {
    return h ? reinterpret_cast<const wchar_t*>(GetPropW(h, L"ph_icon")) : nullptr;
}

// ── 文本控件的文字色 ─────────────────────────────────────
// 默认全部 TEXT_PRIMARY 会让标题/数值/说明混成一片，
// 因此允许逐个控件指定前景色，形成排版层级。
inline void SetCtrlFg(HWND h, COLORREF c) {
    if (h) SetPropW(h, L"ph_fg",
                    reinterpret_cast<HANDLE>(static_cast<INT_PTR>(c)));
}
inline COLORREF GetCtrlFg(HWND h, COLORREF def) {
    HANDLE v = h ? GetPropW(h, L"ph_fg") : nullptr;
    return v ? static_cast<COLORREF>(reinterpret_cast<INT_PTR>(v)) : def;
}

// 自绘按钮。surface = 按钮所在容器的底色，用于填充圆角矩形之外的像素。
void DrawOwnerButton(HDC hdc, HWND hwnd, const RECT& rcItem, UINT itemState,
                     COLORREF surface, HFONT font) {
    const auto& sk = peanut::ui::g_skin;
    const bool pressed  = (itemState & ODS_SELECTED) != 0;
    const bool disabled = (itemState & ODS_DISABLED) != 0;
    const bool hovered  = GetPropW(hwnd, L"ph_hover") != nullptr;
    const int  role     = GetBtnRole(hwnd);
    const COLORREF accent = GetBtnAccent(hwnd, ACCENT);

    HBRUSH surfBr = CreateSolidBrush(surface);
    FillRect(hdc, &rcItem, surfBr);
    DeleteObject(surfBr);

    RECT rc = rcItem;
    COLORREF topC = surface, botC = surface, borderClr = 0, fg = TEXT_PRIMARY;
    bool drawBorder = false;
    int textInsetLeft = 0;

    switch (role) {
    case BTN_PRIMARY: {
        COLORREF base = disabled ? peanut::ui::MixColor(accent, surface, 0.78f) : accent;
        if (disabled) {
            topC = botC = base;
            borderClr = peanut::ui::MixColor(accent, surface, 0.62f);
            fg = peanut::ui::MixColor(peanut::ui::ContrastTextOn(accent), surface, 0.45f);
        } else if (pressed) {
            topC = peanut::ui::ShadeColor(base, -0.10f);
            botC = peanut::ui::ShadeColor(base, -0.20f);
            borderClr = peanut::ui::ShadeColor(base, -0.24f);
            fg = peanut::ui::ContrastTextOn(base);
        } else if (hovered) {
            topC = peanut::ui::ShadeColor(base,  0.12f);
            botC = peanut::ui::ShadeColor(base, -0.02f);
            borderClr = peanut::ui::ShadeColor(base,  0.30f);
            fg = peanut::ui::ContrastTextOn(base);
        } else {
            topC = peanut::ui::ShadeColor(base,  0.05f);
            botC = peanut::ui::ShadeColor(base, -0.12f);
            borderClr = peanut::ui::ShadeColor(base,  0.20f);
            fg = peanut::ui::ContrastTextOn(base);
        }
        drawBorder = true;
        break;
    }
    case BTN_DANGER: {
        const COLORREF danger = ERROR_COLOR;
        if (disabled) {
            topC = botC = surface;
            borderClr = peanut::ui::MixColor(danger, surface, 0.72f);
            fg = TEXT_MUTED;
        } else if (pressed || hovered) {
            topC = borderClr = peanut::ui::ShadeColor(danger, pressed ? -0.14f : -0.04f);
            botC = peanut::ui::ShadeColor(danger, -0.14f);
            fg = peanut::ui::ContrastTextOn(danger);
        } else {
            topC = botC = peanut::ui::MixColor(danger, surface, 0.88f);
            borderClr = peanut::ui::MixColor(danger, surface, 0.42f);
            fg = danger;
        }
        drawBorder = true;
        break;
    }
    case BTN_GHOST: {
        if (disabled) {
            fg = TEXT_MUTED;
        } else if (pressed) {
            topC = botC = peanut::ui::MixColor(accent, surface, 0.80f);
            borderClr = peanut::ui::MixColor(accent, surface, 0.55f);
            fg = accent;
            drawBorder = true;
        } else if (hovered) {
            topC = botC = peanut::ui::MixColor(accent, surface, 0.86f);
            borderClr = peanut::ui::MixColor(accent, surface, 0.62f);
            fg = accent;
            drawBorder = true;
        } else {
            fg = TEXT_SECONDARY;
        }
        break;
    }
    case BTN_TOGGLE: {
        const bool on = GetPropW(hwnd, L"ph_checked") != nullptr;
        if (on) {
            topC = botC = peanut::ui::MixColor(accent, surface, hovered ? 0.78f : 0.84f);
            borderClr = peanut::ui::MixColor(accent, surface, 0.48f);
            fg = accent;
        } else {
            topC = botC = peanut::ui::ShadeColor(surface, sk.light ? -0.05f : 0.10f);
            borderClr = peanut::ui::MixColor(BORDER, surface, 0.15f);
            fg = hovered ? TEXT_PRIMARY : TEXT_SECONDARY;
        }
        drawBorder = true;
        textInsetLeft = 22;
        break;
    }
    default: { // BTN_SECONDARY
        if (disabled) {
            topC = botC = BG_INPUT;
            borderClr = BORDER;
            fg = TEXT_MUTED;
        } else if (pressed) {
            topC = peanut::ui::ShadeColor(BG_CARD, sk.light ? -0.10f : 0.04f);
            botC = peanut::ui::ShadeColor(BG_CARD2, sk.light ? -0.12f : 0.02f);
            borderClr = ACCENT;
            fg = ACCENT;
        } else if (hovered) {
            topC = peanut::ui::ShadeColor(BG_CARD, sk.light ? -0.04f : 0.12f);
            botC = peanut::ui::ShadeColor(BG_CARD2, sk.light ? -0.06f : 0.10f);
            borderClr = ACCENT;
            fg = ACCENT;
        } else {
            if (sk.light) {
                topC = peanut::ui::ShadeColor(BG_CARD, -0.05f);
                botC = peanut::ui::ShadeColor(BG_CARD2, -0.07f);
                borderClr = sk.border;
            } else {
                topC = BG_CARD;
                botC = BG_CARD2;
                borderClr = peanut::ui::ShadeColor(BG_CARD2, 0.18f);
            }
            fg = TEXT_PRIMARY;
        }
        drawBorder = true;
        break;
    }
    }

    // 实心按钮略窄一点，避免与容器边缘贴合显得拥挤
    if (role == BTN_PRIMARY || role == BTN_DANGER) {
        InflateRect(&rc, -1, -1);
    }

    if (rc.right - rc.left > 2 && rc.bottom - rc.top > 2) {
        FillRoundRect(hdc, rc, sk.btnRadius, topC, botC, drawBorder, borderClr, 1.0f);
    }

    // toggle 状态圆点：开=实心，关=空心环
    if (role == BTN_TOGGLE && !disabled) {
        const bool on = GetPropW(hwnd, L"ph_checked") != nullptr;
        const int cy = (rc.top + rc.bottom) / 2;
        const int cx = rc.left + 13;
        HBRUSH fill = on ? CreateSolidBrush(fg)
                         : static_cast<HBRUSH>(GetStockObject(NULL_BRUSH));
        HPEN   pen  = CreatePen(PS_SOLID, on ? 1 : 2, fg);
        HGDIOBJ ob = SelectObject(hdc, fill);
        HGDIOBJ op = SelectObject(hdc, pen);
        Ellipse(hdc, cx - 4, cy - 4, cx + 4, cy + 4);
        SelectObject(hdc, ob);
        SelectObject(hdc, op);
        DeleteObject(pen);
        if (on) DeleteObject(fill);
    }

    wchar_t buf[128] = {};
    GetWindowTextW(hwnd, buf, 128);
    const wchar_t* icon = GetBtnIcon(hwnd);
    SetBkMode(hdc, TRANSPARENT);
    SetTextColor(hdc, fg);
    HFONT oldFont = nullptr;
    if (font) oldFont = static_cast<HFONT>(SelectObject(hdc, font));

    RECT tr = rc;
    tr.left += textInsetLeft;

    // 带图标的按钮：图标 + 文字作为一组整体居中
    if (icon && icon[0]) {
        SIZE ts = { 0, 0 };
        GetTextExtentPoint32W(hdc, buf, static_cast<int>(wcslen(buf)), &ts);
        const int isz = 16, gap = 8;
        int x0 = rc.left + (rc.right - rc.left - (isz + gap + ts.cx)) / 2;
        if (x0 < rc.left + 8) x0 = rc.left + 8;
        const int cy = (rc.top + rc.bottom) / 2 - isz / 2;
        Graphics g(hdc);
        peanut::ui::DrawIcon(g, icon, RectF((REAL)x0, (REAL)cy,
                                            (REAL)isz, (REAL)isz),
                             peanut::ui::Gp(fg), 1.9f);
        tr.left = x0 + isz + gap;
        tr.right = rc.right - 6;
        DrawTextW(hdc, buf, -1, &tr,
                  DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS);
    } else {
        const UINT flags = (textInsetLeft > 0 ? DT_LEFT : DT_CENTER)
                         | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS;
        DrawTextW(hdc, buf, -1, &tr, flags);
    }
    if (oldFont) SelectObject(hdc, oldFont);
}

} // namespace

// ═══════════════════════════════════════════════════════════
//  构造 / 析构
// ═══════════════════════════════════════════════════════════
MainWindow::MainWindow(HINSTANCE hInst) : hInst_(hInst) {
    g_pMainWindow = this;

    // 初始化 GDI+
    GdiplusStartupInput gdiInput;
    GdiplusStartup(&gdiplusToken_, &gdiInput, nullptr);

    // 画刷
    hBrushBg_      = CreateSolidBrush(BG_DEEP);
    hBrushSidebar_ = CreateSolidBrush(BG_TOPNAV);
    hBrushLog_     = CreateSolidBrush(BG_LOG);
    hBrushCard_    = CreateSolidBrush(BG_CARD);
    hBrushInput_   = CreateSolidBrush(BG_INPUT);
    hPenBorder_    = CreatePen(PS_SOLID, 1, BORDER);
    hPenAccent_    = CreatePen(PS_SOLID, 2, ACCENT);

    CreateFonts();

    psp_encoder_ = std::make_unique<Encoder>();
    psp_encoder_->set_psk_hex(config_.psp_key_hex);
    // 加载 RSA 公钥
    {
        wy::wy_rsa_pubkey pub;
        if (peanut::keys::LoadServerPubkey("keys", pub)) {
            config_.rsa_pubkey_hex = wy::wy_rsa_pubkey_to_hex(&pub);
            psp_encoder_->set_rsa_pubkey_hex(config_.rsa_pubkey_hex);
        }
    }
}

MainWindow::~MainWindow() {
    if (hFontDefault_)      DeleteObject(hFontDefault_);
    if (hFontCardKey_)      DeleteObject(hFontCardKey_);
    if (hFontLog_)          DeleteObject(hFontLog_);
    if (hFontTitle_)        DeleteObject(hFontTitle_);
    if (hFontSidebar_)      DeleteObject(hFontSidebar_);
    if (hFontStatValue_)    DeleteObject(hFontStatValue_);
    if (hFontStatTitle_)    DeleteObject(hFontStatTitle_);
    if (hFontLabel_)        DeleteObject(hFontLabel_);
    if (hFontButton_)       DeleteObject(hFontButton_);
    if (hFontHeader_)       DeleteObject(hFontHeader_);
    if (hFontSectionTitle_) DeleteObject(hFontSectionTitle_);
    if (hFontNav_)          DeleteObject(hFontNav_);
    if (hFontBrand_)        DeleteObject(hFontBrand_);
    if (hFontBadge_)        DeleteObject(hFontBadge_);
    if (hFontStatSub_)      DeleteObject(hFontStatSub_);

    if (hBrushBg_)      DeleteObject(hBrushBg_);
    if (hBrushSidebar_) DeleteObject(hBrushSidebar_);
    if (hBrushLog_)     DeleteObject(hBrushLog_);
    if (hBrushCard_)    DeleteObject(hBrushCard_);
    if (hBrushInput_)   DeleteObject(hBrushInput_);
    if (hPenBorder_)    DeleteObject(hPenBorder_);
    if (hPenAccent_)    DeleteObject(hPenAccent_);

    GdiplusShutdown(gdiplusToken_);
}

void MainWindow::CreateFonts() {
    auto makeFont = [](int height, int weight, const wchar_t* face) -> HFONT {
        return CreateFontW(height, 0, 0, 0, weight, FALSE, FALSE, FALSE,
                           DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                           CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_SWISS, face);
    };

    const wchar_t* fam  = peanut::ui::g_skin.family;
    const wchar_t* mono = peanut::ui::g_skin.mono;

    // 字号层级：title(24) > brand(20) > section(20)
    //          > body/nav/button/table/label(18)
    //          > cardKey/sidebar/header(17) > statValue(30) > badge(15)
    //          > statTitle(14) > statSub(12)
    hFontDefault_      = makeFont(18, FW_NORMAL,   fam);
    hFontLog_          = makeFont(16, FW_NORMAL,   mono);
    hFontCardKey_      = makeFont(17, FW_NORMAL,   mono);
    hFontSidebar_      = makeFont(17, FW_NORMAL,   fam);
    hFontNav_          = makeFont(18, FW_SEMIBOLD, fam);
    hFontBrand_        = makeFont(20, FW_BOLD,     fam);
    hFontBadge_        = makeFont(15, FW_SEMIBOLD, fam);
    hFontHeader_       = makeFont(17, FW_SEMIBOLD, fam);
    hFontTitle_        = makeFont(24, FW_BOLD,     fam);
    // KPI 卡片改紧凑布局（卡高 118，原 176），字号随之下调一档
    hFontStatValue_    = makeFont(30, FW_BOLD,     fam);
    hFontStatTitle_    = makeFont(14, FW_NORMAL,   fam);
    hFontStatSub_      = makeFont(12, FW_NORMAL,   fam);
    hFontLabel_        = makeFont(18, FW_NORMAL,   fam);
    hFontButton_       = makeFont(18, FW_NORMAL,   fam);
    hFontSectionTitle_ = makeFont(20, FW_SEMIBOLD, fam);
}

// ═══════════════════════════════════════════════════════════
//  窗口创建 & 运行
// ═══════════════════════════════════════════════════════════
static const wchar_t* WND_CLASS = L"PeanutWLYZ_MainWindow_v7";

bool MainWindow::Create(int nCmdShow) {
    w32::InitCommon();

    WNDCLASSEXW wcex = {};
    wcex.cbSize        = sizeof(WNDCLASSEXW);
    wcex.style         = CS_HREDRAW | CS_VREDRAW;
    wcex.lpfnWndProc   = WndProc;
    wcex.hInstance     = hInst_;
    wcex.hIcon         = LoadIcon(nullptr, IDI_APPLICATION);
    wcex.hCursor       = LoadCursor(nullptr, IDC_ARROW);
    wcex.hbrBackground = hBrushBg_;
    wcex.lpszClassName = WND_CLASS;
    wcex.hIconSm       = LoadIcon(nullptr, IDI_APPLICATION);

    if (!RegisterClassExW(&wcex)) return false;

    // 先读 ini，创建窗口时用记忆的位置/大小
    LoadConfig();

    int wx = config_.window_x;
    int wy = config_.window_y;
    constexpr int fixedClientW = 896;
    constexpr int fixedClientH = 672;
    constexpr DWORD fixedWindowStyle = WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX;
    RECT fixedRect{0, 0, fixedClientW, fixedClientH};
    AdjustWindowRectEx(&fixedRect, fixedWindowStyle, FALSE, 0);
    int ww = fixedRect.right - fixedRect.left;
    int wh = fixedRect.bottom - fixedRect.top;
    if (wx == CW_USEDEFAULT) wy = CW_USEDEFAULT;

    // 传入 this：WM_NCCREATE/WM_CREATE 发生在 CreateWindow 返回前，必须此时绑定 hwnd
    std::wstring title = L"Peanut Soft Protect 2026-7-26  ·  ";
    title += peanut::ui::g_skin.name;

    hwndMain_ = CreateWindowExW(
        0, WND_CLASS, title.c_str(),
        fixedWindowStyle,
        wx, wy, ww, wh,
        nullptr, nullptr, hInst_, this
    );

    if (!hwndMain_) return false;

    // Win10/11 沉浸式暗色（标题栏/部分滚动条）：亮色皮肤关闭
    BOOL dark = peanut::ui::g_skin.light ? FALSE : TRUE;
    DwmSetWindowAttribute(hwndMain_, 20 /* DWMWA_USE_IMMERSIVE_DARK_MODE */, &dark, sizeof(dark));

    // 兜底：若 WM_CREATE 未走到 OnCreate（历史 bug），在此补建 UI
    if (!hwndTopNav_) {
        OnCreate();
    }

    ShowWindow(hwndMain_, nCmdShow);
    UpdateWindow(hwndMain_);
    return true;
}

void MainWindow::Run() {
    MSG msg;
    while (GetMessage(&msg, nullptr, 0, 0)) {
        if (!IsDialogMessage(hwndMain_, &msg)) {
            TranslateMessage(&msg);
            DispatchMessage(&msg);
        }
    }
}

// ═══════════════════════════════════════════════════════════
//  静态窗口过程
// ═══════════════════════════════════════════════════════════
LRESULT CALLBACK MainWindow::WndProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    if (msg == WM_NCCREATE) {
        auto* cs = reinterpret_cast<CREATESTRUCTW*>(lp);
        auto* self = static_cast<MainWindow*>(cs->lpCreateParams);
        if (!self) return FALSE;
        self->hwndMain_ = hwnd;
        SetWindowLongPtrW(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(self));
        return DefWindowProcW(hwnd, msg, wp, lp);
    }

    auto* self = reinterpret_cast<MainWindow*>(GetWindowLongPtrW(hwnd, GWLP_USERDATA));
    if (!self)
        return DefWindowProcW(hwnd, msg, wp, lp);
    return self->HandleMessage(msg, wp, lp);
}

// ═══════════════════════════════════════════════════════════
//  暗色父窗口子类化（子控件的 CTLCOLOR 发给父窗口，非主窗）
// ═══════════════════════════════════════════════════════════
// 自绘按钮 hover 追踪：进出时刷新，让按钮有悬停反馈
LRESULT CALLBACK MainWindow::BtnHoverProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp,
                                          UINT_PTR idSubclass, DWORD_PTR refData) {
    switch (msg) {
    case WM_MOUSEMOVE:
        if (!GetPropW(hwnd, L"ph_hover")) {
            SetPropW(hwnd, L"ph_hover", reinterpret_cast<HANDLE>(1));
            TRACKMOUSEEVENT tme = {};
            tme.cbSize = sizeof(tme);
            tme.dwFlags = TME_LEAVE;
            tme.hwndTrack = hwnd;
            TrackMouseEvent(&tme);
            InvalidateRect(hwnd, nullptr, FALSE);
        }
        break;
    case WM_MOUSELEAVE:
        RemovePropW(hwnd, L"ph_hover");
        InvalidateRect(hwnd, nullptr, FALSE);
        break;
    case WM_NCDESTROY:
        RemovePropW(hwnd, L"ph_hover");
        break;
    default:
        break;
    }
    return DefSubclassProc(hwnd, msg, wp, lp);
}

// 亮色皮肤下统一 Edit 边框为主题色，去掉系统的硬黑边（只动非客户区，不影响文本）
LRESULT CALLBACK MainWindow::EditBorderProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp,
                                            UINT_PTR idSubclass, DWORD_PTR refData) {
    if (msg == WM_NCPAINT && peanut::ui::g_skin.light) {
        RECT wr, cr;
        GetWindowRect(hwnd, &wr);
        GetClientRect(hwnd, &cr);
        const int w  = wr.right - wr.left;
        const int h  = wr.bottom - wr.top;
        const int bw = (w - (cr.right - cr.left)) / 2;
        if (bw > 0 && h > bw * 2) {
            HDC dc = GetWindowDC(hwnd);
            if (dc) {
                HBRUSH b = CreateSolidBrush(BORDER);
                RECT r = { 0, 0, w, bw };
                FillRect(dc, &r, b);
                r.top = h - bw; r.bottom = h;
                FillRect(dc, &r, b);
                r = { 0, bw, bw, h - bw };
                FillRect(dc, &r, b);
                r = { w - bw, bw, w, h - bw };
                FillRect(dc, &r, b);
                DeleteObject(b);
                ReleaseDC(hwnd, dc);
            }
        }
        return 0;
    }
    return DefSubclassProc(hwnd, msg, wp, lp);
}

// 卡密列表行悬停：只跟踪鼠标、刷新高亮行，不接管任何绘制
LRESULT CALLBACK MainWindow::ListHoverProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp,
                                           UINT_PTR, DWORD_PTR) {
    auto* self = g_pMainWindow;
    if (self) {
        if (msg == WM_MOUSEMOVE) {
            LVHITTESTINFO ht = {};
            ht.pt.x = GET_X_LPARAM(lp);
            ht.pt.y = GET_Y_LPARAM(lp);
            ListView_SubItemHitTest(hwnd, &ht);
            const int hot = ht.iItem;
            if (hot != self->cardListHot_) {
                self->cardListHot_ = hot;
                InvalidateRect(hwnd, nullptr, FALSE);
            }
            TRACKMOUSEEVENT tme = { sizeof(tme), TME_LEAVE, hwnd, 0 };
            TrackMouseEvent(&tme);
        } else if (msg == WM_MOUSELEAVE) {
            if (self->cardListHot_ != -1) {
                self->cardListHot_ = -1;
                InvalidateRect(hwnd, nullptr, FALSE);
            }
        }
    }
    return DefSubclassProc(hwnd, msg, wp, lp);
}

LRESULT CALLBACK MainWindow::DarkParentProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp,
                                             UINT_PTR, DWORD_PTR) {
    auto* self = g_pMainWindow;
    if (!self) return DefSubclassProc(hwnd, msg, wp, lp);

    switch (msg) {
        case WM_MOUSEWHEEL:
            // 设置页：滚轮（含落在分组卡片上的滚轮）滚动整页
            if (self->hwndPanelSettings_ &&
                (hwnd == self->hwndPanelSettings_ ||
                 IsChild(self->hwndPanelSettings_, hwnd))) {
                const int notches = GET_WHEEL_DELTA_WPARAM(wp) / WHEEL_DELTA;
                self->ScrollSettings(-notches * 56);
                return 0;
            }
            break;

        case WM_COMMAND:
            // 子面板上的按钮/单选的 BN_CLICKED 发给父面板，需转到主窗处理
            if (self->hwndMain_) {
                self->OnCommand(wp);
                return 0;
            }
            break;

        case WM_NOTIFY:
            if (self->hwndMain_)
                return SendMessageW(self->hwndMain_, WM_NOTIFY, wp, lp);
            break;

        case WM_DRAWITEM:
            // 子控件 OWNERDRAW 发给父面板，必须转给主窗绘制
            self->OnDrawItem(wp, lp);
            return TRUE;

        case WM_MEASUREITEM: {
            auto* mis = reinterpret_cast<LPMEASUREITEMSTRUCT>(lp);
            if (mis && mis->CtlType == ODT_COMBOBOX) {
                mis->itemHeight = 26;
                return TRUE;
            }
            break;
        }

        case WM_PAINT: {
            // SS_OWNERDRAW 由父窗口 DRAWITEM 绘制，勿在此盖一层
            const LONG style = GetWindowLongW(hwnd, GWL_STYLE);
            if ((style & SS_OWNERDRAW) == SS_OWNERDRAW)
                return DefSubclassProc(hwnd, msg, wp, lp);

            PAINTSTRUCT ps;
            HDC hdc = BeginPaint(hwnd, &ps);
            RECT rc;
            GetClientRect(hwnd, &rc);
            if (hwnd == self->hwndTopNav_) {
                const auto& sk = peanut::ui::g_skin;
                FillVGradient(hdc, rc, BG_TOPNAV, BG_TOPNAV2);

                // ── 品牌标识区：渐变 logo 方块 + 产品名 + 皮肤副标 ──
                {
                    const int chipS = 28;
                    const int chipX = 14;
                    const int chipY = (rc.bottom - chipS) / 2;
                    {
                        Graphics g(hdc);
                        g.SetSmoothingMode(SmoothingModeAntiAlias);
                        RectF chip((REAL)chipX, (REAL)chipY, (REAL)chipS, (REAL)chipS);
                        LinearGradientBrush lb(chip, peanut::ui::Gp(sk.accent),
                                               peanut::ui::Gp(sk.accent2),
                                               LinearGradientModeForwardDiagonal);
                        GraphicsPath cp;
                        GpRoundPath(cp, chip, 10.0f);
                        g.FillPath(&lb, &cp);
                        peanut::ui::DrawIcon(g, L"logo",
                            RectF(chip.X + 7.0f, chip.Y + 7.0f, 14.0f, 14.0f),
                            Color(255, 255, 255), 1.6f);
                    }

                    SetBkMode(hdc, TRANSPARENT);
                    SetTextColor(hdc, TEXT_PRIMARY);
                    HFONT oldB = static_cast<HFONT>(SelectObject(hdc, self->hFontBrand_));
                    RECT tr = { chipX + chipS + 8, chipY - 4, kNavBrandW - 10, chipY + 16 };
                    DrawTextW(hdc, L"Peanut", -1, &tr,
                              DT_LEFT | DT_VCENTER | DT_SINGLELINE);
                    if (oldB) SelectObject(hdc, oldB);

                    SetTextColor(hdc, sk.textMuted);
                    HFONT oldS = static_cast<HFONT>(SelectObject(hdc, self->hFontBadge_));
                    RECT sr = { chipX + chipS + 9, chipY + 15, kNavBrandW - 10, chipY + 30 };
                    DrawTextW(hdc, sk.name, -1, &sr,
                              DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS);
                    if (oldS) SelectObject(hdc, oldS);

                    // 品牌区与导航区之间的竖分隔
                    RECT vs = { kNavBrandW - 12, rc.top + 14, kNavBrandW - 11, rc.bottom - 14 };
                    FillRect(hdc, &vs, self->hBrushInput_);
                }

                if (peanut::ui::g_skin.navDivider && rc.bottom >= 2) {
                    RECT ln = { rc.left, rc.bottom - 1, rc.right, rc.bottom };
                    FillHGradientLine(hdc, ln, ACCENT, ACCENT2);
                }
            } else if (hwnd == self->hwndPanelLogs_) {
                FillRect(hdc, &rc, self->hBrushLog_);
                // 头部：左侧强调圆点 + 下方细分割线，把"标题条"从日志流里分出来
                const int hdrH = 34;
                const int cy = hdrH / 2;
                HBRUSH dot = CreateSolidBrush(ACCENT);
                HGDIOBJ ob = SelectObject(hdc, dot);
                HGDIOBJ op = SelectObject(hdc, GetStockObject(NULL_PEN));
                Ellipse(hdc, 14, cy - 4, 22, cy + 4);
                SelectObject(hdc, ob);
                SelectObject(hdc, op);
                DeleteObject(dot);

                RECT ln = { 0, hdrH, rc.right, hdrH + 1 };
                FillRect(hdc, &ln, self->hBrushInput_);
            } else {
                FillRect(hdc, &rc, self->hBrushBg_);
            }
            EndPaint(hwnd, &ps);
            return 0;
        }

        case WM_CTLCOLORSTATIC:
        case WM_CTLCOLOREDIT:
        case WM_CTLCOLORLISTBOX:
        case WM_CTLCOLORBTN: {
            HDC hdc = reinterpret_cast<HDC>(wp);
            HWND child = reinterpret_cast<HWND>(lp);
            const bool isLog = (hwnd == self->hwndPanelLogs_);
            const bool isTop = (hwnd == self->hwndTopNav_);
            // 卡片容器（统计卡 / 快捷面板 / 运行概览卡 / 风控卡）内的文字控件需与卡片底色一致
            bool isCardSurface = (hwnd == self->hwndFwRuleCard_ ||
                                  hwnd == self->hwndDashQuickPanel_ ||
                                  hwnd == self->hwndDashOverviewPanel_);
            if (!isCardSurface) {
                for (auto& sc : self->statCards_) {
                    if (sc.hwndPanel == hwnd) { isCardSurface = true; break; }
                }
            }
            COLORREF bg = isLog ? BG_LOG
                        : (isTop ? BG_TOPNAV
                        : (isCardSurface ? BG_CARD : BG_DEEP));
            HBRUSH brush = isLog ? self->hBrushLog_
                          : (isTop ? self->hBrushSidebar_
                          : (isCardSurface ? self->hBrushCard_ : self->hBrushBg_));

            if (msg == WM_CTLCOLOREDIT) {
                bg = isLog ? BG_LOG : (isCardSurface ? BG_CARD : BG_INPUT);
                brush = isLog ? self->hBrushLog_ : (isCardSurface ? self->hBrushCard_ : self->hBrushInput_);
            }
            SetBkMode(hdc, OPAQUE);
            SetBkColor(hdc, bg);
            SetTextColor(hdc, GetCtrlFg(child, TEXT_PRIMARY));
            return reinterpret_cast<LRESULT>(brush);
        }
        case WM_ERASEBKGND:
            return 1;
    }
    return DefSubclassProc(hwnd, msg, wp, lp);
}

// ═══════════════════════════════════════════════════════════
//  ListView 表头暗色
// ═══════════════════════════════════════════════════════════
LRESULT CALLBACK MainWindow::DarkHeaderProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp,
                                             UINT_PTR, DWORD_PTR) {
    auto* self = g_pMainWindow;
    if (!self) return DefSubclassProc(hwnd, msg, wp, lp);

    switch (msg) {
        case WM_ERASEBKGND:
            return 1;
        case WM_PAINT: {
            PAINTSTRUCT ps;
            HDC hdc = BeginPaint(hwnd, &ps);
            RECT rc;
            GetClientRect(hwnd, &rc);
            FillVGradient(hdc, rc, BG_HEADER, peanut::ui::MixColor(BG_HEADER, BG_DEEP, 0.30f));
            if (rc.bottom >= 2) {
                RECT ln = { rc.left, rc.bottom - 1, rc.right, rc.bottom };
                FillHGradientLine(hdc, ln, ACCENT, DIVIDER);
            }

            HPEN pen = CreatePen(PS_SOLID, 1, DIVIDER);
            HPEN oldPen = static_cast<HPEN>(SelectObject(hdc, pen));

            SetBkMode(hdc, TRANSPARENT);
            SetTextColor(hdc, TEXT_SECONDARY);
            HFONT oldFont = self->hFontHeader_
                ? static_cast<HFONT>(SelectObject(hdc, self->hFontHeader_)) : nullptr;

            const int count = Header_GetItemCount(hwnd);
            for (int i = 0; i < count; ++i) {
                RECT ir = {};
                Header_GetItemRect(hwnd, i, &ir);
                wchar_t text[128] = {};
                HDITEMW item = {};
                item.mask = HDI_TEXT;
                item.pszText = text;
                item.cchTextMax = 128;
                Header_GetItem(hwnd, i, &item);
                ir.left += 8;
                DrawTextW(hdc, text, -1, &ir,
                          DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS);
                MoveToEx(hdc, ir.right - 1, rc.top + 4, nullptr);
                LineTo(hdc, ir.right - 1, rc.bottom - 4);
            }

            if (oldFont) SelectObject(hdc, oldFont);
            SelectObject(hdc, oldPen);
            DeleteObject(pen);
            EndPaint(hwnd, &ps);
            return 0;
        }
    }
    return DefSubclassProc(hwnd, msg, wp, lp);
}

// ═══════════════════════════════════════════════════════════
//  顶部导航按钮子类化
// ═══════════════════════════════════════════════════════════
LRESULT CALLBACK MainWindow::NavBtnProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp,
                                          UINT_PTR idSubclass, DWORD_PTR) {
    auto* self = g_pMainWindow;
    if (!self) return DefSubclassProc(hwnd, msg, wp, lp);

    switch (msg) {
        case WM_PAINT: {
            PAINTSTRUCT ps;
            HDC hdc = BeginPaint(hwnd, &ps);
            RECT rc;
            GetClientRect(hwnd, &rc);

            NavButton* btn = nullptr;
            for (auto& b : self->navButtons_) {
                if (b.hwnd == hwnd) { btn = &b; break; }
            }
            const auto& sk = peanut::ui::g_skin;
            const bool active = btn && btn->isActive;
            const bool hover  = btn && btn->isHovered;

            // 背景取顶栏渐变的对应行，保证圆角处无缝
            RECT wr = rc;
            MapWindowPoints(hwnd, GetParent(hwnd), reinterpret_cast<LPPOINT>(&wr), 2);
            const float totalH = (float)(NavH() > 0 ? NavH() : 1);
            COLORREF topC = peanut::ui::MixColor(BG_TOPNAV, BG_TOPNAV2, (float)wr.top / totalH);
            COLORREF botC = peanut::ui::MixColor(BG_TOPNAV, BG_TOPNAV2, (float)wr.bottom / totalH);
            FillVGradient(hdc, rc, topC, botC);

            COLORREF textColor = active ? sk.textPrimary : sk.textSecondary;

            if (sk.navStyle == peanut::ui::NAV_PILL) {
                // 胶囊风格：选中 = 强调色实心胶囊
                if (active || hover) {
                    RECT r = rc;
                    InflateRect(&r, -1, -1);
                    const float rad = (float)(r.bottom - r.top) / 2.0f;
                    const COLORREF fill = active ? sk.accent : sk.bgHover;
                    FillRoundRect(hdc, r, rad, fill,
                                  active ? peanut::ui::ShadeColor(sk.accent, 0.12f) : fill,
                                  false, fill, 1.0f);
                    if (active) textColor = peanut::ui::ContrastTextOn(sk.accent);
                }
            } else if (sk.navStyle == peanut::ui::NAV_LEFTMARK) {
                // 左侧竖条风格
                if (active || hover) {
                    RECT r = rc;
                    InflateRect(&r, -1, -1);
                    const COLORREF fill = active ? sk.accentSoft : sk.bgHover;
                    FillRoundRect(hdc, r, sk.navItemRadius, fill, fill, false, 0, 0);
                }
                if (active) {
                    const int markH = rc.bottom - rc.top - 14;
                    RectF br((REAL)(rc.left + 2), (REAL)(rc.top + 7),
                             (REAL)3.0f, (REAL)markH);
                    Graphics g(hdc);
                    g.SetSmoothingMode(SmoothingModeAntiAlias);
                    SolidBrush b(peanut::ui::Gp(sk.accent));
                    g.FillRectangle(&b, br);
                    textColor = sk.accent;
                }
            } else { // NAV_UNDERLINE — 柔和底 + 底部短渐变条
                if (active || hover) {
                    RECT r = rc;
                    InflateRect(&r, -1, -1);
                    const COLORREF fill = active
                        ? sk.accentSoft
                        : peanut::ui::MixColor(sk.bgHover, topC, 0.55f);
                    FillRoundRect(hdc, r, sk.navItemRadius, fill, fill, false, 0, 0);
                }
                if (active) {
                    RECT bar = { rc.left + 24, rc.bottom - 2, rc.right - 24, rc.bottom };
                    FillHGradientLine(hdc, bar, sk.accent, sk.accent2);
                    textColor = sk.accent;
                }
            }

            // 图标（若该导航项定义了）
            int textLeft = rc.left + 14;
            if (btn && btn->icon && btn->icon[0]) {
                const int side = 16;
                Graphics g(hdc);
                g.SetSmoothingMode(SmoothingModeAntiAlias);
                RectF ib((REAL)(rc.left + 13),
                         (REAL)((rc.top + rc.bottom - side) / 2),
                         (REAL)side, (REAL)side);
                peanut::ui::DrawIcon(g, btn->icon, ib, peanut::ui::Gp(textColor), 1.9f);
                textLeft = rc.left + 13 + side + 7;
            }

            SetBkMode(hdc, TRANSPARENT);
            SetTextColor(hdc, textColor);
            HFONT oldF = static_cast<HFONT>(SelectObject(hdc, self->hFontNav_));
            if (btn) {
                RECT tr = rc;
                tr.left  = textLeft;
                tr.right -= 6;
                DrawTextW(hdc, btn->label, -1, &tr,
                          DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS);
            }
            if (oldF) SelectObject(hdc, oldF);

            EndPaint(hwnd, &ps);
            return 0;
        }

        case WM_LBUTTONDOWN: {
            for (auto& b : self->navButtons_) {
                if (b.hwnd == hwnd) {
                    self->NavigateTo(b.tab);
                    break;
                }
            }
            return 0;
        }

        case WM_MOUSEMOVE: {
            for (auto& b : self->navButtons_) {
                if (b.hwnd == hwnd && !b.isHovered) {
                    b.isHovered = true;
                    TRACKMOUSEEVENT tme = { sizeof(tme), TME_LEAVE, hwnd, 0 };
                    TrackMouseEvent(&tme);
                    InvalidateRect(hwnd, nullptr, FALSE);
                }
            }
            return 0;
        }

        case WM_MOUSELEAVE:
            for (auto& b : self->navButtons_) {
                if (b.hwnd == hwnd) {
                    b.isHovered = false;
                    InvalidateRect(hwnd, nullptr, FALSE);
                }
            }
            return 0;

        case WM_ERASEBKGND:
            return 1;
    }

    return DefSubclassProc(hwnd, msg, wp, lp);
}

// ═══════════════════════════════════════════════════════════
//  消息分发
// ═══════════════════════════════════════════════════════════
LRESULT MainWindow::HandleMessage(UINT msg, WPARAM wp, LPARAM lp) {
    switch (msg) {
        case WM_CREATE:
            OnCreate();
            return 0;
        case WM_SIZE:      OnSize(LOWORD(lp), HIWORD(lp)); break;
        case WM_COMMAND:   OnCommand(wp); break;
        case WM_NOTIFY:    return OnNotify(lp);
        case WM_PAINT:     OnPaint(); break;
        case WM_DRAWITEM:  OnDrawItem(wp, lp); return TRUE;
        case WM_TIMER:     OnTimer(wp); break;
        case WM_DESTROY:   OnDestroy(); break;
        case WM_ERASEBKGND: return 1;  // 自己处理背景
        case WM_APP + 1:   // 启动后自动扫描本地插件
            ScanLocalPlugins();
            return 0;
        case WM_APP + 10:  // 卡密数据或在线集合实际变化后刷新 UI
            if (activeTab_ == NavTab::CardMgmt) RefreshCardList();
            UpdateDashboardStats();
            return 0;

        case WM_CTLCOLORSTATIC:
        case WM_CTLCOLOREDIT:
        case WM_CTLCOLORLISTBOX:
        case WM_CTLCOLORBTN: {
            HDC hdc = reinterpret_cast<HDC>(wp);
            HWND ctrlHwnd = reinterpret_cast<HWND>(lp);

            if (ctrlHwnd == hwndPanelLogs_ || ctrlHwnd == hwndLogTitle_ ||
                ctrlHwnd == hwndLogEdit_ || ctrlHwnd == hwndLogAutoScrollChk_) {
                SetBkColor(hdc, BG_LOG);
                SetTextColor(hdc, TEXT_PRIMARY);
                return reinterpret_cast<LRESULT>(hBrushLog_);
            }

            SetBkColor(hdc, BG_INPUT);
            SetTextColor(hdc, TEXT_PRIMARY);

            if (msg == WM_CTLCOLOREDIT) {
                SetDCBrushColor(hdc, BG_INPUT);
                return reinterpret_cast<LRESULT>(hBrushInput_);
            }

            return reinterpret_cast<LRESULT>(hBrushBg_);
        }

        // 分割条拖动（卡密详情 / 全局日志）
        case WM_LBUTTONDOWN: {
            POINT pt = { GET_X_LPARAM(lp), GET_Y_LPARAM(lp) };
            if (hwndLogSplitter_) {
                RECT rc;
                GetWindowRect(hwndLogSplitter_, &rc);
                MapWindowPoints(nullptr, hwndMain_, reinterpret_cast<POINT*>(&rc), 2);
                if (pt.y >= rc.top - 3 && pt.y <= rc.bottom + 3) {
                    draggingLogSplitter_ = true;
                    dragStartY_ = pt.y;
                    dragStartPos_ = globalLogH_;
                    SetCapture(hwndMain_);
                    SetCursor(LoadCursor(nullptr, IDC_SIZENS));
                    break;
                }
            }
            if (hwndCardSplitter_ && activeTab_ == NavTab::CardMgmt) {
                RECT rc;
                GetWindowRect(hwndCardSplitter_, &rc);
                MapWindowPoints(nullptr, hwndMain_, reinterpret_cast<POINT*>(&rc), 2);
                if (pt.y >= rc.top - 3 && pt.y <= rc.bottom + 3) {
                    draggingSplitter_ = true;
                    dragStartY_ = pt.y;
                    dragStartPos_ = splitterPos_;
                    SetCapture(hwndMain_);
                    SetCursor(LoadCursor(nullptr, IDC_SIZENS));
                }
            }
            break;
        }
        case WM_MOUSEMOVE: {
            POINT pt = { GET_X_LPARAM(lp), GET_Y_LPARAM(lp) };
            if (draggingLogSplitter_) {
                int delta = dragStartY_ - pt.y; // 上拖加大日志区
                globalLogH_ = dragStartPos_ + delta;
                if (globalLogH_ < 120) globalLogH_ = 120;
                if (globalLogH_ > (clientH_ * 2) / 3) globalLogH_ = (clientH_ * 2) / 3;
                Layout();
            } else if (draggingSplitter_) {
                splitterPos_ = dragStartPos_ + (pt.y - dragStartY_);
                int headerH = 48;
                int minPos = headerH + 80;
                int maxPos = contentH_ - 120;
                if (splitterPos_ < minPos) splitterPos_ = minPos;
                if (splitterPos_ > maxPos) splitterPos_ = maxPos;
                LayoutCardManagement();
            } else {
                bool overSplit = false;
                if (hwndLogSplitter_) {
                    RECT rc;
                    GetWindowRect(hwndLogSplitter_, &rc);
                    MapWindowPoints(nullptr, hwndMain_, reinterpret_cast<POINT*>(&rc), 2);
                    if (pt.y >= rc.top - 3 && pt.y <= rc.bottom + 3) overSplit = true;
                }
                if (!overSplit && hwndCardSplitter_ && activeTab_ == NavTab::CardMgmt) {
                    RECT rc;
                    GetWindowRect(hwndCardSplitter_, &rc);
                    MapWindowPoints(nullptr, hwndMain_, reinterpret_cast<POINT*>(&rc), 2);
                    if (pt.y >= rc.top - 3 && pt.y <= rc.bottom + 3) overSplit = true;
                }
                if (overSplit) SetCursor(LoadCursor(nullptr, IDC_SIZENS));
            }
            break;
        }
        case WM_LBUTTONUP:
            if (draggingSplitter_ || draggingLogSplitter_) {
                draggingSplitter_ = false;
                draggingLogSplitter_ = false;
                ReleaseCapture();
            }
            break;

        default:
            return DefWindowProc(hwndMain_, msg, wp, lp);
    }
    return 0;
}

// ═══════════════════════════════════════════════════════════
//  WM_CREATE
// ═══════════════════════════════════════════════════════════
void MainWindow::OnCreate() {
    if (hwndTopNav_) return; // 已创建，避免重复

    // 建 UI 之前先用真实客户区刷新布局参数：
    // 各页面（尤其设置页）在创建时就按最终尺寸落位，
    // 否则会沿用成员默认值，右侧留出一条空白。
    if (hwndMain_) {
        RECT crc = {};
        if (GetClientRect(hwndMain_, &crc) && crc.right > 0) {
            clientW_ = crc.right;
            clientH_ = crc.bottom;
            contentW_ = clientW_;
            contentH_ = clientH_ - NavH() - 5 - globalLogH_ - statusBarH_;
            if (contentH_ < 120) contentH_ = 120;
        }
    }

    // Layer 1: 启动反调试 watchdog (SDK, Release-only)
    peanut::security::antidebug::StartWatchdog([]() {
        // 威胁回调: 清密钥 + 安全擦除 (由 security_runtime 处理)
        // watchdog 自身会 MarkCompromised + SilentExit
    });

    // 状态栏 (最先创建, 固定高度)
    CreateStatusBar();
    statusBarH_ = 30;

    // 顶部导航
    CreateTopNav();

    // 内容区背景面板（顶栏之下、全局日志之上）
    hwndContentArea_ = CreateControl(L"STATIC", L"",
        WS_CHILD | WS_VISIBLE | WS_CLIPCHILDREN | WS_CLIPSIBLINGS | SS_OWNERDRAW,
        0, NavH(), 0, 0,
        hwndMain_, nullptr, nullptr);

    // 各标签页面板（无独立 Logs 页）
    CreateDashboardPanel();
    CreateCardManagementPanel();
    CreatePluginCenterPanel();
    CreateSettingsPanel();
    CreateFirewallPanel();
    CreateCardDetailSplitter();

    // 全局底部日志（始终可见）
    CreateGlobalLogPanel();

    // 暗色：父窗口 CTLCOLOR + ListView/Edit 去白
    ApplyDarkTheme();

    // 保存上次导航页记忆（Dashboard 导航会覆盖 config_.last_nav_tab）
    int savedTab = config_.last_nav_tab;

    // 显示默认页
    NavigateTo(NavTab::Dashboard);

    // 定时器 (时钟)
    SetTimer(hwndMain_, TIMER_CLOCK, 1000, nullptr);

    // 再次应用配置到控件（Create 时已 LoadConfig，此处刷新 UI 记忆项）
    ApplySettingsToUI();
    ApplyUiPrefsToRuntime();
    LoadCards();
    RefreshCardList();
    SyncProtocolUi();

    // 恢复上次导航页（排除 Dashboard 避免重复）
    if (savedTab >= 0 && savedTab <= 4 && savedTab != static_cast<int>(NavTab::Dashboard))
        NavigateTo(static_cast<NavTab>(savedTab));

    PostMessageW(hwndMain_, WM_APP + 1, 0, 0);

    Log("═══════════════════════════════════");
    Log(" Peanut Soft Protect 已启动");
    Log(" 核心客户端协议: 加密 TCP");
    Log(" 卡密数: " + std::to_string(cards_.size()));
    Log("═══════════════════════════════════");

    StartServer();
}

// ═══════════════════════════════════════════════════════════
//  顶部导航栏
// ═══════════════════════════════════════════════════════════
void MainWindow::CreateTopNav() {
    hwndTopNav_ = CreateControl(L"STATIC", L"",
        WS_CHILD | WS_VISIBLE | WS_CLIPCHILDREN,
        0, 0, 0, TOP_NAV_H,
        hwndMain_, nullptr, nullptr);

    struct NavDef {
        NavTab tab;
        const wchar_t* label;
        const wchar_t* icon;
    };

    const NavDef navs[] = {
        { NavTab::Dashboard,    L"仪表盘",   L"dashboard" },
        { NavTab::CardMgmt,     L"卡密管理", L"key"       },
        { NavTab::PluginCenter, L"插件中心", L"plugin"    },
        { NavTab::Firewall,     L"防火墙",   L"shield"    },
        { NavTab::Settings,     L"设置",     L"gear"      },
    };

    navButtons_.clear();
    const int btnW = 112;
    const int navH = NavH();
    int btnH = peanut::ui::g_skin.navBtnHeight;
    if (btnH < 28) btnH = 28;
    if (btnH > navH - 10) btnH = navH - 10;
    const int btnY = (navH - btnH) / 2;
    int x = kNavBrandW;   // 让开左侧品牌标识区

    for (auto& nd : navs) {
        UINT_PTR subId = IDC_NAV_DASHBOARD + static_cast<UINT_PTR>(static_cast<int>(nd.tab));
        HWND hBtn = CreateControl(L"STATIC", L"",
            WS_CHILD | WS_VISIBLE | SS_NOTIFY,
            x, btnY, btnW, btnH,
            hwndTopNav_, reinterpret_cast<HMENU>(subId),
            hFontNav_);

        SetWindowSubclass(hBtn, NavBtnProc, subId, 0);
        navButtons_.push_back({ hBtn, nd.tab, nd.label, nd.icon, false, false });
        x += btnW + 2;
    }

    InvalidateRect(hwndTopNav_, nullptr, TRUE);
}

// ═══════════════════════════════════════════════════════════
//  仪表盘面板
// ═══════════════════════════════════════════════════════════
void MainWindow::CreateDashboardPanel() {
    hwndPanelDashboard_ = CreateControl(L"STATIC", L"",
        WS_CHILD | WS_CLIPCHILDREN | WS_CLIPSIBLINGS,
        0, 0, 0, 0,
        hwndContentArea_, reinterpret_cast<HMENU>(static_cast<INT_PTR>(IDC_PANEL_DASHBOARD)),
        nullptr);

    // 页面名称已由顶部导航高亮，页内不再重复绘制标题与说明，
    // 让出的高度全部给底部日志区。
    hwndDashQuickPanel_ = CreateControl(L"STATIC", L"",
        WS_CHILD | WS_VISIBLE | SS_OWNERDRAW, 0, 0, 0, 0,
        hwndPanelDashboard_, nullptr, nullptr);
    // 快捷操作卡片内的控件（父窗口坐标系，含 kCardPad 落影留白）
    hwndDashQuickTitle_ = CreateControl(L"STATIC", L"快捷操作", WS_CHILD | WS_VISIBLE | SS_LEFT,
        kCardPad + 22, kCardPad + 16, 200, 26, hwndDashQuickPanel_, nullptr, hFontSectionTitle_);
    hwndDashQuickHint_ = CreateControl(L"STATIC", L"常用命令与状态刷新", WS_CHILD | WS_VISIBLE | SS_LEFT,
        kCardPad + 23, kCardPad + 42, 260, 20, hwndDashQuickPanel_, nullptr, hFontBadge_);
    SetCtrlFg(hwndDashQuickHint_, TEXT_MUTED);

    hwndDashGenerateBtn_ = CreateControl(L"BUTTON", L"生成卡密",
        WS_CHILD | WS_VISIBLE | BS_OWNERDRAW,
        0, 0, 132, 36, hwndDashQuickPanel_,
        (HMENU)(INT_PTR)IDC_DASH_GENERATE_BTN, hFontButton_);
    hwndDashRefreshBtn_ = CreateControl(L"BUTTON", L"刷新数据",
        WS_CHILD | WS_VISIBLE | BS_OWNERDRAW,
        0, 0, 132, 36, hwndDashQuickPanel_,
        (HMENU)(INT_PTR)IDC_DASH_REFRESH_BTN, hFontButton_);

    // ── 运行概览卡：2 列 × 3 行键值对 ──────────────────────
    // KPI 卡改紧凑后腾出的纵向空间由本卡填充，避免页面出现大片空余。
    hwndDashOverviewPanel_ = CreateControl(L"STATIC", L"",
        WS_CHILD | WS_VISIBLE | SS_OWNERDRAW, 0, 0, 0, 0,
        hwndPanelDashboard_, nullptr, nullptr);
    hwndDashOverviewTitle_ = CreateControl(L"STATIC", L"运行概览",
        WS_CHILD | WS_VISIBLE | SS_LEFT,
        kCardPad + 20, kCardPad + 12, 200, 28, hwndDashOverviewPanel_,
        nullptr, hFontSectionTitle_);
    hwndDashOverviewHint_ = CreateControl(L"STATIC", L"当前运行参数，随配置与状态自动刷新",
        WS_CHILD | WS_VISIBLE | SS_RIGHT,
        0, kCardPad + 16, 260, 22, hwndDashOverviewPanel_, nullptr, hFontBadge_);
    SetCtrlFg(hwndDashOverviewHint_, TEXT_MUTED);

    {
        // 行优先排列：第 1 行 3 项，第 2 行 3 项
        const wchar_t* ovKeys[kOvCols * kOvRows] = {
            L"监听地址", L"协议模式", L"传输加密",
            L"帧上限",   L"心跳周期", L"授权方式",
        };
        const wchar_t* ovVals[kOvCols * kOvRows] = {
            L"127.0.0.1:9001", L"TCP", L"WY-Cipher + HMAC",
            L"64 MiB", L"30 秒", L"设备绑定 + 会话令牌",
        };
        for (int i = 0; i < kOvCols * kOvRows; ++i) {
            hwndOvKey_[i] = CreateControl(L"STATIC", ovKeys[i],
                WS_CHILD | WS_VISIBLE | SS_LEFT | SS_ENDELLIPSIS,
                0, 0, 0, 0, hwndDashOverviewPanel_, nullptr, hFontStatSub_);
            hwndOvVal_[i] = CreateControl(L"STATIC", ovVals[i],
                WS_CHILD | WS_VISIBLE | SS_LEFT | SS_ENDELLIPSIS | SS_NOPREFIX,
                0, 0, 0, 0, hwndDashOverviewPanel_, nullptr, hFontBadge_);
            SetCtrlFg(hwndOvKey_[i], TEXT_MUTED);
            SetCtrlFg(hwndOvVal_[i], TEXT_SECONDARY);
        }
    }

    struct DashDef {
        const wchar_t* title;
        const wchar_t* value;
        const wchar_t* subtext;
        COLORREF accent;
        const wchar_t* icon;
    };
    // 配色收敛：数量类统一用主强调色，状态卡用状态色，协议用第二强调色
    const DashDef sc[] = {
        { L"总卡密数", L"0",      L"当前库存", ACCENT,  L"cards"  },
        { L"已激活",   L"0",      L"含已过期", ACCENT2, L"bolt"   },
        { L"服务状态", L"运行中", L"等待监听", SUCCESS, L"server" },
        { L"通信协议", L"TCP",    L"加密传输", INFO,    L"wifi"   },
    };

    statCards_.clear();
    for (auto& s : sc) {
        StatCard card;
        card.title       = s.title;
        card.value       = s.value;
        card.subtext     = s.subtext;
        card.accentColor = s.accent;
        card.iconGlyph   = s.icon;
        card.iconKind    = 0;

        card.hwndPanel = CreateControl(L"STATIC", L"",
            WS_CHILD | WS_VISIBLE | SS_OWNERDRAW,
            0, 0, 0, 0,
            hwndPanelDashboard_, nullptr, nullptr);

        card.hwndTitle = CreateControl(L"STATIC", s.title,
            WS_CHILD | WS_VISIBLE | SS_LEFT | SS_ENDELLIPSIS,
            0, 0, 0, 0,
            card.hwndPanel, nullptr, hFontStatTitle_);

        card.hwndValue = CreateControl(L"STATIC", s.value,
            WS_CHILD | WS_VISIBLE | SS_LEFT | SS_ENDELLIPSIS | SS_NOPREFIX,
            0, 0, 0, 0,
            card.hwndPanel, nullptr, hFontStatValue_);

        card.hwndSub = CreateControl(L"STATIC", s.subtext,
            WS_CHILD | WS_VISIBLE | SS_LEFT | SS_ENDELLIPSIS | SS_NOPREFIX,
            0, 0, 0, 0,
            card.hwndPanel, nullptr, hFontStatSub_);

        // 排版层级：标签弱、数值强、说明最弱
        SetCtrlFg(card.hwndTitle, TEXT_SECONDARY);
        SetCtrlFg(card.hwndSub,   TEXT_MUTED);

        statCards_.push_back(card);
    }
}

// ═══════════════════════════════════════════════════════════
//  卡密管理面板
// ═══════════════════════════════════════════════════════════
void MainWindow::CreateCardManagementPanel() {
    hwndPanelCardMgmt_ = CreateControl(L"STATIC", L"",
        WS_CHILD | WS_CLIPCHILDREN | WS_CLIPSIBLINGS,
        0, 0, 0, 0,
        hwndContentArea_, reinterpret_cast<HMENU>(static_cast<INT_PTR>(IDC_PANEL_CARDMGMT)),
        nullptr);

    // 搜索框
    hwndCardSearchEdit_ = CreateControl(L"EDIT", L"",
        WS_CHILD | WS_VISIBLE | ES_LEFT | ES_AUTOHSCROLL,
        0, 0, 0, 0,
        hwndPanelCardMgmt_, reinterpret_cast<HMENU>(static_cast<INT_PTR>(IDC_CARD_SEARCH)),
        hFontDefault_);
    SendMessage(hwndCardSearchEdit_, EM_SETCUEBANNER, 0,
                reinterpret_cast<LPARAM>(L"搜索卡密..."));
    // ENTER 键触发搜索（子类化窗口过程）
    SetWindowSubclass(hwndCardSearchEdit_, [](HWND h, UINT m, WPARAM w, LPARAM l, UINT_PTR, DWORD_PTR) -> LRESULT {
        if (m == WM_KEYDOWN && w == VK_RETURN) {
            PostMessage(GetParent(h), WM_COMMAND, MAKEWPARAM(IDC_BTN_SEARCH, 0), 0);
            return 0;
        }
        return DefSubclassProc(h, m, w, l);
    }, 1, 0);

    // 搜索按钮
    hwndCardSearchBtn_ = CreateControl(L"BUTTON", L"搜索",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON | BS_OWNERDRAW,
        0, 0, 0, 0,
        hwndPanelCardMgmt_, reinterpret_cast<HMENU>(static_cast<INT_PTR>(IDC_BTN_SEARCH)),
        hFontButton_);

    // 筛选（自绘按钮 + 弹出菜单，避免系统 Combo 白边）
    hwndCardFilterBtn_ = CreateControl(L"BUTTON", L"全部",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON | BS_OWNERDRAW,
        0, 0, 0, 0,
        hwndPanelCardMgmt_, reinterpret_cast<HMENU>(static_cast<INT_PTR>(IDC_CARD_FILTER_BTN)),
        hFontButton_);
    cardFilterIndex_ = 0;

    // 操作按钮
    auto makeCardBtn = [&](const wchar_t* text, int id) -> HWND {
        return CreateControl(L"BUTTON", text,
            WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON | BS_OWNERDRAW,
            0, 0, 0, 0,
            hwndPanelCardMgmt_, reinterpret_cast<HMENU>(static_cast<INT_PTR>(id)),
            hFontButton_);
    };

    hwndCardGenerateBtn_ = makeCardBtn(L"生成", IDM_CARD_GENERATE);
    hwndCardImportBtn_   = makeCardBtn(L"导入",   IDC_CARD_IMPORT_BTN);
    hwndCardExportBtn_   = makeCardBtn(L"导出",   IDC_CARD_EXPORT_BTN);
    hwndCardDeleteBtn_   = makeCardBtn(L"删除",   IDC_CARD_DELETE_BTN);
    hwndCardUnbindBtn_   = makeCardBtn(L"解绑",   IDC_CARD_UNBIND_BTN);
    makeCardBtn(L"备注", IDC_CARD_REMARK_BTN);

    // 卡密列表
    hwndCardList_ = CreateControl(WC_LISTVIEWW, L"",
        WS_CHILD | WS_VISIBLE | WS_VSCROLL | LVS_REPORT | LVS_SHOWSELALWAYS,
        0, 0, 0, 0,
        hwndPanelCardMgmt_, reinterpret_cast<HMENU>(static_cast<INT_PTR>(IDC_CARD_LIST)),
        hFontLabel_);

    ListView_SetExtendedListViewStyle(hwndCardList_,
        LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER | LVS_EX_SUBITEMIMAGES);
    // 行高由图像列表尺寸决定：用 28px 高的透明图标把行撑到 30px 左右，
    // 同时保留首列的在线状态圆点（字号放大后行高需同步增加）。
    hwndCardStateImages_ = ImageList_Create(20, 28, ILC_COLOR32 | ILC_MASK, 2, 1);
    if (hwndCardStateImages_) {
        HDC screen=GetDC(nullptr),mem=CreateCompatibleDC(screen);for(int i=0;i<2;++i){HBITMAP bmp=CreateCompatibleBitmap(screen,20,28);HGDIOBJ old=SelectObject(mem,bmp);RECT r{0,0,20,28};FillRect(mem,&r,(HBRUSH)GetStockObject(BLACK_BRUSH));COLORREF fill=i?RGB(35,205,90):RGB(120,128,142),edge=i?RGB(20,150,65):RGB(86,94,108);HBRUSH brush=CreateSolidBrush(fill);HGDIOBJ oldBrush=SelectObject(mem,brush);HPEN pen=CreatePen(PS_SOLID,1,edge);HGDIOBJ oldPen=SelectObject(mem,pen);Ellipse(mem,5,9,15,19);SelectObject(mem,oldPen);SelectObject(mem,oldBrush);DeleteObject(pen);DeleteObject(brush);SelectObject(mem,old);ImageList_AddMasked(hwndCardStateImages_,bmp,RGB(0,0,0));DeleteObject(bmp);}DeleteDC(mem);ReleaseDC(nullptr,screen);ListView_SetImageList(hwndCardList_,hwndCardStateImages_,LVSIL_SMALL);
    }

    // 列表整体底色与表头字体，避免出现系统浅色
    ListView_SetBkColor(hwndCardList_, BG_DEEP);
    ListView_SetTextBkColor(hwndCardList_, BG_DEEP);
    ListView_SetTextColor(hwndCardList_, TEXT_PRIMARY);
    if (HWND hdr = ListView_GetHeader(hwndCardList_)) {
        SendMessageW(hdr, WM_SETFONT, reinterpret_cast<WPARAM>(hFontLabel_), TRUE);
    }
    SetWindowSubclass(hwndCardList_, ListHoverProc,
                      reinterpret_cast<UINT_PTR>(hwndCardList_),
                      reinterpret_cast<DWORD_PTR>(this));

    w32::ListView_AddColumn(hwndCardList_, 0, L"卡密",     330);
    w32::ListView_AddColumn(hwndCardList_, 1, L"类型",     60);
    w32::ListView_AddColumn(hwndCardList_, 2, L"时长",     80);
    w32::ListView_AddColumn(hwndCardList_, 3, L"状态",     80);
    w32::ListView_AddColumn(hwndCardList_, 4, L"机器码（24位）",   160);
    w32::ListView_AddColumn(hwndCardList_, 5, L"激活时间", 160);
    w32::ListView_AddColumn(hwndCardList_, 6, L"到期时间", 160);
    w32::ListView_AddColumn(hwndCardList_, 7, L"备注",     180);

    // 列表下方按钮行
    hwndCardBottomBtns_ = CreateControl(L"STATIC", L"",
        WS_CHILD | WS_VISIBLE,
        0, 0, 0, 0,
        hwndPanelCardMgmt_, nullptr, nullptr);

    auto makeBottomBtn = [&](const wchar_t* text, int id) -> HWND {
        return CreateControl(L"BUTTON", text,
            WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON | BS_OWNERDRAW,
            0, 0, 0, 0,
            hwndCardBottomBtns_, reinterpret_cast<HMENU>(static_cast<INT_PTR>(id)),
            hFontButton_);
    };
    makeBottomBtn(L"全选",     IDC_CARD_SELECT_ALL);
    makeBottomBtn(L"取消全选", IDC_CARD_DESELECT_ALL);
    makeBottomBtn(L"复制所选", IDC_CARD_COPY_SELECTED);

    // 分割条 (卡密列表 — 详情)
    hwndCardSplitter_ = CreateControl(L"STATIC", L"",
        WS_CHILD | WS_VISIBLE | SS_NOTIFY,
        0, 0, 0, 0,
        hwndPanelCardMgmt_, nullptr, nullptr);

    hwndCardDetailLog_ = CreateControl(L"EDIT", L"",
        WS_CHILD | WS_VISIBLE | WS_VSCROLL | ES_LEFT |
        ES_MULTILINE | ES_READONLY | ES_AUTOVSCROLL,
        0, 0, 0, 0,
        hwndPanelCardMgmt_, reinterpret_cast<HMENU>(static_cast<INT_PTR>(IDC_CARD_DETAIL_LOG)),
        hFontLog_);
}

// ═══════════════════════════════════════════════════════════
//  插件中心面板
// ═══════════════════════════════════════════════════════════
void MainWindow::CreatePluginCenterPanel() {
    hwndPanelPlugin_ = CreateControl(L"STATIC", L"",
        WS_CHILD | WS_CLIPCHILDREN | WS_CLIPSIBLINGS,
        0, 0, 0, 0,
        hwndContentArea_, reinterpret_cast<HMENU>(static_cast<INT_PTR>(IDC_PANEL_PLUGIN)),
        nullptr);

    auto makePlgBtn = [&](const wchar_t* text, int id) -> HWND {
        return CreateControl(L"BUTTON", text,
            WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON | BS_OWNERDRAW,
            0, 0, 0, 0,
            hwndPanelPlugin_, reinterpret_cast<HMENU>(static_cast<INT_PTR>(id)),
            hFontButton_);
    };

    hwndPluginRefreshBtn_ = makePlgBtn(L"扫描本地插件", IDC_PLUGIN_REFRESH_BTN);
    hwndPluginExecBtn_    = makePlgBtn(L"执行所选",     IDC_PLUGIN_EXEC_BTN);

    HWND hPlgParamLabel = CreateControl(L"STATIC", L"参数(JSON):",
        WS_CHILD | WS_VISIBLE | SS_LEFT,
        0, 0, 0, 0,
        hwndPanelPlugin_, nullptr, hFontLabel_);

    hwndPluginParamEdit_ = CreateControl(L"EDIT", L"{}",
        WS_CHILD | WS_VISIBLE | ES_LEFT | ES_AUTOHSCROLL,
        0, 0, 0, 0,
        hwndPanelPlugin_, reinterpret_cast<HMENU>(static_cast<INT_PTR>(IDC_PLUGIN_PARAM_EDIT)),
        hFontDefault_);

    hwndPluginList_ = CreateControl(WC_LISTVIEWW, L"",
        WS_CHILD | WS_VISIBLE | LVS_REPORT | LVS_SHOWSELALWAYS,
        0, 0, 0, 0,
        hwndPanelPlugin_, reinterpret_cast<HMENU>(static_cast<INT_PTR>(IDC_PLUGIN_LIST)),
        hFontDefault_);

    ListView_SetExtendedListViewStyle(hwndPluginList_,
        LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER);

    w32::ListView_AddColumn(hwndPluginList_, 0, L"名称",   160);
    w32::ListView_AddColumn(hwndPluginList_, 1, L"状态",    88);
    w32::ListView_AddColumn(hwndPluginList_, 2, L"版本",    76);
    w32::ListView_AddColumn(hwndPluginList_, 3, L"函数数",  76);
    w32::ListView_AddColumn(hwndPluginList_, 4, L"调用次数", 88);
    w32::ListView_AddColumn(hwndPluginList_, 5, L"说明",   320);
}

// ═══════════════════════════════════════════════════════════
//  全局底部日志（所有页面共用，非独立标签）
// ═══════════════════════════════════════════════════════════
void MainWindow::CreateGlobalLogPanel() {
    hwndLogSplitter_ = CreateControl(L"STATIC", L"",
        WS_CHILD | WS_VISIBLE | SS_OWNERDRAW | SS_NOTIFY,
        0, 0, 0, 5,
        hwndMain_, reinterpret_cast<HMENU>(static_cast<INT_PTR>(IDC_LOG_SPLITTER)),
        nullptr);

    hwndPanelLogs_ = CreateControl(L"STATIC", L"",
        WS_CHILD | WS_VISIBLE | WS_CLIPSIBLINGS,
        0, 0, 0, 0,
        hwndMain_, reinterpret_cast<HMENU>(static_cast<INT_PTR>(IDC_PANEL_GLOBAL_LOG)),
        nullptr);

    hwndLogTitle_ = CreateControl(L"STATIC", L"日志",
        WS_CHILD | WS_VISIBLE | SS_LEFT,
        0, 0, 0, 0,
        hwndPanelLogs_, nullptr, hFontSectionTitle_);

    auto makeLogBtn = [&](const wchar_t* text, int id) -> HWND {
        return CreateControl(L"BUTTON", text,
            WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON | BS_OWNERDRAW,
            0, 0, 0, 0,
            hwndPanelLogs_, reinterpret_cast<HMENU>(static_cast<INT_PTR>(id)), hFontButton_);
    };

    hwndLogClearBtn_  = makeLogBtn(L"清空", IDC_LOG_CLEAR_BTN);
    hwndLogExportBtn_ = makeLogBtn(L"导出", IDC_LOG_EXPORT_BTN);

    hwndLogAutoScrollChk_ = CreateControl(L"BUTTON", L"? 自动滚动",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON | BS_OWNERDRAW,
        0, 0, 0, 0,
        hwndPanelLogs_, reinterpret_cast<HMENU>(static_cast<INT_PTR>(IDC_LOG_AUTOSCROLL_CHK)), hFontButton_);

    // RichEdit：可设背景色 + 彩色日志（普通 EDIT 会白底）
    hwndLogEdit_ = CreateWindowExW(
        0, MSFTEDIT_CLASS, L"",
        WS_CHILD | WS_VISIBLE | WS_VSCROLL |
        ES_LEFT | ES_MULTILINE | ES_READONLY | ES_AUTOVSCROLL,
        0, 0, 0, 0,
        hwndPanelLogs_, reinterpret_cast<HMENU>(static_cast<INT_PTR>(IDC_LOG_EDIT)),
        GetModuleHandle(nullptr), nullptr);
    if (hwndLogEdit_) {
        SendMessage(hwndLogEdit_, WM_SETFONT, reinterpret_cast<WPARAM>(hFontLog_), TRUE);
        SendMessage(hwndLogEdit_, EM_SETBKGNDCOLOR, 0, static_cast<LPARAM>(BG_LOG));
        SetWindowTheme(hwndLogEdit_, L"DarkMode_Explorer", nullptr);
    }
}

// ═══════════════════════════════════════════════════════════
//  设置面板
// ═══════════════════════════════════════════════════════════
void MainWindow::CreateSettingsPanel() {
    hwndPanelSettings_ = CreateControl(L"STATIC", L"",
        WS_CHILD | WS_CLIPCHILDREN | WS_CLIPSIBLINGS,
        0, 0, 0, 0,
        hwndContentArea_, reinterpret_cast<HMENU>(static_cast<INT_PTR>(IDC_PANEL_SETTINGS)),
        nullptr);

    int x = 15;
    int labelW = 90;

    auto makeLabel = [&](const wchar_t* text) -> HWND {
        return CreateControl(L"STATIC", text,
            WS_CHILD | WS_VISIBLE | SS_LEFT,
            0, 0, 0, 0,
            hwndPanelSettings_, nullptr, hFontLabel_);
    };
    auto makeEdit = [&](int id, bool isNum = false) -> HWND {
        DWORD style = WS_CHILD | WS_VISIBLE | ES_LEFT | ES_AUTOHSCROLL;
        if (isNum) style |= ES_NUMBER;
        return CreateControl(L"EDIT", L"",
            style, 0, 0, 0, 0,
            hwndPanelSettings_, reinterpret_cast<HMENU>(static_cast<INT_PTR>(id)), hFontDefault_);
    };
    auto makeGroup = [&](const wchar_t* text, int height) -> HWND {
        // 自绘卡片框代替系统 GroupBox（颜色可控 + 边框更细）
        return CreateControl(L"STATIC", text,
            WS_CHILD | WS_VISIBLE | SS_OWNERDRAW,
            0, 0, 0, 0,
            hwndPanelSettings_, nullptr, nullptr);
    };
    auto makeSettingBtn = [&](const wchar_t* text, int id) -> HWND {
        return CreateControl(L"BUTTON", text,
            WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON | BS_OWNERDRAW,
            0, 0, 0, 0,
            hwndPanelSettings_, reinterpret_cast<HMENU>(static_cast<INT_PTR>(id)), hFontButton_);
    };

    // ── Background Panel ──
    hwndSettBg_ = CreateControl(L"STATIC", L"",
        WS_CHILD | WS_VISIBLE,
        10, 10, contentW_ - 40, contentH_ - 20,
        hwndPanelSettings_, nullptr, nullptr);

    auto settPos = [](HWND hwnd, int x, int y, int w, int ht) {
        if (hwnd) SetWindowPos(hwnd, nullptr, x, y, w, ht, SWP_NOZORDER);
    };

    // ── 服务配置（合并服务器协议 + 加密密钥）──
    // 页内不再重复页面标题，首个分组直接贴顶
    int gy = 18;
    hwndSettGrpSrv_ = makeGroup(L"服务配置", 0);
    settPos(hwndSettGrpSrv_, 15, gy, contentW_ - 55, 344);

    HWND hLblHost = makeLabel(L"监听地址:");
    HWND hLblPort = makeLabel(L"端口:");
    HWND hLblHmac = makeLabel(L"HMAC密钥:");
    HWND hLblProto = makeLabel(L"协议:");
    HWND hLblAes = makeLabel(L"会话密钥:");
    HWND hLblPsp = makeLabel(L"PSP种子:");
    hwndSettHostEdit_ = makeEdit(IDC_SETT_EDIT_HOST);
    hwndSettPortEdit_ = makeEdit(IDC_SETT_EDIT_PORT, true);
    hwndSettHmacEdit_ = makeEdit(IDC_SETT_EDIT_HMAC);
    hwndSettAesEdit_ = makeEdit(IDC_SETT_EDIT_AES);
    SendMessage(hwndSettAesEdit_, EM_SETPASSWORDCHAR, '*', 0);
    SendMessage(hwndSettAesEdit_, EM_SETREADONLY, TRUE, 0);
    hwndSettPspEdit_ = makeEdit(IDC_SETT_EDIT_PSP);
    SendMessage(hwndSettPspEdit_, EM_SETPASSWORDCHAR, '*', 0);
    SendMessage(hwndSettPspEdit_, EM_SETREADONLY, TRUE, 0);

    int ey = gy + 46;   // 让出卡片标题与分隔线
    int col1 = 28, col2 = col1 + 90, col3 = col2 + 220, kw = 60;
    int rowH = 27;      // 行距随字号同步放宽

    auto settLabel = [&](const wchar_t* t, int x, int yp) { settPos(makeLabel(t), x, yp, 90, 24); };
    auto settEdit = [&](HWND h, int x, int yp, int w) { settPos(h, x, yp, w, 24); };

    // Row 1: 监听地址 | 端口 | 协议
    settLabel(L"监听地址:", col1, ey);
    settEdit(hwndSettHostEdit_, col2, ey, 180);
    settLabel(L"端口:", col2 + 188, ey);
    settEdit(hwndSettPortEdit_, col2 + 222, ey, 60);
    settLabel(L"协议:", col2 + 290, ey);
    hwndSettProtoHttp_ = CreateControl(L"BUTTON", L"HTTP",
        WS_CHILD | WS_VISIBLE | BS_AUTORADIOBUTTON | WS_GROUP,
        col2 + 330, ey, 70, 24,
        hwndPanelSettings_, reinterpret_cast<HMENU>(static_cast<INT_PTR>(IDC_SETT_PROTO_HTTP)), hFontLabel_);
    hwndSettProtoTcp_ = CreateControl(L"BUTTON", L"TCP",
        WS_CHILD | WS_VISIBLE | BS_AUTORADIOBUTTON,
        col2 + 408, ey, 70, 24,
        hwndPanelSettings_, reinterpret_cast<HMENU>(static_cast<INT_PTR>(IDC_SETT_PROTO_TCP)), hFontLabel_);
    ey += rowH;

    // Row 2: HMAC密钥
    settLabel(L"HMAC密钥:", col1, ey);
    settEdit(hwndSettHmacEdit_, col2, ey, 290);
    ey += rowH;

    // 分隔线（视觉区分）
    ey += 4;

    // Row 3: 会话密钥 (AES)
    settLabel(L"会话密钥:", col1, ey);
    settEdit(hwndSettAesEdit_, col2, ey, 220);
    settPos(makeSettingBtn(L"复制", IDC_SETT_COPY_AES), col2 + 226, ey - 1, 56, 24);
    hwndSettGenAes_ = makeSettingBtn(L"生成", IDC_SETT_GEN_AES);
    settPos(hwndSettGenAes_,  col2 + 286, ey - 1, 56, 24);
    hwndSettGenAesNote_ = makeLabel(L"");
    settPos(hwndSettGenAesNote_, col2 + 346, ey + 1, 260, 20);
    ey += rowH;

    // Row 4: PSP种子
    settLabel(L"PSP种子:", col1, ey);
    settEdit(hwndSettPspEdit_, col2, ey, 220);
    settPos(makeSettingBtn(L"复制", IDC_SETT_COPY_PSP), col2 + 226, ey - 1, 56, 24);
    hwndSettGenPsp_ = makeSettingBtn(L"生成", IDC_SETT_GEN_PSP);
    settPos(hwndSettGenPsp_,  col2 + 286, ey - 1, 56, 24);
    hwndSettGenPspNote_ = makeLabel(L"");
    settPos(hwndSettGenPspNote_, col2 + 346, ey + 1, 260, 20);
    ey += rowH;

    // RSA说明
    ey += 4;
    CreateControl(L"STATIC",
        L"RSA密钥: keys/server_privkey.hex (服务端) / server_pubkey.hex (客户端)",
        WS_CHILD | WS_VISIBLE | SS_LEFT,
        col1, ey, contentW_ - 70, 24,
        hwndPanelSettings_, nullptr, hFontLabel_);

    ey += 32;
    CreateControl(L"STATIC", L"自动更新（仅服务器开关开启时强制）",
        WS_CHILD | WS_VISIBLE | SS_LEFT, col1, ey, 320, 26, hwndPanelSettings_, nullptr, hFontSectionTitle_);
    hwndSettUpdateEnable_ = CreateControl(L"BUTTON", L"启用强制更新",
        WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX, col1, ey + 28, 140, 24, hwndPanelSettings_,
        reinterpret_cast<HMENU>(static_cast<INT_PTR>(IDC_SETT_UPDATE_ENABLE)), hFontLabel_);
    // 勾选框文字较长，标签必须让开，否则会叠在一起
    settLabel(L"目标进程:", col2 + 62, ey + 30);
    hwndSettUpdateTarget_ = makeEdit(IDC_SETT_UPDATE_TARGET);
    settEdit(hwndSettUpdateTarget_, col2 + 150, ey + 27, 190);
    ey += 58;
    settLabel(L"目标SHA256:", col1, ey);
    hwndSettUpdateHash_ = makeEdit(IDC_SETT_UPDATE_HASH);
    settEdit(hwndSettUpdateHash_, col2, ey, 340);
    ey += rowH;
    settLabel(L"TCP 包标识:", col1, ey);
    hwndSettUpdateUrl_ = makeEdit(IDC_SETT_UPDATE_URL);
    settEdit(hwndSettUpdateUrl_, col2, ey, 340);
    ey += rowH;
    settLabel(L"包SHA256:", col1, ey);
    hwndSettUpdatePackageHash_ = makeEdit(IDC_SETT_UPDATE_PKG_HASH);
    settEdit(hwndSettUpdatePackageHash_, col2, ey, 340);

    // ── 卡密权限 ──
    int permY = gy + 344 + 10;
    hwndSettGrpPerm_ = makeGroup(L"卡密权限", 0);
    settPos(hwndSettGrpPerm_, 15, permY, contentW_ - 55, 84);

    hwndSettPermUnbind_ = CreateControl(L"BUTTON", L"允许解绑",
        WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX,
        col1, permY + 20, 120, 24,
        hwndPanelSettings_, reinterpret_cast<HMENU>(static_cast<INT_PTR>(IDC_SETT_UNBIND_ENABLE)), hFontLabel_);

    HWND hPermDayLabel = makeLabel(L"每天解绑上限:");
    hwndSettPermDayEdit_ = makeEdit(IDC_SETT_UNBIND_DAY, true);
    HWND hPermMonLabel = makeLabel(L"每月解绑上限:");
    hwndSettPermMonEdit_ = makeEdit(IDC_SETT_UNBIND_MONTH, true);

    int permRowY = permY + 44;
    settPos(hwndSettPermUnbind_, col1, permRowY, 120, 24);
    settPos(hPermDayLabel, col2, permRowY + 2, 90, 24);
    settPos(hwndSettPermDayEdit_, col2 + 90, permRowY - 1, 60, 24);
    settPos(hPermMonLabel, col2 + 160, permRowY + 2, 90, 24);
    settPos(hwndSettPermMonEdit_, col2 + 250, permRowY - 1, 60, 24);

    // 在线并发（服务端强制）
    int concY = permY + 84 + 10;
    hwndSettGrpConc_ = makeGroup(L"在线并发（服务端强制）", 0);
    settPos(hwndSettGrpConc_, 15, concY, contentW_ - 55, 84);
    hwndSettMultiOpen_ = CreateControl(L"BUTTON", L"允许同卡多开",
        WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX,
        col1, concY + 44, 140, 24,
        hwndPanelSettings_, reinterpret_cast<HMENU>(static_cast<INT_PTR>(IDC_SETT_MULTI_OPEN)), hFontLabel_);
    HWND hMaxOnlineLabel = makeLabel(L"同卡最多在线:");
    hwndSettMaxOnlineEdit_ = makeEdit(IDC_SETT_MAX_ONLINE, true);
    settPos(hMaxOnlineLabel, col2, concY + 46, 100, 24);
    settPos(hwndSettMaxOnlineEdit_, col2 + 100, concY + 44, 60, 24);
    CreateControl(L"STATIC", L"关闭多开时强制为1（新登录踢掉旧会话）",
        WS_CHILD | WS_VISIBLE | SS_LEFT,
        col2 + 180, concY + 46, 360, 24,
        hwndPanelSettings_, nullptr, hFontLabel_);

    UpdateKeyGenButtons();
    ApplySettingsToUI();

    // ── 记录基准位置：设置页内容高于可视区时用滚轮下移查看 ──
    settBaseRect_.clear();
    settScrollY_ = 0;
    settContentH_ = 0;
    EnumChildWindows(hwndPanelSettings_, [](HWND child, LPARAM lp) -> BOOL {
        auto* self = reinterpret_cast<MainWindow*>(lp);
        // 背景板固定不动，其余控件参与滚动
        if (child == self->hwndSettBg_) return TRUE;
        RECT r = {};
        GetWindowRect(child, &r);
        MapWindowPoints(HWND_DESKTOP, self->hwndPanelSettings_,
                        reinterpret_cast<LPPOINT>(&r), 2);
        self->settBaseRect_[child] = r;
        if (r.bottom > self->settContentH_) self->settContentH_ = r.bottom;
        return TRUE;
    }, reinterpret_cast<LPARAM>(this));
}

// 设置页滚轮滚动：整体平移子控件（顶部 30px 的页面标题保持不动）
void MainWindow::ScrollSettings(int dyPx) {
    if (settBaseRect_.empty() || !hwndPanelSettings_) return;
    RECT crc = {};
    GetClientRect(hwndPanelSettings_, &crc);

    const int maxScroll = (settContentH_ + 16 > crc.bottom)
                        ? (settContentH_ + 16 - crc.bottom) : 0;
    int next = settScrollY_ + dyPx;
    if (next < 0) next = 0;
    if (next > maxScroll) next = maxScroll;
    if (next == settScrollY_ && dyPx != 0) return;   // dyPx==0 用于重新夹紧
    settScrollY_ = next;

    for (const auto& kv : settBaseRect_) {
        const RECT& b = kv.second;
        SetWindowPos(kv.first, nullptr, b.left, b.top - settScrollY_,
                     b.right - b.left, b.bottom - b.top,
                     SWP_NOZORDER | SWP_NOACTIVATE);
    }
    InvalidateRect(hwndPanelSettings_, nullptr, TRUE);
}

static bool KeyFileExists(const std::wstring& exeDir, const char* relPath) {
    std::filesystem::path p(exeDir);
    p /= peanut::keys::kDefaultKeyDir;
    p /= relPath;
    std::error_code ec;
    return std::filesystem::exists(p, ec) && !ec;
}

void MainWindow::UpdateKeyGenButtons() {
    if (!hwndSettGenAes_ || !hwndSettGenPsp_) return;

    wchar_t mod[MAX_PATH];
    GetModuleFileNameW(nullptr, mod, MAX_PATH);
    std::wstring dir(mod);
    size_t slash = dir.find_last_of(L"\\/");
    if (slash != std::wstring::npos) dir.resize(slash);

    bool aesExists = KeyFileExists(dir, peanut::keys::kCipherKeyFile);
    bool pspExists = KeyFileExists(dir, peanut::keys::kPspKeyFile);

    EnableWindow(hwndSettGenAes_, aesExists ? FALSE : TRUE);
    EnableWindow(hwndSettGenPsp_, pspExists ? FALSE : TRUE);

    if (hwndSettGenAesNote_) {
        SetWindowText(hwndSettGenAesNote_, aesExists ? L"本地密钥已存在, 请先删除 keys/cipher_key.hex" : L"");
    }
    if (hwndSettGenPspNote_) {
        SetWindowText(hwndSettGenPspNote_, pspExists ? L"本地密钥已存在, 请先删除 keys/psp_key.hex" : L"");
    }
}

// ═══════════════════════════════════════════════════════════
//  状态栏
// ═══════════════════════════════════════════════════════════
void MainWindow::CreateStatusBar() {
    // 自绘底栏（系统 StatusBar 难以统一暗色文字）
    hwndStatusBar_ = CreateControl(L"STATIC", L"",
        WS_CHILD | WS_VISIBLE | SS_OWNERDRAW,
        0, 0, 0, 30,
        hwndMain_, reinterpret_cast<HMENU>(static_cast<INT_PTR>(IDC_STATUS_BAR)),
        hFontLabel_);
    statusBarH_ = 30;
    UpdateStatusBar();
}

// ═══════════════════════════════════════════════════════════
//  分割条
// ═══════════════════════════════════════════════════════════
void MainWindow::CreateCardDetailSplitter() {
    // Already created above as hwndCardSplitter_
}

// ═══════════════════════════════════════════════════════════
//  防火墙面板（独立标签页）
// ═══════════════════════════════════════════════════════════
void MainWindow::CreateFirewallPanel() {
    hwndPanelFirewall_ = CreateControl(L"STATIC", L"",
        WS_CHILD | WS_CLIPCHILDREN | WS_CLIPSIBLINGS,
        0, 0, 0, 0,
        hwndContentArea_, reinterpret_cast<HMENU>(static_cast<INT_PTR>(IDC_PANEL_FIREWALL)),
        nullptr);

    hwndFwRuleCard_ = CreateControl(L"STATIC", L"",
        WS_CHILD | WS_VISIBLE | SS_OWNERDRAW | WS_CLIPCHILDREN,
        0, 0, 0, 0, hwndPanelFirewall_, nullptr, nullptr);
    CreateControl(L"STATIC", L"IP 风控规则", WS_CHILD | WS_VISIBLE | SS_LEFT,
        0, 0, 0, 0, hwndFwRuleCard_, nullptr, hFontSectionTitle_);
    CreateControl(L"STATIC", L"连续失败达到阈值后自动封禁来源地址", WS_CHILD | WS_VISIBLE | SS_LEFT,
        0, 0, 0, 0, hwndFwRuleCard_, nullptr, hFontLabel_);

    auto mkLbl = [&](const wchar_t* t) {
        return CreateControl(L"STATIC", t, WS_CHILD | WS_VISIBLE | SS_LEFT,
            0, 0, 0, 0, hwndFwRuleCard_, nullptr, hFontLabel_);
    };
    auto mkEdt = [&](int id) {
        return CreateControl(L"EDIT", L"", WS_CHILD | WS_VISIBLE | ES_LEFT | ES_AUTOHSCROLL | ES_NUMBER,
            0, 0, 0, 0, hwndFwRuleCard_, (HMENU)(INT_PTR)id, hFontDefault_);
    };

    HWND hL1 = mkLbl(L"允许失败次数:");
    hwndSettFwAttemptEdit_ = mkEdt(IDC_SETT_FW_ATTEMPTS);
    HWND hL2 = mkLbl(L"统计窗口(分钟):");
    hwndSettFwWindowEdit_ = mkEdt(IDC_SETT_FW_WINDOW);
    HWND hL3 = mkLbl(L"封禁时长(分钟):");
    hwndSettFwBanEdit_ = mkEdt(IDC_SETT_FW_BAN);

    SetWindowPos(hL1, nullptr, 20, 62, 120, 24, SWP_NOZORDER);
    SetWindowPos(hwndSettFwAttemptEdit_, nullptr, 150, 58, 90, 28, SWP_NOZORDER);
    SetWindowPos(hL2, nullptr, 275, 62, 125, 24, SWP_NOZORDER);
    SetWindowPos(hwndSettFwWindowEdit_, nullptr, 410, 58, 90, 28, SWP_NOZORDER);
    SetWindowPos(hL3, nullptr, 535, 62, 125, 24, SWP_NOZORDER);
    SetWindowPos(hwndSettFwBanEdit_, nullptr, 670, 58, 90, 28, SWP_NOZORDER);

    // 当前封禁 IP 列表
    hwndFwListTitle_ = CreateControl(L"STATIC", L"当前封禁列表",
        WS_CHILD | WS_VISIBLE | SS_LEFT,
        0, 0, 0, 0,
        hwndPanelFirewall_, nullptr, hFontSectionTitle_);

    hwndFwIpList_ = CreateControl(WC_LISTVIEWW, L"",
        WS_CHILD | WS_VISIBLE | LVS_REPORT | LVS_SHOWSELALWAYS,
        0, 0, 0, 0,
        hwndPanelFirewall_, (HMENU)(INT_PTR)9100, hFontDefault_);

    ListView_SetExtendedListViewStyle(hwndFwIpList_, LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER);
    w32::ListView_AddColumn(hwndFwIpList_, 0, L"IP 地址", 180);
    w32::ListView_AddColumn(hwndFwIpList_, 1, L"失败次数", 80);
    w32::ListView_AddColumn(hwndFwIpList_, 2, L"封禁至", 180);

    ApplySettingsToUI();
}

void MainWindow::LayoutFirewall() {
    if (!hwndPanelFirewall_ || !IsWindowVisible(hwndPanelFirewall_)) return;
    const int pad = 14;
    const int cardW = (std::max)(520, contentW_ - pad * 2);
    SetWindowPos(hwndFwRuleCard_, nullptr, pad, pad, cardW, 100, SWP_NOZORDER);
    // 卡片内：标题 + 说明一行，三个阈值字段一行（紧凑两行式布局）
    HWND c = GetWindow(hwndFwRuleCard_, GW_CHILD); int i = 0;
    while (c) {
        switch (i) {
        case 0: SetWindowPos(c, nullptr, 18, 10, 220, 26, SWP_NOZORDER); break;  // 标题
        case 1: SetWindowPos(c, nullptr, 18, 36, 440, 22, SWP_NOZORDER); break;  // 说明
        case 2: SetWindowPos(c, nullptr, 18,  64, 110, 22, SWP_NOZORDER); break; // 标签1
        case 3: SetWindowPos(c, nullptr, 130, 62,  70, 24, SWP_NOZORDER); break; // 输入1
        case 4: SetWindowPos(c, nullptr, 215, 64, 130, 22, SWP_NOZORDER); break; // 标签2
        case 5: SetWindowPos(c, nullptr, 348, 62,  70, 24, SWP_NOZORDER); break; // 输入2
        case 6: SetWindowPos(c, nullptr, 435, 64, 130, 22, SWP_NOZORDER); break; // 标签3
        case 7: SetWindowPos(c, nullptr, 568, 62,  70, 24, SWP_NOZORDER); break; // 输入3
        default: break;
        }
        c = GetWindow(c, GW_HWNDNEXT); ++i;
    }
    SetWindowPos(hwndFwListTitle_, nullptr, pad, pad + 100 + 12, 240, 26, SWP_NOZORDER);
    SetWindowPos(hwndFwIpList_, nullptr, pad, pad + 100 + 40, cardW,
                 (std::max)(80, contentH_ - (pad + 100 + 54)), SWP_NOZORDER);

    // 末列吸收剩余宽度
    RECT flc{};
    if (GetClientRect(hwndFwIpList_, &flc)) {
        const int fixed = 190 + 88;
        ListView_SetColumnWidth(hwndFwIpList_, 2,
                                (std::max)(120, static_cast<int>(flc.right) - fixed - 24));
    }
}

// ═══════════════════════════════════════════════════════════
//  面板布局 (总)
// ═══════════════════════════════════════════════════════════
void MainWindow::OnSize(int width, int height) {
    clientW_ = width;
    clientH_ = height;
    contentX_ = 0;
    contentY_ = NavH();
    contentW_ = clientW_;
    // 内容区 = 客户区 - 顶栏 - 日志分割条 - 全局日志 - 状态栏
    const int splitH = 5;
    contentH_ = clientH_ - NavH() - splitH - globalLogH_ - statusBarH_;
    if (contentH_ < 120) contentH_ = 120;
    Layout();
}

void MainWindow::Layout() {
    if (!hwndMain_) return;

    const int splitH = 5;
    int logTop = clientH_ - statusBarH_ - globalLogH_;
    if (logTop < NavH() + 80) logTop = NavH() + 80;
    globalLogH_ = clientH_ - statusBarH_ - logTop;
    contentH_ = logTop - splitH - NavH();
    if (contentH_ < 120) contentH_ = 120;
    contentW_ = clientW_;

    // 顶栏
    SetWindowPos(hwndTopNav_, nullptr, 0, 0, clientW_, NavH(), SWP_NOZORDER);

    // 内容区（顶栏下、日志上）
    SetWindowPos(hwndContentArea_, nullptr, 0, NavH(),
                 contentW_, contentH_, SWP_NOZORDER);

    // only resize active panel, skip hidden panels to avoid z-order pollution
    HWND activePanel = nullptr;
    switch (activeTab_) {
        case NavTab::Dashboard:    activePanel = hwndPanelDashboard_; break;
        case NavTab::CardMgmt:     activePanel = hwndPanelCardMgmt_; break;
        case NavTab::PluginCenter: activePanel = hwndPanelPlugin_; break;
        case NavTab::Settings:     activePanel = hwndPanelSettings_; break;
        case NavTab::Firewall:     activePanel = hwndPanelFirewall_; break;
    }
    if (activePanel && IsWindowVisible(activePanel)) {
        SetWindowPos(activePanel, nullptr, 0, 0, contentW_, contentH_,
                     SWP_NOZORDER | SWP_NOACTIVATE);
    }

    // 日志分割条 + 全局日志（始终可见）
    SetWindowPos(hwndLogSplitter_, nullptr, 0, NavH() + contentH_,
                 clientW_, splitH, SWP_NOZORDER | SWP_SHOWWINDOW);
    SetWindowPos(hwndPanelLogs_, nullptr, 0, logTop,
                 clientW_, globalLogH_, SWP_NOZORDER | SWP_SHOWWINDOW);

    LayoutDashboard();
    LayoutCardManagement();
    LayoutPluginCenter();
    LayoutGlobalLog();
    LayoutSettings();
    LayoutFirewall();

    if (hwndStatusBar_) {
        SetWindowPos(hwndStatusBar_, nullptr,
                     0, clientH_ - statusBarH_, clientW_, statusBarH_,
                     SWP_NOZORDER);
    }
    InvalidateRect(hwndTopNav_, nullptr, TRUE);
}

// ═══════════════════════════════════════════════════════════
//  仪表盘布局
// ═══════════════════════════════════════════════════════════
void MainWindow::LayoutDashboard() {
    if (!hwndPanelDashboard_ || !IsWindowVisible(hwndPanelDashboard_)) return;

    // ── 三段式纵向布局：KPI 行 → 运行概览卡 → 快捷操作栏 ──
    // 卡片窗口每侧比视觉卡片大 kCardPad，用来承载落影；
    // 因此窗口之间可以零间隙，视觉间距完全由落影留白决定。
    const int margin = 20;    // 视觉外边距
    const int vGap   = 14;    // 视觉间距
    const int bottom = 20;    // 内容区底部留白
    const int quickH = 78;    // 快捷操作栏高度

    auto clampI = [](int v, int lo, int hi) { return v < lo ? lo : (v > hi ? hi : v); };

    // 内容区高度随皮肤导航栏而变（皮肤3=375，皮肤1/2=371）：
    // KPI 118 + 概览 100 + 快捷 78 + 边距 68 恰好填满，因此概览卡最小高度按
    // “标题 + 2 行键值”（100）取值，两套皮肤的导航高度都放得下。
    const int kpiH   = 118;
    const int ovMin  = 100;   // 概览卡最小可用高度（标题 + 2 行键值）
    const int ovMax  = 112;   // 概览卡上限，再富余的部分转为整块居中留白
    const int kpiMin = 92;    // 空间不足时 KPI 卡的下限

    int kpiCardH = kpiH;
    int ovH      = 0;
    const int avail = contentH_ - margin - bottom - vGap * 2 - quickH;
    if (avail >= kpiH + ovMin) {
        ovH = (avail - kpiH > ovMax) ? ovMax : (avail - kpiH);
    } else if (avail > kpiMin) {
        kpiCardH = clampI(avail, kpiMin, kpiH);   // 空间不足：收起概览卡，KPI 卡吸收
    } else {
        kpiCardH = clampI(avail, 60, kpiH);
    }

    const int stackH = kpiCardH + vGap + (ovH > 0 ? ovH + vGap : 0) + quickH;
    const int slack  = contentH_ - margin - bottom - stackH;
    const int rowTop = margin + (slack > 0 ? slack / 2 : 0);

    // ── KPI 行 ────────────────────────────────────────────
    const int n = static_cast<int>(statCards_.size());
    const int cols = (contentW_ >= 640) ? 4 : 2;   // 窗口偏窄时仍保持一行 4 卡
    const int vw = (contentW_ - margin * 2 - vGap * (cols - 1)) / cols;
    const int cardW = vw + kCardPad * 2;
    const int cardH = kpiCardH + kCardPad * 2;
    const int stepX = vw + vGap;
    const int stepY = kpiCardH + vGap;
    const int chipS = 34;     // 图标容器边长
    const int tx    = kCardPad + 16 + chipS + 12;
    // 文字块高度：标签 18 + 间隔 2 + 数值 34 + 间隔 2 + 说明 16 = 72
    const int blkH  = 72;
    const int blkY  = kCardPad + (kpiCardH - blkH) / 2;   // 卡高变化时文字块保持居中

    for (int i = 0; i < n; ++i) {
        const int row = i / cols, col = i % cols;
        const int cx = margin - kCardPad + col * stepX;
        const int cy = rowTop + row * stepY;

        SetWindowPos(statCards_[i].hwndPanel, nullptr, cx, cy, cardW, cardH, SWP_NOZORDER);

        const int tw = vw - (tx - kCardPad) - 14;
        SetWindowPos(statCards_[i].hwndTitle, nullptr, tx, blkY,      tw, 18, SWP_NOZORDER);
        SetWindowPos(statCards_[i].hwndValue, nullptr, tx, blkY + 20, tw, 34, SWP_NOZORDER);
        SetWindowPos(statCards_[i].hwndSub,   nullptr, tx, blkY + 56, tw, 16, SWP_NOZORDER);
        InvalidateRect(statCards_[i].hwndPanel, nullptr, FALSE);
    }

    // ── 运行概览卡 ────────────────────────────────────────
    const int ovY = rowTop + kpiCardH + vGap;
    if (ovH > 0 && hwndDashOverviewPanel_) {
        ShowWindow(hwndDashOverviewPanel_, SW_SHOW);
        SetWindowPos(hwndDashOverviewPanel_, nullptr, margin - kCardPad, ovY,
                     contentW_ - margin * 2 + kCardPad * 2, ovH + kCardPad * 2, SWP_NOZORDER);
        InvalidateRect(hwndDashOverviewPanel_, nullptr, TRUE);

        const int innerW = contentW_ - margin * 2;
        SetWindowPos(hwndDashOverviewTitle_, nullptr, kCardPad + 20, kCardPad + 8,
                     200, 26, SWP_NOZORDER);
        if (hwndDashOverviewHint_) {
            const int hintW = 250;
            SetWindowPos(hwndDashOverviewHint_, nullptr,
                         kCardPad + innerW - 20 - hintW, kCardPad + 12, hintW, 22,
                         SWP_NOZORDER);
        }

        // 键值网格：3 列 × 最多 2 行（行优先），行数按卡片实际高度自适应
        const int keyW   = 62;
        const int gutter = 16;
        const int colW   = (innerW - 40 - gutter * (kOvCols - 1)) / kOvCols;
        const int rowH   = 24;
        int fitRows = (ovH - 52) / rowH;
        if (fitRows > kOvRows) fitRows = kOvRows;
        if (fitRows < 0) fitRows = 0;

        for (int i = 0; i < kOvCols * kOvRows; ++i) {
            HWND hk = hwndOvKey_[i];
            HWND hv = hwndOvVal_[i];
            if (!hk || !hv) continue;
            const int col = i % kOvCols;   // 列号
            const int r   = i / kOvCols;   // 行号
            const bool vis = (r < fitRows);
            ShowWindow(hk, vis ? SW_SHOW : SW_HIDE);
            ShowWindow(hv, vis ? SW_SHOW : SW_HIDE);
            if (!vis) continue;

            const int cx = kCardPad + 20 + col * (colW + gutter);
            const int cy = kCardPad + 44 + r * rowH;
            SetWindowPos(hk, nullptr, cx, cy, keyW, rowH, SWP_NOZORDER);
            SetWindowPos(hv, nullptr, cx + keyW, cy, colW - keyW, rowH, SWP_NOZORDER);
        }
    } else if (hwndDashOverviewPanel_) {
        ShowWindow(hwndDashOverviewPanel_, SW_HIDE);
    }

    // ── 快捷操作栏 ────────────────────────────────────────
    const int quickY = rowTop + kpiCardH + vGap + (ovH > 0 ? ovH + vGap : 0);
    SetWindowPos(hwndDashQuickPanel_, nullptr, margin - kCardPad, quickY,
                 contentW_ - margin * 2 + kCardPad * 2, quickH + kCardPad * 2, SWP_NOZORDER);

    // 左侧文字块与右侧按钮组各自垂直居中
    {
        const int blkTop = kCardPad + (quickH - 46) / 2;
        SetWindowPos(hwndDashQuickTitle_, nullptr, kCardPad + 20, blkTop,      200, 26, SWP_NOZORDER);
        SetWindowPos(hwndDashQuickHint_,  nullptr, kCardPad + 21, blkTop + 26, 240, 20, SWP_NOZORDER);

        const int btnW = 118, btnH = 32;
        const int rightPad = 20;
        const int btnY = kCardPad + (quickH - btnH) / 2;
        const int r = contentW_ - margin - rightPad;
        SetWindowPos(hwndDashRefreshBtn_,  nullptr, r - btnW, btnY, btnW, btnH, SWP_NOZORDER);
        SetWindowPos(hwndDashGenerateBtn_, nullptr, r - btnW * 2 - 10, btnY, btnW, btnH, SWP_NOZORDER);
    }
    InvalidateRect(hwndDashQuickPanel_, nullptr, TRUE);
}

// ═══════════════════════════════════════════════════════════
//  卡密管理布局
// ═══════════════════════════════════════════════════════════
void MainWindow::LayoutCardManagement() {
    if (!hwndPanelCardMgmt_ || !IsWindowVisible(hwndPanelCardMgmt_)) return;

    const int pad = 14;
    int y = pad;   // 页内无标题，工具栏直接贴顶

    // 主工具栏：搜索框 | 搜索 | 筛选 || 生成 导入 导出 删除
    // 次要工具栏：解绑 备注 || 全选 取消全选 复制所选（右对齐）
    // 窄窗（896px）下所有按钮挤一行会互相重叠，故拆成两行，
    // 按“主操作在上、批量操作在下”的信息层级分配。
    const int searchW = 150;
    const int comboW  = 80;
    const int btnH    = 28;

    SetWindowPos(hwndCardSearchEdit_,  nullptr, pad,                y, searchW, btnH, SWP_NOZORDER);
    SetWindowPos(hwndCardSearchBtn_,   nullptr, pad + searchW + 8,  y, 66,     btnH, SWP_NOZORDER);
    SetWindowPos(hwndCardFilterBtn_,   nullptr, pad + searchW + 82, y, comboW,  btnH, SWP_NOZORDER);

    int btnX = pad + searchW + comboW + 94;
    SetWindowPos(hwndCardGenerateBtn_, nullptr, btnX, y, 84, btnH, SWP_NOZORDER); btnX += 92;
    SetWindowPos(hwndCardImportBtn_,   nullptr, btnX, y, 76, btnH, SWP_NOZORDER); btnX += 84;
    SetWindowPos(hwndCardExportBtn_,   nullptr, btnX, y, 76, btnH, SWP_NOZORDER); btnX += 84;
    SetWindowPos(hwndCardDeleteBtn_,   nullptr, btnX, y, 76, btnH, SWP_NOZORDER);
    y += btnH + 8;

    // 次行：解绑 / 备注（左） + 批量选择（右）
    SetWindowPos(hwndCardUnbindBtn_, nullptr, pad, y, 72, btnH, SWP_NOZORDER);
    SetWindowPos(GetDlgItem(hwndPanelCardMgmt_, IDC_CARD_REMARK_BTN),
                 nullptr, pad + 80, y, 72, btnH, SWP_NOZORDER);
    {
        const int selW = 94, gap = 6;
        const int totalW = selW * 3 + gap * 2;
        if (hwndCardBottomBtns_)
            SetWindowPos(hwndCardBottomBtns_, nullptr, contentW_ - pad - totalW, y,
                         totalW, btnH, SWP_NOZORDER);
        HWND btns3[] = { GetDlgItem(hwndCardBottomBtns_, IDC_CARD_SELECT_ALL),
                         GetDlgItem(hwndCardBottomBtns_, IDC_CARD_DESELECT_ALL),
                         GetDlgItem(hwndCardBottomBtns_, IDC_CARD_COPY_SELECTED) };
        int sx = 0;
        for (auto hb : btns3) {
            if (!hb) continue;
            SetWindowPos(hb, nullptr, sx, 0, selW, btnH, SWP_NOZORDER);
            sx += selW + gap;
        }
    }
    y += btnH + 10;

    // 卡密列表
    splitterPos_ = contentH_ - 10;
    int listH = splitterPos_ - y;
    if (listH < 80) listH = 80;
    SetWindowPos(hwndCardList_, nullptr, pad, y, contentW_ - pad*2, listH, SWP_NOZORDER);
    // 列宽按紧凑窗口重算：固定列合计必须小于列表宽度，
    // 否则会露出原生浅色横向滚动条（以及右下角白块）。
    {
        const int kCols[7] = { 200, 48, 54, 78, 132, 120, 120 };  // 0..6
        int fixed = 0;
        for (int i = 0; i < 7; ++i) { ListView_SetColumnWidth(hwndCardList_, i, kCols[i]); fixed += kCols[i]; }
        RECT cardListClient{};
        if (GetClientRect(hwndCardList_, &cardListClient)) {
            // 纵向滚动条占的是客户区宽度，必须一起扣掉，
            // 否则会露出原生横向滚动条。
            const int availableWidth =
                static_cast<int>(cardListClient.right) - fixed - 4 - 20;
            const int remarkWidth = (std::max)(80, availableWidth);
            ListView_SetColumnWidth(hwndCardList_, 7, remarkWidth);
        }
    }
    y += listH;

    // 分割条
    SetWindowPos(hwndCardSplitter_, nullptr, pad, y, contentW_ - pad*2, splitterH_, SWP_NOZORDER);
    y += splitterH_;

    // 详情/日志底部区域（-80px）
    ShowWindow(hwndCardSplitter_,SW_HIDE);
    ShowWindow(hwndCardDetailLog_,SW_HIDE);
}

// ═══════════════════════════════════════════════════════════
//  插件中心布局
// ═══════════════════════════════════════════════════════════
void MainWindow::LayoutPluginCenter() {
    if (!hwndPanelPlugin_ || !IsWindowVisible(hwndPanelPlugin_)) return;

    const int pad = 14;
    int y = pad;   // 页内无标题，操作按钮直接贴顶

    const int btnW = 132, btnH = 30;
    SetWindowPos(hwndPluginRefreshBtn_, nullptr, pad, y, btnW, btnH, SWP_NOZORDER);
    SetWindowPos(hwndPluginExecBtn_,    nullptr, pad + btnW + 10, y, btnW, btnH, SWP_NOZORDER);
    y += btnH + 8;

    // 参数输入行
    if (hwndPluginParamEdit_) {
        HWND hPlgParamLabel = GetWindow(hwndPluginParamEdit_, GW_HWNDPREV);
        if (hPlgParamLabel) SetWindowPos(hPlgParamLabel, nullptr, pad, y, 86, 26, SWP_NOZORDER);
        SetWindowPos(hwndPluginParamEdit_, nullptr, pad + 86, y, contentW_ - pad*2 - 86, 26, SWP_NOZORDER);
        y += 32;
    }

    int listH = contentH_ - y - pad;
    if (listH < 40) listH = 40;
    SetWindowPos(hwndPluginList_, nullptr, pad, y, contentW_ - pad*2, listH, SWP_NOZORDER);

    // 说明列吸收剩余宽度，避免表格右侧留白
    RECT plc{};
    if (GetClientRect(hwndPluginList_, &plc)) {
        const int fixed = 160 + 88 + 76 + 76 + 88;
        ListView_SetColumnWidth(hwndPluginList_, 5,
                                (std::max)(200, static_cast<int>(plc.right) - fixed - 4));
    }
}

// ═══════════════════════════════════════════════════════════
//  全局日志布局（底部常驻）
// ═══════════════════════════════════════════════════════════
void MainWindow::LayoutGlobalLog() {
    if (!hwndPanelLogs_) return;

    const int pad  = 14;
    const int hdrH = 36;
    const int btnH = 24;

    // 标题与绘制在面板上的强调圆点对齐
    SetWindowPos(hwndLogTitle_, nullptr, pad + 14, (hdrH - 26) / 2 + 1, 70, 26, SWP_NOZORDER);

    // 工具按钮统一右对齐，贴近视觉重心
    const int btnY = (hdrH - btnH) / 2;
    int x = clientW_ - pad;
    auto place = [&](HWND h, int w) {
        if (!h) return;
        x -= w;
        SetWindowPos(h, nullptr, x, btnY, w, btnH, SWP_NOZORDER);
        x -= 8;
    };
    place(hwndLogAutoScrollChk_, 108);
    place(hwndLogExportBtn_, 72);
    place(hwndLogClearBtn_, 72);

    const int editTop = hdrH + 2;
    int editH = globalLogH_ - editTop - 10;
    if (editH < 40) editH = 40;
    SetWindowPos(hwndLogEdit_, nullptr, pad, editTop,
                 clientW_ - pad * 2, editH, SWP_NOZORDER);
}

// ═══════════════════════════════════════════════════════════
//  设置布局
// ═══════════════════════════════════════════════════════════
void MainWindow::LayoutSettings() {
    if (!hwndPanelSettings_ || !IsWindowVisible(hwndPanelSettings_)) return;
    // 控件在创建时已按最终尺寸落位，这里只处理随内容区变化的部分：
    // 背景板尺寸 + 滚动位置夹紧（内容高于可视区时可用滚轮查看下方分组）
    if (hwndSettBg_) {
        SetWindowPos(hwndSettBg_, nullptr, 10, 10,
                     (std::max)(200, contentW_ - 40),
                     (std::max)(120, contentH_ - 20), SWP_NOZORDER);
    }
    if (!settBaseRect_.empty()) ScrollSettings(0);
}

// ═══════════════════════════════════════════════════════════
//  导航
// ═══════════════════════════════════════════════════════════
void MainWindow::NavigateTo(NavTab tab) {
    activeTab_ = tab;
    config_.last_nav_tab = static_cast<int>(tab);
    UpdateActiveNavButton();
    ShowPanelForTab(tab);
    InvalidateRect(hwndTopNav_, nullptr, TRUE);

    switch (tab) {
        case NavTab::Dashboard:    LayoutDashboard(); break;
        case NavTab::CardMgmt:     LayoutCardManagement(); break;
        case NavTab::PluginCenter: LayoutPluginCenter(); break;
        case NavTab::Firewall:     LayoutFirewall(); break;
        case NavTab::Settings:     LayoutSettings(); break;
    }
    // 记忆当前页（轻量写 ini）
    SaveConfig();
}

void MainWindow::UpdateActiveNavButton() {
    for (auto& btn : navButtons_) {
        btn.isActive = (btn.tab == activeTab_);
        if (btn.hwnd) InvalidateRect(btn.hwnd, nullptr, FALSE);
    }
}

void MainWindow::ShowPanelForTab(NavTab tab) {
    HWND panels[] = { hwndPanelDashboard_, hwndPanelCardMgmt_,
                   hwndPanelPlugin_, hwndPanelSettings_, hwndPanelFirewall_ };
    const int w = (std::max)(1, contentW_);
    const int h = (std::max)(1, contentH_);
    // 显式隐藏页面及全部后代。部分 Win32 公共控件在频繁切换、重绘时会
    // 保留独立可见区域，仅隐藏 STATIC 父面板不足以可靠清除。
    for (HWND panel : panels) {
        if (!panel) continue;
        EnumChildWindows(panel, [](HWND child, LPARAM) -> BOOL { ShowWindow(child, SW_HIDE); return TRUE; }, 0);
        ShowWindow(panel, SW_HIDE);
    }
    for (size_t i = 0; i < _countof(panels); ++i) {
        if (!panels[i]) continue;
        if (static_cast<int>(i) == static_cast<int>(tab)) {
            EnumChildWindows(panels[i], [](HWND child, LPARAM) -> BOOL { ShowWindow(child, SW_SHOWNA); return TRUE; }, 0);
            SetWindowPos(panels[i], HWND_TOP, 0, 0, w, h, SWP_SHOWWINDOW | SWP_NOACTIVATE);
            RedrawWindow(panels[i], nullptr, nullptr, RDW_INVALIDATE | RDW_ERASE | RDW_ALLCHILDREN | RDW_UPDATENOW);
        }
    }
    // force redraw content area to avoid stale panel painting
    if (hwndContentArea_) RedrawWindow(hwndContentArea_, nullptr, nullptr,
        RDW_INVALIDATE | RDW_ERASE | RDW_ALLCHILDREN | RDW_UPDATENOW);
    // 全局日志始终显示，不参与切页隐藏
    if (hwndPanelLogs_) ShowWindow(hwndPanelLogs_, SW_SHOW);
    if (hwndLogSplitter_) ShowWindow(hwndLogSplitter_, SW_SHOW);
}

// ═══════════════════════════════════════════════════════════
//  仪表盘数据更新
// ═══════════════════════════════════════════════════════════
void MainWindow::UpdateDashboardStats() {
    if (statCards_.size() >= 4) {
        int total = (int)cards_.size();
        int active = 0, expired = 0, used = 0;
        for (auto& c : cards_) {
            if (c.status == 1) active++;
            else if (c.status == 2) expired++;
            else if (c.status == 0) used++;
        }

        statCards_[0].value   = std::to_wstring(total);
        statCards_[0].subtext = L"未使用 " + std::to_wstring(used);
        statCards_[1].value   = std::to_wstring(active);
        statCards_[1].subtext = L"已过期 " + std::to_wstring(expired);
        statCards_[2].value   = serverRunning_ ? L"运行中" : L"已停止";
        statCards_[2].subtext = L"端口 " + std::to_wstring(config_.port);
        statCards_[2].accentColor = serverRunning_ ? SUCCESS : ERROR_COLOR;
        statCards_[3].value   = protocolMode_ == 1 ? L"HTTP" : L"TCP";
        statCards_[3].subtext = L"加密传输";

        for (auto& sc : statCards_) {
            if (sc.hwndValue) SetWindowText(sc.hwndValue, sc.value.c_str());
            if (sc.hwndSub)   SetWindowText(sc.hwndSub,   sc.subtext.c_str());
        }

        // 服务状态卡的强调色跟随运行状态，仅在变化时重绘，避免周期性闪烁
        static COLORREF s_lastSrvAccent = (COLORREF)-1;
        if (statCards_[2].accentColor != s_lastSrvAccent) {
            s_lastSrvAccent = statCards_[2].accentColor;
            if (statCards_[2].hwndPanel)
                InvalidateRect(statCards_[2].hwndPanel, nullptr, FALSE);
        }
    }

    // 运行概览卡：键值网格第 0 项=监听地址、第 1 项=协议模式，跟随实际配置
    if (hwndOvVal_[0]) {
        std::wstring addr = L"127.0.0.1:" + std::to_wstring(config_.port);
        SetWindowText(hwndOvVal_[0], addr.c_str());
    }
    if (hwndOvVal_[1]) {
        SetWindowText(hwndOvVal_[1], (protocolMode_ == 1) ? L"HTTP" : L"TCP");
    }
}

// ═══════════════════════════════════════════════════════════
//  命令处理
// ═══════════════════════════════════════════════════════════
void MainWindow::OnCommand(WPARAM wp) {
    int id = LOWORD(wp);
    int notify = HIWORD(wp);

    // 顶部导航
    switch (id) {
        case IDC_NAV_DASHBOARD:     NavigateTo(NavTab::Dashboard);    return;
        case IDC_NAV_CARD_MGMT:     NavigateTo(NavTab::CardMgmt);     return;
        case IDC_NAV_PLUGIN_CENTER: NavigateTo(NavTab::PluginCenter); return;
        case IDC_NAV_SETTINGS:      NavigateTo(NavTab::Settings);     return;
        case IDC_NAV_FIREWALL:      NavigateTo(NavTab::Firewall);     return;
}

    switch (id) {
        // ── 仪表盘 ──
        case IDC_DASH_GENERATE_BTN:
            ShowCardGenerateDialog();
            break;

        // ── 卡密管理 ──
        case IDC_CARD_COPY_SELECTED: CopySelectedCards(); break;
        case IDC_CARD_SELECT_ALL:    SelectAllCards(); break;
        case IDC_CARD_DESELECT_ALL:  DeselectAllCards(); break;
        case IDC_CARD_UNBIND_BTN:    UnbindSelectedCards(); break;
        case IDC_CARD_REMARK_BTN:    EditSelectedCardRemark(); break;
        case IDC_CARD_DELETE_BTN:
        case IDM_CARD_DELETE:        DeleteSelectedCards(); break;
        case IDM_CARD_GENERATE:      ShowCardGenerateDialog(); break;
        case IDC_CARD_IMPORT_BTN:    ShowCardImportDialog(); break;
        case IDC_CARD_EXPORT_BTN:    ExportLog(); /* 复用导出逻辑 */ break;
        case IDC_BTN_SEARCH:         RefreshCardList(); break;

        case IDC_CARD_FILTER_BTN: {
            if (!hwndCardFilterBtn_) break;
            RECT rc{};
            GetWindowRect(hwndCardFilterBtn_, &rc);
            HMENU hMenu = CreatePopupMenu();
            AppendMenuW(hMenu, MF_STRING | (cardFilterIndex_ == 0 ? MF_CHECKED : 0),
                        IDC_CARD_FILTER_ALL, L"全部");
            AppendMenuW(hMenu, MF_STRING | (cardFilterIndex_ == 1 ? MF_CHECKED : 0),
                        IDC_CARD_FILTER_ACTIVE, L"已激活");
            AppendMenuW(hMenu, MF_STRING | (cardFilterIndex_ == 2 ? MF_CHECKED : 0),
                        IDC_CARD_FILTER_EXPIRED, L"已过期");
            AppendMenuW(hMenu, MF_STRING | (cardFilterIndex_ == 3 ? MF_CHECKED : 0),
                        IDC_CARD_FILTER_DISABLED, L"已禁用");
            TrackPopupMenu(hMenu, TPM_LEFTALIGN | TPM_TOPALIGN, rc.left, rc.bottom, 0, hwndMain_, nullptr);
            DestroyMenu(hMenu);
            break;
        }
        case IDC_CARD_FILTER_ALL:
        case IDC_CARD_FILTER_ACTIVE:
        case IDC_CARD_FILTER_EXPIRED:
        case IDC_CARD_FILTER_DISABLED: {
            cardFilterIndex_ = id - IDC_CARD_FILTER_ALL;
            config_.card_filter = cardFilterIndex_;
            static const wchar_t* labels[] = { L"全部", L"已激活", L"已过期", L"已禁用" };
            if (hwndCardFilterBtn_ && cardFilterIndex_ >= 0 && cardFilterIndex_ < 4)
                SetWindowTextW(hwndCardFilterBtn_, labels[cardFilterIndex_]);
            RefreshCardList();
            SaveConfig();
            break;
        }

        // ── 插件中心 ──
        case IDC_PLUGIN_REFRESH_BTN:
            ScanLocalPlugins();
            break;
        case IDC_PLUGIN_EXEC_BTN:
            ExecuteSelectedPlugin();
            break;

        // ── 日志 ──
        case IDC_LOG_CLEAR_BTN:     ClearLog(); break;
        case IDC_LOG_EXPORT_BTN:    ExportLog(); break;
        case IDC_LOG_AUTOSCROLL_CHK:
            logAutoScroll_ = !logAutoScroll_;
            config_.log_auto_scroll = logAutoScroll_;
            SetWindowTextW(hwndLogAutoScrollChk_, logAutoScroll_ ? L"自动滚动" : L"暂停滚动");
            SetBtnChecked(hwndLogAutoScrollChk_, logAutoScroll_);
            InvalidateRect(hwndLogAutoScrollChk_, nullptr, FALSE);
            SaveConfig();
            break;
        case IDB_CLEAR_LOG:         ClearLog(); break;

        // ── 设置 ──
        case IDC_SETT_PROTO_HTTP:
        case IDC_SETT_PROTO_TCP:
            config_.protocol_mode = 0;
            protocolMode_ = config_.protocol_mode;
            if (hwndSettProtoHttp_)
                SendMessage(hwndSettProtoHttp_, BM_SETCHECK,
                    config_.protocol_mode == 1 ? BST_CHECKED : BST_UNCHECKED, 0);
            if (hwndSettProtoTcp_)
                SendMessage(hwndSettProtoTcp_, BM_SETCHECK,
                    config_.protocol_mode == 0 ? BST_CHECKED : BST_UNCHECKED, 0);
            SaveConfig();
            SyncProtocolUi();
            Log("核心客户端协议固定为加密 TCP");
            break;
        case IDC_SETT_EDIT_HOST:
        case IDC_SETT_EDIT_PORT:
        case IDC_SETT_EDIT_HMAC:
        case IDC_SETT_MAX_ONLINE:
            if (notify == EN_KILLFOCUS) {
                ReadSettingsFromUI();
                SaveConfig();
            }
            break;
        case IDC_SETT_MULTI_OPEN:
            ReadSettingsFromUI();
            ApplySettingsToUI();
            SaveConfig();
            Log(config_.multi_open_enabled
                ? "[会话策略] 已允许同卡多开，最大在线数=" + std::to_string(config_.max_online_per_card)
                : "[会话策略] 已禁止同卡多开，新登录将踢掉旧会话");
            break;
        case IDC_SETT_COPY_AES:
            w32::Clipboard_SetText(wstring_from_utf8(config_.aes_key_hex));
            LogSuccess("AES key copied to clipboard");
            break;
        case IDC_SETT_COPY_PSP:
            w32::Clipboard_SetText(wstring_from_utf8(config_.psp_key_hex));
            LogSuccess("PSP key copied to clipboard");
            break;
        case IDC_SETT_GEN_AES: {
            // Generate random 256-bit key
            uint8_t key[32];
            for (int i = 0; i < 32; ++i) key[i] = static_cast<uint8_t>(rand() % 256);
            std::stringstream ss;
            ss << std::hex << std::uppercase << std::setfill('0');
            for (int i = 0; i < 32; ++i) ss << std::setw(2) << static_cast<int>(key[i]);
            config_.aes_key_hex = ss.str();
            ApplySettingsToUI();
            SaveConfig();
            LogSuccess("New AES key generated");
            break;
        }
        case IDC_SETT_GEN_PSP: {
            uint8_t key[32];
            for (int i = 0; i < 32; ++i) key[i] = static_cast<uint8_t>(rand() % 256);
            std::stringstream ss;
            ss << std::hex << std::uppercase << std::setfill('0');
            for (int i = 0; i < 32; ++i) ss << std::setw(2) << static_cast<int>(key[i]);
            config_.psp_key_hex = ss.str();
            ApplySettingsToUI();
            SaveConfig();
            psp_encoder_->set_psk_hex(config_.psp_key_hex);
            LogSuccess("New PSP key generated");
            break;
        }

        // ── 刷新 ──
        case IDB_REFRESH: RefreshCardList(); break;

        // ── 菜单 ──
        case IDM_FILE_EXIT:     PostQuitMessage(0); break;
        case IDM_FILE_SETTINGS: NavigateTo(NavTab::Settings); break;
        case IDM_PLUGIN_RELOAD: ScanLocalPlugins(); break;
        case IDM_HELP_ABOUT:    ShowAboutDialog(); break;

        default:
            if (id >= IDM_PLUGIN_START && id < IDM_PLUGIN_END) {
                int idx = static_cast<int>(id - IDM_PLUGIN_START);
                if (idx >= 0 && idx < static_cast<int>(local_plugins_.size())) {
                    ListView_SetItemState(hwndPluginList_, -1, 0, LVIS_SELECTED);
                    ListView_SetItemState(hwndPluginList_, idx, LVIS_SELECTED | LVIS_FOCUSED,
                                          LVIS_SELECTED | LVIS_FOCUSED);
                    ExecuteSelectedPlugin();
                }
            }
            break;
    }
}

// ═══════════════════════════════════════════════════════════
//  通知消息 (ListView 双击等)
// ═══════════════════════════════════════════════════════════
LRESULT MainWindow::OnNotify(LPARAM lp) {
    NMHDR* nmh = reinterpret_cast<NMHDR*>(lp);

    if (nmh->hwndFrom == hwndCardList_) {
        if (nmh->code == NM_CUSTOMDRAW) {
            auto* draw = reinterpret_cast<LPNMLVCUSTOMDRAW>(lp);
            switch (draw->nmcd.dwDrawStage) {
            case CDDS_PREPAINT:
                return CDRF_NOTIFYITEMDRAW;

            case CDDS_ITEMPREPAINT: {
                // 行底色：选中 > 悬停 > 斑马纹
                const int row = static_cast<int>(draw->nmcd.dwItemSpec);
                const bool sel = (draw->nmcd.uItemState & CDIS_SELECTED) != 0;
                if (sel)
                    draw->clrTextBk = peanut::ui::MixColor(ACCENT, BG_DEEP, 0.72f);
                else if (row == cardListHot_)
                    draw->clrTextBk = peanut::ui::MixColor(ACCENT, BG_DEEP, 0.90f);
                else
                    draw->clrTextBk = (row & 1)
                        ? peanut::ui::MixColor(BG_DEEP, BG_CARD, 0.34f)
                        : BG_DEEP;
                draw->clrText = TEXT_PRIMARY;
                return CDRF_NOTIFYSUBITEMDRAW;
            }

            case (CDDS_ITEMPREPAINT | CDDS_SUBITEM): {
                const int row = static_cast<int>(draw->nmcd.dwItemSpec);
                const bool sel = (draw->nmcd.uItemState & CDIS_SELECTED) != 0;
                switch (draw->iSubItem) {
                case 0:   // 卡密：主信息，等宽字体
                    if (hFontCardKey_) SelectObject(draw->nmcd.hdc, hFontCardKey_);
                    draw->clrText = sel ? TEXT_PRIMARY : TEXT_PRIMARY;
                    break;
                case 3: { // 状态：按语义着色
                    wchar_t st[32] = {};
                    ListView_GetItemText(hwndCardList_, row, 3, st, 32);
                    if (wcscmp(st, L"已激活") == 0)      draw->clrText = SUCCESS;
                    else if (wcscmp(st, L"已过期") == 0) draw->clrText = WARNING;
                    else if (wcscmp(st, L"已禁用") == 0) draw->clrText = ERROR_COLOR;
                    else                                  draw->clrText = TEXT_MUTED;
                    break;
                }
                default:  // 其余列退到次要层级，避免整行同权
                    draw->clrText = sel ? TEXT_PRIMARY : TEXT_SECONDARY;
                    break;
                }
                return CDRF_NEWFONT;
            }

            default:
                break;
            }
        }
        switch (nmh->code) {
            case NM_DBLCLK: {
                LPNMITEMACTIVATE lv = reinterpret_cast<LPNMITEMACTIVATE>(lp);
                if (lv->iItem >= 0) ShowCardDetail(lv->iItem);
                break;
            }
            case NM_RCLICK: {
                // 右击上下文菜单
                POINT pt;
                GetCursorPos(&pt);
                HMENU hCtx = CreatePopupMenu();
                AppendMenuW(hCtx, MF_STRING, IDC_CARD_SELECT_ALL,    L"全选");
                AppendMenuW(hCtx, MF_STRING, IDC_CARD_DESELECT_ALL,  L"取消全选");
                AppendMenuW(hCtx, MF_STRING, IDC_CARD_COPY_SELECTED, L"复制所选");
                AppendMenuW(hCtx, MF_STRING, IDC_CARD_REMARK_BTN, L"修改备注");
                AppendMenuW(hCtx, MF_SEPARATOR, 0, nullptr);
                AppendMenuW(hCtx, MF_STRING, IDC_CARD_DELETE_BTN,    L"删除");
                TrackPopupMenu(hCtx, TPM_RIGHTBUTTON, pt.x, pt.y, 0, hwndMain_, nullptr);
                DestroyMenu(hCtx);
                break;
            }
        }
    }
    return 0;
}

// ═══════════════════════════════════════════════════════════
//  绘制
// ═══════════════════════════════════════════════════════════
void MainWindow::OnPaint() {
    PAINTSTRUCT ps;
    HDC hdc = BeginPaint(hwndMain_, &ps);

    RECT rc;
    GetClientRect(hwndMain_, &rc);
    FillRect(hdc, &rc, hBrushBg_);

    // 顶栏底部分割线
    if (hwndTopNav_) {
        HPEN old = static_cast<HPEN>(SelectObject(hdc, hPenBorder_));
        MoveToEx(hdc, 0, NavH() - 1, nullptr);
        LineTo(hdc, rc.right, NavH() - 1);
        SelectObject(hdc, old);
    }

    EndPaint(hwndMain_, &ps);
}

void MainWindow::PaintTopNav(Graphics& g) {
    if (!hwndTopNav_) return;
    RECT rc;
    GetClientRect(hwndTopNav_, &rc);
    SolidBrush bg(GpTopNav());
    g.FillRectangle(&bg, 0, 0, rc.right, rc.bottom);
}

void MainWindow::PaintStatusBar(Graphics&) {
    // 系统状态栏控件自绘
}

void MainWindow::DrawRoundedButton(Graphics& g, const RectF& rect,
                                    const Color& bg, const Color& textColor,
                                    const std::wstring& text, Font& font,
                                    float radius, bool drawBorder) {
    GraphicsPath path;
    path.AddArc(rect.X, rect.Y, radius*2, radius*2, 180, 90);
    path.AddArc(rect.X + rect.Width - radius*2, rect.Y, radius*2, radius*2, 270, 90);
    path.AddArc(rect.X + rect.Width - radius*2, rect.Y + rect.Height - radius*2, radius*2, radius*2, 0, 90);
    path.AddArc(rect.X, rect.Y + rect.Height - radius*2, radius*2, radius*2, 90, 90);
    path.CloseFigure();

    SolidBrush bgBrush(bg);
    g.FillPath(&bgBrush, &path);

    if (drawBorder) {
        Pen pen(ACCENT, 1.0f);
        g.DrawPath(&pen, &path);
    }

    SolidBrush txtBrush(textColor);
    StringFormat sf;
    sf.SetAlignment(StringAlignmentCenter);
    sf.SetLineAlignment(StringAlignmentCenter);
    g.DrawString(text.c_str(), -1, &font, rect, &sf, &txtBrush);
}

// ═══════════════════════════════════════════════════════════
//  自绘控件 (OWNERDRAW)
// ═══════════════════════════════════════════════════════════
void MainWindow::OnDrawItem(WPARAM wp, LPARAM lp) {
    auto* dis = reinterpret_cast<LPDRAWITEMSTRUCT>(lp);
    if (!dis || !dis->hDC) return;

    // 内容区 / 日志分割条
    if (dis->hwndItem == hwndContentArea_) {
        FillRect(dis->hDC, &dis->rcItem, hBrushBg_);
        return;
    }
    if (dis->hwndItem == hwndLogSplitter_) {
        FillRect(dis->hDC, &dis->rcItem, hBrushSidebar_);
        RECT mid = dis->rcItem;
        int cy = (dis->rcItem.top + dis->rcItem.bottom) / 2;
        mid.top = cy; mid.bottom = cy + 1;
        int totalW = dis->rcItem.right - dis->rcItem.left;
        mid.left  += totalW / 4;
        mid.right -= totalW / 4;
        RECT left = mid, right = mid;
        left.right  = mid.left + (mid.right - mid.left) / 2;
        right.left  = left.right;
        FillHGradientLine(dis->hDC, left,  DIVIDER, ACCENT);
        FillHGradientLine(dis->hDC, right, ACCENT,  DIVIDER);
        return;
    }

    // 自绘状态栏
    if (dis->hwndItem == hwndStatusBar_) {
        FillVGradient(dis->hDC, dis->rcItem, BG_TOPNAV2, BG_TOPNAV);
        RECT ln = { dis->rcItem.left, dis->rcItem.top,
                    dis->rcItem.right, dis->rcItem.top + 1 };
        FillHGradientLine(dis->hDC, ln, ACCENT, DIVIDER);

        SetBkMode(dis->hDC, TRANSPARENT);
        SetTextColor(dis->hDC, TEXT_SECONDARY);
        HFONT oldFont = hFontLabel_
            ? static_cast<HFONT>(SelectObject(dis->hDC, hFontLabel_)) : nullptr;

        const int widths[] = { 180, 200, 160, 120 };
        int x = 12;
        for (int i = 0; i < 4; ++i) {
            RECT r = { x, dis->rcItem.top, x + widths[i], dis->rcItem.bottom };
            COLORREF fg = TEXT_SECONDARY;
            if (i == 0) {
                fg = isConnected_ ? SUCCESS : TEXT_MUTED;
                int cy = (dis->rcItem.top + dis->rcItem.bottom) / 2;
                HBRUSH dot = CreateSolidBrush(fg);
                HPEN   dp  = CreatePen(PS_SOLID, 1, fg);
                HGDIOBJ ob = SelectObject(dis->hDC, dot);
                HGDIOBJ op = SelectObject(dis->hDC, dp);
                Ellipse(dis->hDC, x, cy - 4, x + 8, cy + 4);
                SelectObject(dis->hDC, ob);
                SelectObject(dis->hDC, op);
                DeleteObject(dp);
                DeleteObject(dot);
                r.left += 14;
            }
            SetTextColor(dis->hDC, fg);
            DrawTextW(dis->hDC, statusParts_[i].c_str(), -1, &r,
                      DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS);
            x += widths[i];
        }
        if (oldFont) SelectObject(dis->hDC, oldFont);
        return;
    }

    // 快捷面板 / 防火墙规则卡 / 设置页GroupBox
    const bool isSettingsGroup = (dis->hwndItem == hwndSettGrpSrv_ ||
                                  dis->hwndItem == hwndSettGrpPerm_ ||
                                  dis->hwndItem == hwndSettGrpConc_);
    // 仪表盘「快捷操作」卡：与 KPI 卡统一的落影 + 卡片面
    // 运行概览卡（与 KPI 卡同底色，左侧一条渐变强调条，标题下压细分隔线）
    if (dis->hwndItem == hwndDashOverviewPanel_) {
        const auto& sk = peanut::ui::g_skin;
        FillRect(dis->hDC, &dis->rcItem, hBrushBg_);

        RECT cardRc = dis->rcItem;
        InflateRect(&cardRc, -kCardPad, -kCardPad);
        if (cardRc.right > cardRc.left && cardRc.bottom > cardRc.top) {
            DrawSoftShadow(dis->hDC, cardRc, sk.cardRadius,
                           sk.shadowSpread, sk.shadowOffsetY, sk.shadowAlpha);
            const COLORREF brd = peanut::ui::MixColor(sk.border, BG_CARD,
                                                      1.0f - sk.cardBorderAlpha);
            FillRoundRect(dis->hDC, cardRc, sk.cardRadius,
                          BG_CARD, BG_CARD2, true, brd, 1.0f);

            // 左侧强调条（沿用 KPI 卡的处理：圆角内裁切 + 向下渐隐）
            const int barW = sk.accentBarW > 0 ? sk.accentBarW : 3;
            Graphics g(dis->hDC);
            g.SetSmoothingMode(SmoothingModeAntiAlias);
            RectF rf((REAL)cardRc.left, (REAL)cardRc.top,
                     (REAL)(cardRc.right - cardRc.left),
                     (REAL)(cardRc.bottom - cardRc.top));
            GraphicsPath path;
            GpRoundPath(path, rf, sk.cardRadius);
            g.SetClip(&path);
            RectF barRf((REAL)cardRc.left, (REAL)cardRc.top, (REAL)barW,
                        (REAL)(cardRc.bottom - cardRc.top));
            LinearGradientBrush lb(barRf, peanut::ui::Gp(ACCENT),
                                   peanut::ui::Gp(ACCENT, 60),
                                   LinearGradientModeVertical);
            g.FillRectangle(&lb, barRf);
            g.ResetClip();
        }

        // 标题与键值区之间的细分隔线
        RECT sep = { dis->rcItem.left + 20, dis->rcItem.top + kCardPad + 38,
                     dis->rcItem.right - 20, dis->rcItem.top + kCardPad + 39 };
        if (sep.right > sep.left) {
            HBRUSH sb = CreateSolidBrush(sk.border);
            FillRect(dis->hDC, &sep, sb);
            DeleteObject(sb);
        }
        return;
    }

    if (dis->hwndItem == hwndDashQuickPanel_) {
        const auto& sk = peanut::ui::g_skin;
        FillRect(dis->hDC, &dis->rcItem, hBrushBg_);

        RECT cardRc = dis->rcItem;
        InflateRect(&cardRc, -kCardPad, -kCardPad);
        if (cardRc.right > cardRc.left && cardRc.bottom > cardRc.top) {
            DrawSoftShadow(dis->hDC, cardRc, sk.cardRadius,
                           sk.shadowSpread, sk.shadowOffsetY, sk.shadowAlpha);
            const COLORREF brd = peanut::ui::MixColor(sk.border, BG_CARD,
                                                      1.0f - sk.cardBorderAlpha);
            FillRoundRect(dis->hDC, cardRc, sk.cardRadius,
                          BG_CARD, BG_CARD2, true, brd, 1.0f);
        }
        return;
    }

    if (dis->hwndItem == hwndFwRuleCard_ || isSettingsGroup) {
        const auto& sk = peanut::ui::g_skin;
        // 先擦成面板底色，圆角之外无残留
        FillRect(dis->hDC, &dis->rcItem, hBrushBg_);

        RECT cardRc = dis->rcItem;
        InflateRect(&cardRc, -1, -1);
        if (cardRc.right > cardRc.left && cardRc.bottom > cardRc.top) {
            // 设置页分组与面板同底色（其子控件背景即面板色），靠描边 + 顶部高光区分
            COLORREF topC = isSettingsGroup ? BG_DEEP : BG_CARD;
            COLORREF botC = isSettingsGroup ? BG_DEEP : BG_CARD2;
            COLORREF brd  = isSettingsGroup ? BORDER
                                            : peanut::ui::ShadeColor(BG_CARD2, 0.12f);
            FillRoundRect(dis->hDC, cardRc, sk.cardRadius, topC, botC, true, brd, 1.0f);

            if (cardRc.bottom - cardRc.top > 10) {
                Graphics g(dis->hDC);
                g.SetSmoothingMode(SmoothingModeAntiAlias);
                RectF rf((REAL)cardRc.left, (REAL)cardRc.top,
                         (REAL)(cardRc.right - cardRc.left),
                         (REAL)(cardRc.bottom - cardRc.top));
                GraphicsPath path;
                GpRoundPath(path, rf, sk.cardRadius);
                g.SetClip(&path);
                RectF tl((REAL)cardRc.left, (REAL)cardRc.top,
                         (REAL)(cardRc.right - cardRc.left), 2.0f);
                LinearGradientBrush lb(tl, peanut::ui::Gp(ACCENT),
                                       peanut::ui::Gp(ACCENT2),
                                       LinearGradientModeHorizontal);
                g.FillRectangle(&lb, tl);
                g.ResetClip();
            }
        }
        // 绘制标题文字（左上角）
        if (isSettingsGroup) {
            wchar_t title[128] = {};
            GetWindowTextW(dis->hwndItem, title, 128);
            if (title[0]) {
                // 标题放在卡片内部（窗口矩形之外的内容会被裁掉，
                // 所以不能像 fieldset 那样骑在边框上），并在其下压一条细分隔线
                HFONT oldF = static_cast<HFONT>(SelectObject(dis->hDC, hFontSectionTitle_));
                SetBkMode(dis->hDC, TRANSPARENT);
                SetTextColor(dis->hDC, TEXT_PRIMARY);
                RECT tr = { dis->rcItem.left + 18, dis->rcItem.top + 10,
                            dis->rcItem.right - 18, dis->rcItem.top + 40 };
                DrawTextW(dis->hDC, title, -1, &tr,
                          DT_LEFT | DT_VCENTER | DT_SINGLELINE);
                if (oldF) SelectObject(dis->hDC, oldF);

                RECT sep = { dis->rcItem.left + 18, dis->rcItem.top + 44,
                             dis->rcItem.right - 18, dis->rcItem.top + 45 };
                if (sep.right > sep.left) {
                    HBRUSH sb = CreateSolidBrush(sk.border);
                    FillRect(dis->hDC, &sep, sb);
                    DeleteObject(sb);
                }
            }
        }
        return;
    }

    // 统计卡片面板
    for (auto& sc : statCards_) {
        if (sc.hwndPanel == dis->hwndItem) {
            const auto& sk = peanut::ui::g_skin;
            FillRect(dis->hDC, &dis->rcItem, hBrushBg_);

            // 视觉卡片 = 窗口内缩 kCardPad，让出的空间用于落影
            RECT cardRc = dis->rcItem;
            InflateRect(&cardRc, -kCardPad, -kCardPad);
            if (cardRc.right > cardRc.left && cardRc.bottom > cardRc.top) {
                DrawSoftShadow(dis->hDC, cardRc, sk.cardRadius,
                               sk.shadowSpread, sk.shadowOffsetY, sk.shadowAlpha);

                const COLORREF brd = peanut::ui::MixColor(sk.border, BG_CARD,
                                                          1.0f - sk.cardBorderAlpha);
                FillRoundRect(dis->hDC, cardRc, sk.cardRadius,
                              BG_CARD, BG_CARD2, true, brd, 1.0f);

                // 左侧强调条（圆角内裁切，向下渐隐）
                const int barW = sk.accentBarW > 0 ? sk.accentBarW : 3;
                Graphics g(dis->hDC);
                g.SetSmoothingMode(SmoothingModeAntiAlias);
                RectF rf((REAL)cardRc.left, (REAL)cardRc.top,
                         (REAL)(cardRc.right - cardRc.left),
                         (REAL)(cardRc.bottom - cardRc.top));
                GraphicsPath path;
                GpRoundPath(path, rf, sk.cardRadius);
                g.SetClip(&path);
                RectF barRf((REAL)cardRc.left, (REAL)cardRc.top, (REAL)barW,
                            (REAL)(cardRc.bottom - cardRc.top));
                LinearGradientBrush lb(barRf, peanut::ui::Gp(sc.accentColor),
                                       peanut::ui::Gp(sc.accentColor, 60),
                                       LinearGradientModeVertical);
                g.FillRectangle(&lb, barRf);
                g.ResetClip();

                // 图标容器：强调柔光底 + 居中矢量图标（与数值行居中对齐）
                const int chipS = 34;
                const int chipX = cardRc.left + 16;
                const int chipY = (cardRc.top + cardRc.bottom - chipS) / 2;
                RECT chip = { chipX, chipY, chipX + chipS, chipY + chipS };
                FillRoundRect(dis->hDC, chip, 9.0f,
                              peanut::ui::MixColor(sc.accentColor, BG_CARD,  0.86f),
                              peanut::ui::MixColor(sc.accentColor, BG_CARD2, 0.86f),
                              false, 0, 0);
                if (sc.iconGlyph && sc.iconGlyph[0]) {
                    const int is = 18;
                    RectF ib((REAL)(chipX + (chipS - is) / 2),
                             (REAL)(chipY + (chipS - is) / 2),
                             (REAL)is, (REAL)is);
                    peanut::ui::DrawIcon(g, sc.iconGlyph, ib,
                                         peanut::ui::Gp(sc.accentColor), 1.9f);
                }
            }
            return;
        }
    }

    // 普通按钮：按"角色"绘制（primary / secondary / ghost / danger / toggle）
    if (dis->CtlType == ODT_BUTTON) {
        // 按钮所在容器底色，用于填充圆角之外
        HWND par = GetParent(dis->hwndItem);
        COLORREF surface = BG_DEEP;
        if (par == hwndPanelLogs_) surface = BG_LOG;
        else if (par == hwndDashQuickPanel_ || par == hwndFwRuleCard_) surface = BG_CARD;
        else {
            for (auto& sc : statCards_) {
                if (sc.hwndPanel == par) { surface = BG_CARD; break; }
            }
        }
        DrawOwnerButton(dis->hDC, dis->hwndItem, dis->rcItem, dis->itemState,
                        surface, hFontButton_);
        return;
    }

}

// ═══════════════════════════════════════════════════════════
//  定时器 (时钟)
// ═══════════════════════════════════════════════════════════
void MainWindow::OnTimer(WPARAM wp) {
    if (wp == TIMER_CLOCK) {
        UpdateStatusBar();
        // 在线状态每秒轮询；超过60秒未收到合格心跳即删除陈旧会话并显示灰点。
        bool onlineSetChanged = false;
        { std::lock_guard<std::mutex> lock(serverSessionsMutex_); time_t now=time(nullptr); for(auto it=serverSessions_.begin();it!=serverSessions_.end();){if(it->second.last_heartbeat>0&&now-it->second.last_heartbeat>60){it=serverSessions_.erase(it);onlineSetChanged=true;}else ++it;} }
        if (onlineSetChanged && activeTab_ == NavTab::CardMgmt) RefreshCardList();
        // 仪表盘自动刷新（每 3 秒）
        static int dashTicker = 0;
        if (++dashTicker >= 3) {
            dashTicker = 0;
            if (activeTab_ == NavTab::Dashboard) {
                UpdateDashboardStats();
            }
        }
    }
}

// ═══════════════════════════════════════════════════════════
//  状态栏更新
// ═══════════════════════════════════════════════════════════
void MainWindow::UpdateStatusBar() {
    if (!hwndStatusBar_) return;
    // 以 config_ 为准，避免与设置页脱节
    protocolMode_ = config_.protocol_mode;
    statusParts_[0] = serverRunning_
        ? (L"● 服务端运行中 :" + std::to_wstring(config_.port))
        : L"○ 服务端未启动";
    statusParts_[1] = L"协议: " + std::wstring(config_.protocol_mode == 1 ? L"HTTP" : L"TCP");
    statusParts_[2] = L"卡密: " + std::to_wstring(cards_.size()) + L" 张";

    time_t now = time(nullptr);
    struct tm tm_now;
    localtime_s(&tm_now, &now);
    wchar_t clockBuf[32];
    wcsftime(clockBuf, 32, L"%H:%M:%S", &tm_now);
    statusParts_[3] = clockBuf;

    InvalidateRect(hwndStatusBar_, nullptr, FALSE);
}

// ═══════════════════════════════════════════════════════════
//  卡密列表
// ═══════════════════════════════════════════════════════════
void MainWindow::RefreshCardList() {
    if (!hwndCardList_) return;
    ListView_DeleteAllItems(hwndCardList_);

    // 筛选: 0全部 1激活 2过期 3禁用
    int filter = cardFilterIndex_;

    // 搜索
    wchar_t searchBuf[256] = {};
    if (hwndCardSearchEdit_) GetWindowTextW(hwndCardSearchEdit_, searchBuf, 256);
    std::wstring filterText(searchBuf);

    const wchar_t* typeNames[] = { L"天", L"小时", L"月", L"年", L"永久" };
    const wchar_t* statusNames[] = { L"未使用", L"已激活", L"已过期", L"已禁用" };

    // 紧凑表格：时间列只留「月-日 时:分」，去掉年份和秒（完整值在详情里看）
    auto shortTime = [](const std::string& s) -> std::wstring {
        std::wstring w = wstring_from_utf8(s);
        if (w.size() >= 16 && w[4] == L'-' && w[7] == L'-' && w[10] == L' ')
            return w.substr(5, 5) + L" " + w.substr(11, 5);
        return w;
    };

    for (auto& card : cards_) {
        // 筛选
        if (filter == 1 && card.status != 1) continue;
        if (filter == 2 && card.status != 2) continue;
        if (filter == 3 && card.status != 3) continue;

        std::wstring cardKey = wstring_from_utf8(card.cardkey);
        std::wstring machineCode = wstring_from_utf8(card.machine_code);
        std::wstring remark = wstring_from_utf8(card.remark);
        if (!filterText.empty()) {
            if (cardKey.find(filterText) == std::wstring::npos &&
                machineCode.find(filterText) == std::wstring::npos &&
                remark.find(filterText) == std::wstring::npos) continue;
        }

        std::wstring typeStr = (card.duration_type >= 0 && card.duration_type < 5)
            ? typeNames[card.duration_type] : L"未知";
        std::wstring durStr = (card.duration_type == 4) ? L"永久" :
            std::to_wstring(card.duration_value) + L" " + typeStr;
        std::wstring statusStr = (card.status >= 0 && card.status < 4)
            ? statusNames[card.status] : L"未知";

        bool online=false;{std::lock_guard<std::mutex> lock(serverSessionsMutex_);time_t now=time(nullptr);for(const auto& item:serverSessions_)if(item.second.cardkey==card.cardkey&&item.second.tcp_connection!=0&&item.second.last_heartbeat>0&&now-item.second.last_heartbeat<=60){online=true;break;}}
        std::vector<std::wstring> cols = {
            cardKey,
            typeStr,
            durStr,
            statusStr,
            machineCode,
            shortTime(card.activate_time),
            shortTime(card.expire_time),
            remark
        };
        int row=ListView_GetItemCount(hwndCardList_);w32::ListView_AddRow(hwndCardList_, cols);if(hwndCardStateImages_){LVITEMW item{};item.mask=LVIF_IMAGE;item.iItem=row;item.iSubItem=0;item.iImage=online?1:0;ListView_SetItem(hwndCardList_,&item);}
    }
}

void MainWindow::CopySelectedCards() {
    auto indices = w32::ListView_GetSelectedIndices(hwndCardList_);
    if (indices.empty()) {
        LogWarning("No cards selected");
        return;
    }
    std::wstring clipboard;
    for (int idx : indices) {
        auto row = w32::ListView_GetRowText(hwndCardList_, idx);
        if (!row.empty()) {
            clipboard += row[0];
            clipboard += L"\r\n";
        }
    }
    w32::Clipboard_SetText(clipboard);
    LogSuccess("Copied " + std::to_string(indices.size()) + " card(s) to clipboard");
}

void MainWindow::SelectAllCards() {
    w32::ListView_SelectAll(hwndCardList_, true);
}

void MainWindow::DeselectAllCards() {
    w32::ListView_SelectAll(hwndCardList_, false);
}

void MainWindow::UnbindSelectedCards() {
    auto indices = w32::ListView_GetSelectedIndices(hwndCardList_);
    if (indices.empty()) return;
    int ret = MessageBoxW(hwndMain_,
        (L"确定解绑选中的 " + std::to_wstring(indices.size()) + L" 条卡密？").c_str(),
        L"确认解绑", MB_YESNO | MB_ICONWARNING);
    if (ret != IDYES) return;

    for (int idx : indices) {
        auto row = w32::ListView_GetRowText(hwndCardList_, idx);
        if (row.empty()) continue;
        std::string key = utf8_from_wstring(row[0]);
        for (auto& c : cards_) {
            if (c.cardkey == key) {
                c.machine_code.clear();
                c.status = 0;
                c.activate_time.clear();
                { std::lock_guard<std::mutex> sessionLock(serverSessionsMutex_); for(auto it=serverSessions_.begin();it!=serverSessions_.end();){if(it->second.cardkey==key)it=serverSessions_.erase(it);else ++it;} }
                LogSuccess("已解绑: " + key);
                break;
            }
        }
    }
    SaveCards();
    RefreshCardList();
    UpdateDashboardStats();
}

void MainWindow::EditSelectedCardRemark() {
    auto indices = w32::ListView_GetSelectedIndices(hwndCardList_);
    if (indices.size() != 1) { LogWarning("请选择一条卡密修改备注"); return; }
    auto row = w32::ListView_GetRowText(hwndCardList_, indices[0]);
    if (row.empty()) return;
    std::string key = utf8_from_wstring(row[0]);
    CardEntry* target = nullptr;
    for (auto& card : cards_) if (card.cardkey == key) { target = &card; break; }
    if (!target) return;

    wchar_t value[256] = {};
    std::wstring current = wstring_from_utf8(target->remark);
    wcsncpy_s(value, current.c_str(), _TRUNCATE);
    const wchar_t* cls = L"PeanutRemarkEditDialog";
    static bool registered = false;
    if (!registered) {
        WNDCLASSEXW wc{sizeof(wc)}; wc.hInstance=GetModuleHandleW(nullptr); wc.hCursor=LoadCursor(nullptr,IDC_ARROW); wc.lpszClassName=cls;
        wc.lpfnWndProc=[](HWND hwnd,UINT msg,WPARAM wp,LPARAM lp)->LRESULT {
            if(msg==WM_CREATE){auto* cs=reinterpret_cast<CREATESTRUCTW*>(lp);auto* text=reinterpret_cast<wchar_t*>(cs->lpCreateParams);CreateWindowExW(0,L"STATIC",L"备注（可为空）:",WS_CHILD|WS_VISIBLE,18,18,130,24,hwnd,nullptr,nullptr,nullptr);HWND edit=CreateWindowExW(0,L"EDIT",text,WS_CHILD|WS_VISIBLE|ES_AUTOHSCROLL,18,46,350,30,hwnd,(HMENU)1,nullptr,nullptr);SetFocus(edit);CreateWindowExW(0,L"BUTTON",L"保存",WS_CHILD|WS_VISIBLE|BS_DEFPUSHBUTTON,176,92,92,30,hwnd,(HMENU)IDOK,nullptr,nullptr);CreateWindowExW(0,L"BUTTON",L"取消",WS_CHILD|WS_VISIBLE,276,92,92,30,hwnd,(HMENU)IDCANCEL,nullptr,nullptr);return 0;}
            if(msg==WM_COMMAND){if(LOWORD(wp)==IDOK){auto* text=reinterpret_cast<wchar_t*>(GetWindowLongPtrW(hwnd,GWLP_USERDATA));GetWindowTextW(GetDlgItem(hwnd,1),text,256);SetWindowLongPtrW(hwnd,DWLP_MSGRESULT,IDOK);DestroyWindow(hwnd);return 0;}if(LOWORD(wp)==IDCANCEL){DestroyWindow(hwnd);return 0;}}
            if(msg==WM_CLOSE){DestroyWindow(hwnd);return 0;} return DefWindowProcW(hwnd,msg,wp,lp);}; RegisterClassExW(&wc);registered=true;
    }
    RECT pr{};GetWindowRect(hwndMain_,&pr);HWND dlg=CreateWindowExW(WS_EX_DLGMODALFRAME,cls,L"修改卡密备注",WS_POPUP|WS_CAPTION|WS_SYSMENU,pr.left+200,pr.top+180,400,170,hwndMain_,nullptr,GetModuleHandleW(nullptr),value);
    if(!dlg)return;SetWindowLongPtrW(dlg,GWLP_USERDATA,reinterpret_cast<LONG_PTR>(value));EnableWindow(hwndMain_,FALSE);ShowWindow(dlg,SW_SHOW);MSG msg;while(IsWindow(dlg)&&GetMessageW(&msg,nullptr,0,0)>0){if(!IsDialogMessageW(dlg,&msg)){TranslateMessage(&msg);DispatchMessageW(&msg);}}EnableWindow(hwndMain_,TRUE);SetForegroundWindow(hwndMain_);
    target->remark = utf8_from_wstring(value);
    std::replace(target->remark.begin(), target->remark.end(), '|', '/');
    std::replace(target->remark.begin(), target->remark.end(), '\r', ' ');
    std::replace(target->remark.begin(), target->remark.end(), '\n', ' ');
    SaveCards(); RefreshCardList(); LogSuccess("卡密备注已更新");
}

void MainWindow::DeleteSelectedCards() {
    auto indices = w32::ListView_GetSelectedIndices(hwndCardList_);
    if (indices.empty()) return;
    int ret = MessageBoxW(hwndMain_,
        (L"确定删除选中的 " + std::to_wstring(indices.size()) + L" 条卡密？").c_str(),
        L"确认删除", MB_YESNO | MB_ICONWARNING);
    if (ret != IDYES) return;

    std::vector<std::string> keys;
    for (int idx : indices) {
        auto row = w32::ListView_GetRowText(hwndCardList_, idx);
        if (!row.empty())
            keys.push_back(utf8_from_wstring(row[0]));
    }
    cards_.erase(std::remove_if(cards_.begin(), cards_.end(),
        [&](const CardEntry& c) {
            return std::find(keys.begin(), keys.end(), c.cardkey) != keys.end();
        }), cards_.end());
    SaveCards();
    RefreshCardList();
    UpdateDashboardStats();
    for (auto& k : keys) LogSuccess("已删除卡密: " + k);
}

std::string MainWindow::GenerateCardKey(const std::string& prefix) {
    static const char alphabet[] = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
    constexpr int BODY_LEN = 24;
    constexpr int GROUP_LEN = 4;
    std::string key = prefix;
    for (int i = 0; i < BODY_LEN; ++i) {
        if (i > 0 && i % GROUP_LEN == 0) key += '-';
        key += alphabet[rand() % (sizeof(alphabet) - 1)];
    }
    return key;
}

void MainWindow::SaveCards() {
    namespace fs = std::filesystem;
    fs::path base(ConfigIniPath()), dir = base.parent_path() / L"cards";
    std::error_code ec; fs::create_directories(dir, ec);
    if (ec) { LogError("创建卡密数据目录失败"); return; }
    std::map<std::wstring, bool> expected;
    for (const auto& c : cards_) {
        if (c.cardkey.empty() || c.cardkey.size() > 64 || !std::all_of(c.cardkey.begin(), c.cardkey.end(), [](unsigned char ch) { return std::isalnum(ch) || ch == '-' || ch == '_'; })) { LogWarning("跳过文件名不安全的卡密记录"); continue; }
        std::wstring name(c.cardkey.begin(), c.cardkey.end()); name += L".json"; expected[name] = true;
        nlohmann::json j={{"cardkey",c.cardkey},{"duration_type",c.duration_type},{"duration_value",c.duration_value},{"status",c.status},{"machine_code",c.machine_code},{"activate_time",c.activate_time},{"expire_time",c.expire_time},{"usage_count",c.usage_count},{"remark",c.remark},{"schema_version",1}};
        fs::path target=dir/name, temp=target; temp += L".tmp";
        { std::ofstream out(temp,std::ios::binary|std::ios::trunc); if(!out) continue; out << j.dump(2); }
        fs::remove(target,ec); ec.clear(); fs::rename(temp,target,ec);
        if(ec){fs::remove(temp,ec);LogError("保存卡密JSON失败: "+c.cardkey);}
    }
    for(const auto& entry:fs::directory_iterator(dir,ec)) if(entry.is_regular_file()&&entry.path().extension()==L".json"&&expected.find(entry.path().filename().wstring())==expected.end()) fs::remove(entry.path(),ec);
}

void MainWindow::LoadCards() {
    namespace fs = std::filesystem;
    fs::path base(ConfigIniPath()), dir=base.parent_path()/L"cards"; std::error_code ec;
    cards_.clear();
    if(fs::is_directory(dir,ec)){
        for(const auto& entry:fs::directory_iterator(dir,ec)){
            if(!entry.is_regular_file()||entry.path().extension()!=L".json")continue;
            try{std::ifstream in(entry.path(),std::ios::binary);nlohmann::json j;in>>j;CardEntry c;c.cardkey=j.value("cardkey","");c.duration_type=j.value("duration_type",0);c.duration_value=j.value("duration_value",0);c.status=j.value("status",0);c.machine_code=j.value("machine_code","");c.activate_time=j.value("activate_time","");c.expire_time=j.value("expire_time","");c.usage_count=j.value("usage_count",0);c.remark=j.value("remark","");if(!c.cardkey.empty())cards_.push_back(std::move(c));}catch(...){LogWarning("忽略损坏的卡密JSON文件");}
        }
        if(!cards_.empty()){fs::path legacy=base.parent_path()/L"peanut_cards.txt";if(fs::exists(legacy,ec)){fs::path migrated=legacy;migrated+=L".migrated";fs::rename(legacy,migrated,ec);}return;}
    }
    fs::path legacy=base.parent_path()/L"peanut_cards.txt"; std::ifstream ifs(legacy,std::ios::binary); if(!ifs)return;
    std::string line;
    while (std::getline(ifs, line)) {
        if (line.empty()) continue;
        CardEntry c;
        std::stringstream ss(line);
        std::string part;
        if (!std::getline(ss, c.cardkey, '|')) continue;
        if (!std::getline(ss, part, '|')) continue; c.duration_type = std::atoi(part.c_str());
        if (!std::getline(ss, part, '|')) continue; c.duration_value = std::atoi(part.c_str());
        if (!std::getline(ss, part, '|')) continue; c.status = std::atoi(part.c_str());
        if (!std::getline(ss, c.machine_code, '|')) c.machine_code.clear();
        if (!std::getline(ss, c.activate_time, '|')) c.activate_time.clear();
        if (!std::getline(ss, c.expire_time, '|')) c.expire_time.clear();
        if (std::getline(ss, part, '|')) c.usage_count = std::atoi(part.c_str());
        if (std::getline(ss, c.remark)) {} else c.remark.clear();
        cards_.push_back(std::move(c));
    }
    if(!cards_.empty()){ifs.close();SaveCards();fs::path migrated=legacy;migrated+=L".migrated";fs::rename(legacy,migrated,ec);LogSuccess("旧卡密数据已迁移为一卡一JSON文件");}
}

void MainWindow::ShowCardDetail(int index) {
    if (!hwndCardDetailLog_ || index < 0) return;
    auto row = w32::ListView_GetRowText(hwndCardList_, index);
    std::wstring detail = L"=== 卡密详情 ===\r\n";
    const wchar_t* colNames[] = { L"卡密", L"类型", L"时长", L"状态",
                                   L"机器码", L"激活时间", L"到期时间", L"备注" };
    for (size_t i = 0; i < row.size() && i < _countof(colNames); ++i) {
        detail += std::wstring(colNames[i]) + L": " + row[i] + L"\r\n";
    }
    SetWindowText(hwndCardDetailLog_, detail.c_str());
}

// ============================================================
//  暗色主题落地（子面板 CTLCOLOR + ListView/Edit 去白）
// ============================================================
void MainWindow::ApplyDarkTheme() {
    auto subclass = [](HWND hwnd) {
        if (hwnd) SetWindowSubclass(hwnd, DarkParentProc, 1, 0);
    };

    subclass(hwndTopNav_);
    subclass(hwndContentArea_);
    subclass(hwndPanelDashboard_);
    subclass(hwndPanelCardMgmt_);
    subclass(hwndPanelPlugin_);
    subclass(hwndPanelSettings_);
    subclass(hwndPanelFirewall_);
    subclass(hwndPanelLogs_);
    subclass(hwndCardBottomBtns_);
    subclass(hwndDashQuickPanel_);
    subclass(hwndDashOverviewPanel_);
    subclass(hwndFwRuleCard_);
    for (auto& sc : statCards_)
        subclass(sc.hwndPanel);

    // ListView：深色底，去掉刺眼白网格线，暗色表头
    auto darkLv = [&](HWND lv) {
        if (!lv) return;
        w32::ApplyDarkListView(lv, BG_INPUT, TEXT_PRIMARY);
        ListView_SetExtendedListViewStyle(lv,
            LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER);
        HWND hdr = ListView_GetHeader(lv);
        if (hdr) {
            SendMessage(hdr, WM_SETFONT, (WPARAM)hFontHeader_, TRUE);
            SetWindowTheme(hdr, L"", L"");
            SetWindowSubclass(hdr, DarkHeaderProc, 2, 0);
        }
    };
    darkLv(hwndCardList_);
    darkLv(hwndPluginList_);
    darkLv(hwndFwIpList_);

    w32::ApplyDarkEdit(hwndCardSearchEdit_);
    w32::ApplyDarkEdit(hwndCardDetailLog_);
    w32::ApplyDarkEdit(hwndSettHostEdit_);
    w32::ApplyDarkEdit(hwndSettPortEdit_);
    w32::ApplyDarkEdit(hwndSettHmacEdit_);
    w32::ApplyDarkEdit(hwndSettAesEdit_);
    w32::ApplyDarkEdit(hwndSettPspEdit_);
    w32::ApplyDarkEdit(hwndSettPermDayEdit_);
    w32::ApplyDarkEdit(hwndSettPermMonEdit_);
    w32::ApplyDarkEdit(hwndSettMaxOnlineEdit_);
    w32::ApplyDarkEdit(hwndSettFwAttemptEdit_);
    w32::ApplyDarkEdit(hwndSettFwWindowEdit_);
    w32::ApplyDarkEdit(hwndSettFwBanEdit_);
    w32::ApplyDarkEdit(hwndPluginParamEdit_);

    if (hwndLogEdit_) {
        SendMessage(hwndLogEdit_, EM_SETBKGNDCOLOR, 0, static_cast<LPARAM>(BG_LOG));
        SetWindowTheme(hwndLogEdit_, L"DarkMode_Explorer", nullptr);
    }
    if (hwndLogAutoScrollChk_)
        SetWindowTheme(hwndLogAutoScrollChk_, L"", L"");

    // 设置页 GroupBox / 单选去系统浅色
    if (hwndPanelSettings_) {
        for (HWND c = GetWindow(hwndPanelSettings_, GW_CHILD); c; c = GetWindow(c, GW_HWNDNEXT)) {
            wchar_t cls[64] = {};
            GetClassNameW(c, cls, 64);
            if (_wcsicmp(cls, L"Button") == 0)
                SetWindowTheme(c, L"", L"");
        }
    }

    // ── 按钮角色 + 图标 ────────────────────────────────────
    // 规则：一屏只有一个 primary；破坏性操作 danger；工具/次要用 ghost；
    //       开关用 toggle。图标只加在宽度足够的按钮上。
    struct BtnSpec { HWND h; int role; const wchar_t* icon; };
    const BtnSpec specs[] = {
        // 仪表盘快捷操作
        { hwndDashGenerateBtn_, BTN_PRIMARY,   L"plus"    },
        { hwndDashRefreshBtn_,  BTN_GHOST,     L"refresh" },
        // 卡密管理工具栏
        { hwndCardSearchBtn_,   BTN_SECONDARY, L"search"  },
        { hwndCardFilterBtn_,   BTN_SECONDARY, L"filter"  },
        { hwndCardGenerateBtn_, BTN_PRIMARY,   L"plus"    },
        { hwndCardImportBtn_,   BTN_SECONDARY, L"import"  },
        { hwndCardExportBtn_,   BTN_SECONDARY, L"export"  },
        { hwndCardUnbindBtn_,   BTN_SECONDARY, L"unlink"  },
        { hwndCardDeleteBtn_,   BTN_DANGER,    L"trash"   },
        { GetDlgItem(hwndPanelCardMgmt_, IDC_CARD_REMARK_BTN), BTN_SECONDARY, L"note" },
        { GetDlgItem(hwndCardBottomBtns_, IDC_CARD_SELECT_ALL),    BTN_GHOST, nullptr },
        { GetDlgItem(hwndCardBottomBtns_, IDC_CARD_DESELECT_ALL),  BTN_GHOST, nullptr },
        { GetDlgItem(hwndCardBottomBtns_, IDC_CARD_COPY_SELECTED), BTN_GHOST, L"copy" },
        // 插件中心
        { hwndPluginRefreshBtn_, BTN_SECONDARY, L"refresh" },
        { hwndPluginExecBtn_,    BTN_PRIMARY,   L"play"    },
        // 日志
        { hwndLogClearBtn_,      BTN_GHOST,     nullptr   },
        { hwndLogExportBtn_,     BTN_GHOST,     L"export" },
        { hwndLogAutoScrollChk_, BTN_TOGGLE,    nullptr   },
    };
    for (const auto& b : specs) {
        if (!b.h) continue;
        SetBtnRole(b.h, b.role);
        if (b.icon) SetBtnIcon(b.h, b.icon);
        if (b.role == BTN_PRIMARY || b.role == BTN_DANGER)
            SetBtnAccent(b.h, b.role == BTN_DANGER ? ERROR_COLOR : ACCENT);
    }
    SetBtnChecked(hwndLogAutoScrollChk_, logAutoScroll_);

    // 所有自绘按钮挂上 hover 追踪，获得悬停高亮反馈
    {
        auto attachHover = [](HWND parent) {
            if (!parent) return;
            for (HWND c = GetWindow(parent, GW_CHILD); c; c = GetWindow(c, GW_HWNDNEXT)) {
                wchar_t cls[64] = {};
                GetClassNameW(c, cls, 64);
                if (_wcsicmp(cls, L"Button") != 0) continue;
                const LONG style = GetWindowLongW(c, GWL_STYLE);
                if ((style & BS_TYPEMASK) != BS_OWNERDRAW) continue;
                SetWindowSubclass(c, BtnHoverProc, 7, 0);
            }
        };
        attachHover(hwndMain_);
        attachHover(hwndTopNav_);
        attachHover(hwndContentArea_);
        attachHover(hwndPanelDashboard_);
        attachHover(hwndDashQuickPanel_);
        attachHover(hwndPanelCardMgmt_);
        attachHover(hwndCardBottomBtns_);
        attachHover(hwndPanelPlugin_);
        attachHover(hwndPanelSettings_);
        attachHover(hwndPanelFirewall_);
        attachHover(hwndFwRuleCard_);
        attachHover(hwndPanelLogs_);
        for (auto& sc : statCards_) attachHover(sc.hwndPanel);
    }

    // Edit 边框统一（内部按亮/暗皮肤决定是否接管）
    {
        auto attachEdit = [](HWND parent) {
            if (!parent) return;
            for (HWND c = GetWindow(parent, GW_CHILD); c; c = GetWindow(c, GW_HWNDNEXT)) {
                wchar_t cls[64] = {};
                GetClassNameW(c, cls, 64);
                if (_wcsicmp(cls, L"Edit") == 0) {
                    SetWindowSubclass(c, EditBorderProc, 8, 0);
                    RedrawWindow(c, nullptr, nullptr,
                                 RDW_FRAME | RDW_INVALIDATE | RDW_ERASE);
                }
            }
        };
        attachEdit(hwndMain_);
        attachEdit(hwndDashQuickPanel_);
        attachEdit(hwndPanelCardMgmt_);
        attachEdit(hwndPanelSettings_);
        attachEdit(hwndPanelFirewall_);
    }

    InvalidateRect(hwndMain_, nullptr, TRUE);
}

// ============================================================
//  本地插件 (scan plugins/*.dll, load & exec locally)
// ============================================================
void MainWindow::ScanLocalPlugins() {
    // 先卸载之前加载的所有 DLL
    for (auto& plg : local_plugins_) {
        if (plg.destroy) plg.destroy();
        if (plg.module) FreeLibrary(plg.module);
    }
    local_plugins_.clear();

    std::string dir = "plugins";
    std::string pattern = dir + "\\*.dll";
    WIN32_FIND_DATAA ffd;
    HANDLE hFind = FindFirstFileA(pattern.c_str(), &ffd);
    if (hFind == INVALID_HANDLE_VALUE) {
        Log("[本地插件] plugins/ 目录未找到 DLL 文件");
        RefreshLocalPluginListUI();
        return;
    }

    int loaded = 0;
    do {
        if (!(ffd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
            std::string fullPath = dir + "\\" + ffd.cFileName;
            HMODULE hMod = LoadLibraryA(fullPath.c_str());
            if (!hMod) {
                LogWarning("[本地插件] 加载失败: " + std::string(ffd.cFileName));
                continue;
            }
            LocalPlugin plg;
            plg.filename = ffd.cFileName;
            plg.module = hMod;
            plg.exec = (int (*)(const char*, int, int*, char**))
                GetProcAddress(hMod, "PluginExecute");
            plg.free = (void (*)(char*))
                GetProcAddress(hMod, "PluginFree");
            plg.destroy = (void (*)())
                GetProcAddress(hMod, "PluginDestroy");
            auto getFunctionCount = (int (*)())GetProcAddress(hMod, "PluginGetFunctionCount");
            plg.function_count = getFunctionCount ? (std::max)(1, getFunctionCount()) : 1;

            if (!plg.exec || !plg.free) {
                LogWarning("[本地插件] 缺少 PluginExecute/PluginFree: " + plg.filename);
                FreeLibrary(hMod);
                continue;
            }

            auto init = (int (*)(const char*))
                GetProcAddress(hMod, "PluginInit");
            if (init) init("{}");

            // 尝试获取元信息
            auto getInfo = (int (*)(char**, char**, char**, char**))
                GetProcAddress(hMod, "PluginGetInfo");
            if (getInfo) {
                char *n = nullptr, *v = nullptr, *d = nullptr, *a = nullptr;
                if (getInfo(&n, &v, &d, &a) == 0) {
                    if (n) { plg.name = n; plg.free(n); }
                    if (v) { plg.version = v; plg.free(v); }
                    if (d) { plg.description = d; plg.free(d); }
                    if (a) plg.free(a);
                }
            }
            if (plg.name.empty())
                plg.name = ffd.cFileName;

            local_plugins_.push_back(std::move(plg));
            loaded++;
        }
    } while (FindNextFileA(hFind, &ffd));
    FindClose(hFind);

    if (loaded > 0)
        LogSuccess("[本地插件] 已加载 " + std::to_string(loaded) + " 个本地插件");
    else
        Log("[本地插件] 未找到有效插件 DLL");

    RefreshLocalPluginListUI();
}

void MainWindow::RefreshLocalPluginListUI() {
    if (!hwndPluginList_) return;
    ListView_DeleteAllItems(hwndPluginList_);
    for (auto& plg : local_plugins_) {
        std::vector<std::wstring> cols = {
            wstring_from_utf8(plg.name),
            plg.enabled ? L"已加载" : L"禁用",
            wstring_from_utf8(plg.version),
            std::to_wstring(plg.function_count),
            std::to_wstring(plg.call_count),
            wstring_from_utf8(plg.description)
        };
        w32::ListView_AddRow(hwndPluginList_, cols);
    }
}

void MainWindow::ExecuteSelectedPlugin() {
    int idx = ListView_GetNextItem(hwndPluginList_, -1, LVNI_SELECTED);
    if (idx < 0 || idx >= static_cast<int>(local_plugins_.size())) {
        LogWarning("[本地插件] 请先选择一个插件");
        return;
    }
    auto& plg = local_plugins_[idx];
    if (!plg.enabled || !plg.exec) {
        LogWarning("[本地插件] 插件不可用: " + plg.name);
        return;
    }

    Log("[本地插件] 执行: " + plg.name);
    std::string input;
    if (hwndPluginParamEdit_) {
        wchar_t buf[4096]; GetWindowTextW(hwndPluginParamEdit_, buf, 4096);
        input = utf8_from_wstring(buf);
    }
    if (input.empty()) input = "{}";
    int outLen = 0;
    char* outData = nullptr;
    int rc = plg.exec(input.c_str(), (int)input.size(), &outLen, &outData);
    if (rc == 0 && outData) {
        std::string result(outData, outLen);
        if (plg.free) plg.free(outData);
        LogSuccess("[本地插件] " + plg.name + " 执行成功: " + result);
    } else {
        std::string err = (outData && outLen > 0) ? std::string(outData, outLen) : "未知错误";
        if (plg.free && outData) plg.free(outData);
        LogError("[本地插件] " + plg.name + " 执行失败(" + std::to_string(rc) + "): " + err);
    }
    plg.call_count++;
    RefreshLocalPluginListUI();
}

void MainWindow::Log(const std::string& text, COLORREF color) {
    if (!hwndLogEdit_) return;

    time_t now = time(nullptr);
    struct tm tm_now;
    localtime_s(&tm_now, &now);
    char timeBuf[32];
    strftime(timeBuf, sizeof(timeBuf), "[%H:%M:%S] ", &tm_now);

    int len = GetWindowTextLength(hwndLogEdit_);
    SendMessage(hwndLogEdit_, EM_SETSEL, len, len);

    // 时间戳 (灰色)
    CHARFORMATW cf = {};
    cf.cbSize = sizeof(CHARFORMATW);
    cf.dwMask = CFM_COLOR;
    cf.crTextColor = TEXT_MUTED;

    std::wstring wTime = wstring_from_utf8(timeBuf);
    SendMessage(hwndLogEdit_, EM_SETCHARFORMAT, SCF_SELECTION, reinterpret_cast<LPARAM>(&cf));
    SendMessage(hwndLogEdit_, EM_REPLACESEL, FALSE, reinterpret_cast<LPARAM>(wTime.c_str()));

    // 内容 (指定颜色)
    cf.crTextColor = color;
    SendMessage(hwndLogEdit_, EM_SETCHARFORMAT, SCF_SELECTION, reinterpret_cast<LPARAM>(&cf));
    std::wstring wText = wstring_from_utf8(text);
    SendMessage(hwndLogEdit_, EM_REPLACESEL, FALSE, reinterpret_cast<LPARAM>(wText.c_str()));

    // 换行
    cf.crTextColor = TEXT_PRIMARY;
    SendMessage(hwndLogEdit_, EM_SETCHARFORMAT, SCF_SELECTION, reinterpret_cast<LPARAM>(&cf));
    SendMessage(hwndLogEdit_, EM_REPLACESEL, FALSE, reinterpret_cast<LPARAM>(L"\r\n"));

    if (logAutoScroll_) {
        const int end = GetWindowTextLength(hwndLogEdit_);
        SendMessage(hwndLogEdit_, EM_SETSEL, end, end);
        SendMessage(hwndLogEdit_, EM_SCROLLCARET, 0, 0);
        SendMessage(hwndLogEdit_, WM_VSCROLL, SB_BOTTOM, 0);
    }
}

void MainWindow::LogError(const std::string& text) {
    Log("[ERROR] " + text, ERROR_COLOR);
}

void MainWindow::LogSuccess(const std::string& text) {
    Log("[OK] " + text, SUCCESS);
}

void MainWindow::LogWarning(const std::string& text) {
    Log("[WARN] " + text, WARNING);
}

void MainWindow::ClearLog() {
    if (hwndLogEdit_) SetWindowText(hwndLogEdit_, L"");
}

void MainWindow::ExportLog() {
    if (!hwndLogEdit_) return;

    OPENFILENAMEW ofn = {};
    wchar_t fileBuf[MAX_PATH] = L"peanut_log.txt";
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = hwndMain_;
    ofn.lpstrFilter = L"Text Files (*.txt)\0*.txt\0All Files (*.*)\0*.*\0";
    ofn.lpstrFile = fileBuf;
    ofn.nMaxFile = MAX_PATH;
    ofn.lpstrDefExt = L"txt";
    ofn.Flags = OFN_OVERWRITEPROMPT | OFN_PATHMUSTEXIST;

    if (!GetSaveFileNameW(&ofn)) return;

    int len = GetWindowTextLength(hwndLogEdit_);
    std::vector<wchar_t> buf(len + 1);
    GetWindowText(hwndLogEdit_, buf.data(), len + 1);

    std::string utf8 = utf8_from_wstring(buf.data());
    std::string utf8Path = utf8_from_wstring(fileBuf);
    std::ofstream file(utf8Path);
    if (file.is_open()) {
        file << utf8;
        file.close();
        LogSuccess("Log exported to: " + utf8Path);
    } else {
        LogError("Failed to export log");
    }
}

// ═══════════════════════════════════════════════════════════
//  设置
// ═══════════════════════════════════════════════════════════
void MainWindow::ApplySettingsToUI() {
    if (hwndSettHostEdit_)  SetWindowText(hwndSettHostEdit_,  wstring_from_utf8(config_.host).c_str());
    if (hwndSettPortEdit_)  SetWindowText(hwndSettPortEdit_,  std::to_wstring(config_.port).c_str());
    if (hwndSettHmacEdit_)  SetWindowText(hwndSettHmacEdit_,  wstring_from_utf8(config_.hmac_key).c_str());

    if (hwndSettAesEdit_) {
        std::wstring masked(config_.aes_key_hex.size(), L'*');
        SetWindowText(hwndSettAesEdit_, masked.c_str());
    }
    if (hwndSettPspEdit_) {
        std::wstring masked(config_.psp_key_hex.size(), L'*');
        SetWindowText(hwndSettPspEdit_, masked.c_str());
    }
    if (hwndSettProtoHttp_) SendMessage(hwndSettProtoHttp_, BM_SETCHECK,
        config_.protocol_mode == 1 ? BST_CHECKED : BST_UNCHECKED, 0);
    if (hwndSettProtoTcp_)  SendMessage(hwndSettProtoTcp_,  BM_SETCHECK,
        config_.protocol_mode == 0 ? BST_CHECKED : BST_UNCHECKED, 0);

    if (hwndSettPermUnbind_) SendMessage(hwndSettPermUnbind_, BM_SETCHECK,
        config_.unbind_enabled ? BST_CHECKED : BST_UNCHECKED, 0);
    if (hwndSettPermDayEdit_) SetWindowText(hwndSettPermDayEdit_,
        std::to_wstring(config_.unbind_limit_day).c_str());
    if (hwndSettPermMonEdit_) SetWindowText(hwndSettPermMonEdit_,
        std::to_wstring(config_.unbind_limit_month).c_str());
    if (hwndSettMultiOpen_) SendMessage(hwndSettMultiOpen_, BM_SETCHECK,
        config_.multi_open_enabled ? BST_CHECKED : BST_UNCHECKED, 0);
    if (hwndSettMaxOnlineEdit_) {
        SetWindowText(hwndSettMaxOnlineEdit_,
            std::to_wstring(config_.multi_open_enabled ? config_.max_online_per_card : 1).c_str());
        EnableWindow(hwndSettMaxOnlineEdit_, config_.multi_open_enabled ? TRUE : FALSE);
    }
    if (hwndSettFwAttemptEdit_) SetWindowText(hwndSettFwAttemptEdit_,
        std::to_wstring(config_.fw_max_attempts).c_str());
    if (hwndSettFwWindowEdit_) SetWindowText(hwndSettFwWindowEdit_,
        std::to_wstring(config_.fw_window_minutes).c_str());
    if (hwndSettFwBanEdit_) SetWindowText(hwndSettFwBanEdit_,
        std::to_wstring(config_.fw_ban_minutes).c_str());
    if (hwndSettUpdateEnable_) SendMessage(hwndSettUpdateEnable_, BM_SETCHECK, config_.force_update_enabled ? BST_CHECKED : BST_UNCHECKED, 0);
    if (hwndSettUpdateTarget_) SetWindowText(hwndSettUpdateTarget_, wstring_from_utf8(config_.update_target_file).c_str());
    if (hwndSettUpdateHash_) SetWindowText(hwndSettUpdateHash_, wstring_from_utf8(config_.update_target_sha256).c_str());
    if (hwndSettUpdateUrl_) SetWindowText(hwndSettUpdateUrl_, wstring_from_utf8(config_.update_package_id).c_str());
    if (hwndSettUpdatePackageHash_) SetWindowText(hwndSettUpdatePackageHash_, wstring_from_utf8(config_.update_package_sha256).c_str());

    protocolMode_ = config_.protocol_mode;
}

void MainWindow::SyncProtocolUi() {
    protocolMode_ = config_.protocol_mode;
    UpdateDashboardStats();
    UpdateStatusBar();
    if (hwndStatusBar_) InvalidateRect(hwndStatusBar_, nullptr, FALSE);
}

void MainWindow::ReadSettingsFromUI() {
    wchar_t buf[4096];

    if (hwndSettHostEdit_) { GetWindowText(hwndSettHostEdit_, buf, 4096); config_.host = utf8_from_wstring(buf); }
    if (hwndSettPortEdit_) { GetWindowText(hwndSettPortEdit_, buf, 4096);
        config_.port = std::stoi(std::wstring(buf).empty() ? L"8080" : std::wstring(buf)); }
    if (hwndSettHmacEdit_) { GetWindowText(hwndSettHmacEdit_, buf, 4096); config_.hmac_key = utf8_from_wstring(buf); }
    if (hwndSettProtoHttp_) {
        config_.protocol_mode = (SendMessage(hwndSettProtoHttp_, BM_GETCHECK, 0, 0) == BST_CHECKED) ? 1 : 0;
    }

    if (hwndSettPermUnbind_)
        config_.unbind_enabled = (SendMessage(hwndSettPermUnbind_, BM_GETCHECK, 0, 0) == BST_CHECKED);
    if (hwndSettUpdateEnable_) config_.force_update_enabled = SendMessage(hwndSettUpdateEnable_, BM_GETCHECK, 0, 0) == BST_CHECKED;
    if (hwndSettUpdateTarget_) { GetWindowText(hwndSettUpdateTarget_, buf, 4096); config_.update_target_file = utf8_from_wstring(buf); }
    if (hwndSettUpdateHash_) { GetWindowText(hwndSettUpdateHash_, buf, 4096); config_.update_target_sha256 = utf8_from_wstring(buf); }
    if (hwndSettUpdateUrl_) { GetWindowText(hwndSettUpdateUrl_, buf, 4096); config_.update_package_id = utf8_from_wstring(buf); }
    if (hwndSettUpdatePackageHash_) { GetWindowText(hwndSettUpdatePackageHash_, buf, 4096); config_.update_package_sha256 = utf8_from_wstring(buf); }
    if (hwndSettPermDayEdit_) {
        GetWindowText(hwndSettPermDayEdit_, buf, 4096);
        int v = std::stoi(std::wstring(buf).empty() ? L"1" : std::wstring(buf));
        if (v > 0) config_.unbind_limit_day = v;
    }
    if (hwndSettPermMonEdit_) {
        GetWindowText(hwndSettPermMonEdit_, buf, 4096);
        int v = std::stoi(std::wstring(buf).empty() ? L"3" : std::wstring(buf));
        if (v > 0) config_.unbind_limit_month = v;
    }
    if (hwndSettMultiOpen_)
        config_.multi_open_enabled = SendMessage(hwndSettMultiOpen_, BM_GETCHECK, 0, 0) == BST_CHECKED;
    if (hwndSettMaxOnlineEdit_) {
        GetWindowText(hwndSettMaxOnlineEdit_, buf, 4096);
        int v = std::stoi(std::wstring(buf).empty() ? L"1" : std::wstring(buf));
        config_.max_online_per_card = (std::max)(1, v);
    }
    if (!config_.multi_open_enabled) config_.max_online_per_card = 1;
    if (hwndSettFwAttemptEdit_) {
        GetWindowText(hwndSettFwAttemptEdit_, buf, 4096);
        int v = std::stoi(std::wstring(buf).empty() ? L"5" : std::wstring(buf));
        if (v > 0) config_.fw_max_attempts = v;
    }
    if (hwndSettFwWindowEdit_) {
        GetWindowText(hwndSettFwWindowEdit_, buf, 4096);
        int v = std::stoi(std::wstring(buf).empty() ? L"10" : std::wstring(buf));
        if (v > 0) config_.fw_window_minutes = v;
    }
    if (hwndSettFwBanEdit_) {
        GetWindowText(hwndSettFwBanEdit_, buf, 4096);
        int v = std::stoi(std::wstring(buf).empty() ? L"30" : std::wstring(buf));
        if (v > 0) config_.fw_ban_minutes = v;
    }

    protocolMode_ = config_.protocol_mode;
}

std::wstring MainWindow::ConfigIniPath() {
    wchar_t mod[MAX_PATH] = {};
    GetModuleFileNameW(nullptr, mod, MAX_PATH);
    std::wstring path(mod);
    size_t slash = path.find_last_of(L"\\/");
    if (slash != std::wstring::npos) path = path.substr(0, slash + 1);
    path += L"peanut_gui.ini";
    return path;
}

static std::string IniReadA(const std::wstring& ini, const wchar_t* section,
                            const wchar_t* key, const std::string& def) {
    wchar_t buf[4096] = {};
    int n = MultiByteToWideChar(CP_UTF8, 0, def.c_str(), -1, nullptr, 0);
    std::wstring wdef(n > 0 ? static_cast<size_t>(n - 1) : 0, L'\0');
    if (n > 0) MultiByteToWideChar(CP_UTF8, 0, def.c_str(), -1, &wdef[0], n);
    GetPrivateProfileStringW(section, key, wdef.c_str(), buf, 4096, ini.c_str());
    return utf8_from_wstring(buf);
}

static void IniWriteA(const std::wstring& ini, const wchar_t* section,
                      const wchar_t* key, const std::string& val) {
    WritePrivateProfileStringW(section, key, wstring_from_utf8(val).c_str(), ini.c_str());
}

void MainWindow::LoadConfig() {
    std::wstring ini = ConfigIniPath();
    if (GetFileAttributesW(ini.c_str()) == INVALID_FILE_ATTRIBUTES) {
        protocolMode_ = config_.protocol_mode;
        return;
    }

    config_.host = IniReadA(ini, L"Server", L"host", config_.host);
    config_.port = GetPrivateProfileIntW(L"Server", L"port", config_.port, ini.c_str());
    config_.hmac_key = IniReadA(ini, L"Server", L"hmac_key", config_.hmac_key);
    config_.protocol_mode = GetPrivateProfileIntW(L"Server", L"protocol_mode", config_.protocol_mode, ini.c_str());
    config_.protocol_mode = 0;

    config_.aes_key_hex = IniReadA(ini, L"Crypto", L"cipher_key", config_.aes_key_hex);
    config_.psp_key_hex = IniReadA(ini, L"Crypto", L"psp_key", config_.psp_key_hex);
    config_.rsa_pubkey_hex = IniReadA(ini, L"Crypto", L"rsa_pubkey", config_.rsa_pubkey_hex);
    config_.auth_token  = IniReadA(ini, L"Session", L"auth_token", config_.auth_token);

    config_.log_auto_scroll = GetPrivateProfileIntW(L"UI", L"log_auto_scroll",
        config_.log_auto_scroll ? 1 : 0, ini.c_str()) != 0;
    config_.card_filter = GetPrivateProfileIntW(L"UI", L"card_filter", config_.card_filter, ini.c_str());
    config_.last_nav_tab = GetPrivateProfileIntW(L"UI", L"last_nav_tab", config_.last_nav_tab, ini.c_str());
    config_.window_x = GetPrivateProfileIntW(L"UI", L"window_x", config_.window_x, ini.c_str());
    config_.window_y = GetPrivateProfileIntW(L"UI", L"window_y", config_.window_y, ini.c_str());
    config_.window_w = GetPrivateProfileIntW(L"UI", L"window_w", config_.window_w, ini.c_str());
    config_.window_h = GetPrivateProfileIntW(L"UI", L"window_h", config_.window_h, ini.c_str());

    // 卡密权限
    config_.unbind_enabled = GetPrivateProfileIntW(L"Permissions", L"unbind_enabled",
        config_.unbind_enabled ? 1 : 0, ini.c_str()) != 0;
    config_.unbind_limit_day = GetPrivateProfileIntW(L"Permissions", L"unbind_limit_day",
        config_.unbind_limit_day, ini.c_str());
    config_.unbind_limit_month = GetPrivateProfileIntW(L"Permissions", L"unbind_limit_month",
        config_.unbind_limit_month, ini.c_str());
    config_.multi_open_enabled = GetPrivateProfileIntW(L"Session", L"multi_open_enabled",
        config_.multi_open_enabled ? 1 : 0, ini.c_str()) != 0;
    config_.max_online_per_card = GetPrivateProfileIntW(L"Session", L"max_online_per_card",
        config_.max_online_per_card, ini.c_str());
    if (config_.max_online_per_card < 1) config_.max_online_per_card = 1;
    if (!config_.multi_open_enabled) config_.max_online_per_card = 1;
    // 防火墙
    config_.fw_max_attempts = GetPrivateProfileIntW(L"Firewall", L"max_attempts",
        config_.fw_max_attempts, ini.c_str());
    config_.fw_window_minutes = GetPrivateProfileIntW(L"Firewall", L"window_minutes",
        config_.fw_window_minutes, ini.c_str());
    config_.fw_ban_minutes = GetPrivateProfileIntW(L"Firewall", L"ban_minutes",
        config_.fw_ban_minutes, ini.c_str());
    config_.force_update_enabled = GetPrivateProfileIntW(L"Update", L"force_enabled", 0, ini.c_str()) != 0;
    config_.update_target_file = IniReadA(ini, L"Update", L"target_file", config_.update_target_file);
    config_.update_target_sha256 = IniReadA(ini, L"Update", L"target_sha256", config_.update_target_sha256);
    config_.update_package_id = IniReadA(ini, L"Update", L"package_id", config_.update_package_id);
    config_.update_package_path = IniReadA(ini, L"Update", L"package_path", config_.update_package_path);
    config_.update_package_sha256 = IniReadA(ini, L"Update", L"package_sha256", config_.update_package_sha256);
    config_.update_latest_version = IniReadA(ini, L"Update", L"latest_version", config_.update_latest_version);
    config_.update_minimum_version = IniReadA(ini, L"Update", L"minimum_version", config_.update_minimum_version);
    config_.update_package_size = _atoi64(IniReadA(ini, L"Update", L"package_size", "0").c_str());

    protocolMode_ = config_.protocol_mode;
    if (psp_encoder_)
        psp_encoder_->set_psk_hex(config_.psp_key_hex);

    // UI 控件可能尚未创建
    ApplySettingsToUI();
}

void MainWindow::PersistUiPrefsFromRuntime() {
    config_.log_auto_scroll = logAutoScroll_;
    config_.card_filter = cardFilterIndex_;
    config_.last_nav_tab = static_cast<int>(activeTab_);
    config_.protocol_mode = protocolMode_;
}

void MainWindow::ApplyUiPrefsToRuntime() {
    logAutoScroll_ = config_.log_auto_scroll;
    cardFilterIndex_ = config_.card_filter;
    protocolMode_ = config_.protocol_mode;

    if (hwndLogAutoScrollChk_) {
        SetWindowTextW(hwndLogAutoScrollChk_, logAutoScroll_ ? L"自动滚动" : L"暂停滚动");
        SetBtnChecked(hwndLogAutoScrollChk_, logAutoScroll_);
    }

    static const wchar_t* labels[] = { L"全部", L"已激活", L"已过期", L"已禁用" };
    if (hwndCardFilterBtn_ && cardFilterIndex_ >= 0 && cardFilterIndex_ < 4)
        SetWindowTextW(hwndCardFilterBtn_, labels[cardFilterIndex_]);
}

void MainWindow::CaptureWindowPlacement() {
    if (!hwndMain_ || IsIconic(hwndMain_)) return;
    RECT rc{};
    if (!GetWindowRect(hwndMain_, &rc)) return;
    config_.window_x = rc.left;
    config_.window_y = rc.top;
    config_.window_w = rc.right - rc.left;
    config_.window_h = rc.bottom - rc.top;
}

void MainWindow::SaveConfig() {
    PersistUiPrefsFromRuntime();
    CaptureWindowPlacement();

    std::wstring ini = ConfigIniPath();
    IniWriteA(ini, L"Server", L"host", config_.host);
    WritePrivateProfileStringW(L"Server", L"port",
        std::to_wstring(config_.port).c_str(), ini.c_str());
    IniWriteA(ini, L"Server", L"hmac_key", config_.hmac_key);
    WritePrivateProfileStringW(L"Server", L"protocol_mode",
        std::to_wstring(config_.protocol_mode).c_str(), ini.c_str());

    IniWriteA(ini, L"Crypto", L"cipher_key", config_.aes_key_hex);
    IniWriteA(ini, L"Crypto", L"psp_key", config_.psp_key_hex);
    IniWriteA(ini, L"Crypto", L"rsa_pubkey", config_.rsa_pubkey_hex);

    WritePrivateProfileStringW(L"UI", L"log_auto_scroll",
        config_.log_auto_scroll ? L"1" : L"0", ini.c_str());
    WritePrivateProfileStringW(L"UI", L"card_filter",
        std::to_wstring(config_.card_filter).c_str(), ini.c_str());
    WritePrivateProfileStringW(L"UI", L"last_nav_tab",
        std::to_wstring(config_.last_nav_tab).c_str(), ini.c_str());
    WritePrivateProfileStringW(L"UI", L"window_x",
        std::to_wstring(config_.window_x).c_str(), ini.c_str());
    WritePrivateProfileStringW(L"UI", L"window_y",
        std::to_wstring(config_.window_y).c_str(), ini.c_str());
    WritePrivateProfileStringW(L"UI", L"window_w",
        std::to_wstring(config_.window_w).c_str(), ini.c_str());
    WritePrivateProfileStringW(L"UI", L"window_h",
        std::to_wstring(config_.window_h).c_str(), ini.c_str());

    // 卡密权限
    WritePrivateProfileStringW(L"Permissions", L"unbind_enabled",
        config_.unbind_enabled ? L"1" : L"0", ini.c_str());
    WritePrivateProfileStringW(L"Permissions", L"unbind_limit_day",
        std::to_wstring(config_.unbind_limit_day).c_str(), ini.c_str());
    WritePrivateProfileStringW(L"Permissions", L"unbind_limit_month",
        std::to_wstring(config_.unbind_limit_month).c_str(), ini.c_str());
    WritePrivateProfileStringW(L"Session", L"multi_open_enabled",
        config_.multi_open_enabled ? L"1" : L"0", ini.c_str());
    WritePrivateProfileStringW(L"Session", L"max_online_per_card",
        std::to_wstring(config_.max_online_per_card).c_str(), ini.c_str());
    // 防火墙
    WritePrivateProfileStringW(L"Firewall", L"max_attempts",
        std::to_wstring(config_.fw_max_attempts).c_str(), ini.c_str());
    WritePrivateProfileStringW(L"Firewall", L"window_minutes",
        std::to_wstring(config_.fw_window_minutes).c_str(), ini.c_str());
    WritePrivateProfileStringW(L"Firewall", L"ban_minutes",
        std::to_wstring(config_.fw_ban_minutes).c_str(), ini.c_str());
    WritePrivateProfileStringW(L"Update", L"force_enabled", config_.force_update_enabled ? L"1" : L"0", ini.c_str());
    IniWriteA(ini, L"Update", L"target_file", config_.update_target_file);
    IniWriteA(ini, L"Update", L"target_sha256", config_.update_target_sha256);
    IniWriteA(ini, L"Update", L"package_id", config_.update_package_id);
    IniWriteA(ini, L"Update", L"package_path", config_.update_package_path);
    IniWriteA(ini, L"Update", L"package_sha256", config_.update_package_sha256);
    IniWriteA(ini, L"Update", L"latest_version", config_.update_latest_version);
    IniWriteA(ini, L"Update", L"minimum_version", config_.update_minimum_version);
    IniWriteA(ini, L"Update", L"package_size", std::to_string(config_.update_package_size));
}

void MainWindow::ShowAboutDialog() {
    MessageBoxW(hwndMain_,
        L"Peanut Soft Protect 2026-7-26\n\n"
        L"原生 Win32 界面\n"
        L"云 DLL：仅服务端执行\n"
        L"PeanutSecure 协议 v2.0\n\n"
        L"暗黑主题版",
        L"关于 Peanut WLYZ", MB_OK | MB_ICONINFORMATION);
}

// ═══════════════════════════════════════════════════════════
//  销毁
// ═══════════════════════════════════════════════════════════
void MainWindow::OnDestroy() {
    // 停止反调试 watchdog
    peanut::security::antidebug::StopWatchdog();

    StopServer();
    peanut::security::antidebug::StopWatchdog();
    ReadSettingsFromUI();
    PersistUiPrefsFromRuntime();
    CaptureWindowPlacement();
    SaveConfig();
    KillTimer(hwndMain_, TIMER_CLOCK);
    PostQuitMessage(0);
}

