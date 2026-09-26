// ============================================================
// Peanut WLYZ — 运行时 UI 皮肤引擎 (实现)  v8
// 3 套完全不同的视觉风格，命令行 --skin=N 选择
//   skin 1 = 极夜霓虹 Aurora   深空蓝 + 青紫霓虹
//   skin 2 = 晨曦白   Daylight 明亮简约 + 克莱因蓝
//   skin 3 = 熔岩黑   Magma    纯黑硬朗 + 熔岩橙红
//
// v8 重点：每套皮肤除了配色，还各自定义了 层次(三级表面)、
// 阴影强度、导航高度/圆角，因此三套皮肤的"设计"而非"颜色"不同。
// ============================================================
#include "ui_skin.h"
#include <cstdlib>
#include <cwchar>

namespace peanut { namespace ui {

// ── 皮肤 1：极夜霓虹 Aurora ─────────────────────────────
static const UiSkin kAurora = {
    L"aurora", L"极夜霓虹", L"Microsoft YaHei UI", L"Consolas", false,
    /*bgDeep*/      RGB(9, 12, 21),
    /*bgDeep2*/     RGB(13, 17, 30),
    /*bgTopNav*/    RGB(16, 21, 37),
    /*bgTopNav2*/   RGB(20, 27, 47),
    /*bgLog*/       RGB(10, 13, 23),
    /*bgCard*/      RGB(27, 35, 55),
    /*bgCard2*/     RGB(32, 42, 65),
    /*bgInput*/     RGB(19, 25, 42),
    /*bgHeader*/    RGB(31, 40, 61),
    /*bgHover*/     RGB(41, 52, 79),
    /*accent*/      RGB(34, 211, 238),
    /*accentDim*/   RGB(21, 138, 161),
    /*accentGlow*/  RGB(103, 232, 249),
    /*accent2*/     RGB(167, 139, 250),
    /*textPrimary*/ RGB(233, 238, 248),
    /*textSecondary*/ RGB(150, 163, 194),
    /*textMuted*/   RGB(97, 110, 143),
    /*success*/     RGB(52, 211, 153),
    /*warning*/     RGB(251, 191, 36),
    /*danger*/      RGB(248, 113, 113),
    /*info*/        RGB(96, 165, 250),
    /*border*/      RGB(42, 54, 82),
    /*divider*/     RGB(31, 41, 64),
    /*cardRadius*/  13.0f,
    /*btnRadius*/   8.0f,
    /*navStyle*/    NAV_UNDERLINE,
    /*navBtnHeight*/ 30,
    /*navDivider*/  true,
    /*accentBarW*/  3,
    /*softShadow*/  true,
    /*bgElevated*/  RGB(35, 45, 68),
    /*accentSoft*/  RGB(17, 51, 66),
    /*cardBorderAlpha*/ 0.20f,
    /*navHeight*/   50,
    /*navItemRadius*/ 9.0f,
    /*shadowAlpha*/ 0.55f,
    /*shadowSpread*/ 12,
    /*shadowOffsetY*/ 4
};

// ── 皮肤 2：晨曦白 Daylight ─────────────────────────────
static const UiSkin kDaylight = {
    L"daylight", L"晨曦白", L"Microsoft YaHei UI", L"Consolas", true,
    /*bgDeep*/      RGB(238, 242, 248),
    /*bgDeep2*/     RGB(230, 236, 245),
    /*bgTopNav*/    RGB(255, 255, 255),
    /*bgTopNav2*/   RGB(250, 252, 255),
    /*bgLog*/       RGB(247, 249, 253),
    /*bgCard*/      RGB(255, 255, 255),
    /*bgCard2*/     RGB(252, 253, 255),
    /*bgInput*/     RGB(255, 255, 255),
    /*bgHeader*/    RGB(244, 247, 252),
    /*bgHover*/     RGB(235, 241, 251),
    /*accent*/      RGB(37, 99, 235),
    /*accentDim*/   RGB(29, 78, 216),
    /*accentGlow*/  RGB(96, 165, 250),
    /*accent2*/     RGB(124, 58, 237),
    /*textPrimary*/ RGB(17, 24, 39),
    /*textSecondary*/ RGB(71, 85, 105),
    /*textMuted*/   RGB(148, 163, 184),
    /*success*/     RGB(22, 163, 74),
    /*warning*/     RGB(202, 138, 4),
    /*danger*/      RGB(220, 38, 38),
    /*info*/        RGB(37, 99, 235),
    /*border*/      RGB(219, 226, 238),
    /*divider*/     RGB(232, 237, 245),
    /*cardRadius*/  14.0f,
    /*btnRadius*/   8.0f,
    /*navStyle*/    NAV_PILL,
    /*navBtnHeight*/ 30,
    /*navDivider*/  true,
    /*accentBarW*/  4,
    /*softShadow*/  true,
    /*bgElevated*/  RGB(246, 248, 252),
    /*accentSoft*/  RGB(224, 233, 255),
    /*cardBorderAlpha*/ 1.0f,
    /*navHeight*/   50,
    /*navItemRadius*/ 9.0f,
    /*shadowAlpha*/ 0.15f,
    /*shadowSpread*/ 12,
    /*shadowOffsetY*/ 4
};

// ── 皮肤 3：熔岩黑 Magma ────────────────────────────────
static const UiSkin kMagma = {
    L"magma", L"熔岩黑", L"Microsoft YaHei UI", L"Consolas", false,
    /*bgDeep*/      RGB(9, 9, 11),
    /*bgDeep2*/     RGB(15, 11, 12),
    /*bgTopNav*/    RGB(13, 12, 14),
    /*bgTopNav2*/   RGB(24, 16, 15),
    /*bgLog*/       RGB(8, 8, 10),
    /*bgCard*/      RGB(26, 20, 21),
    /*bgCard2*/     RGB(35, 25, 24),
    /*bgInput*/     RGB(17, 14, 15),
    /*bgHeader*/    RGB(30, 22, 22),
    /*bgHover*/     RGB(48, 30, 27),
    /*accent*/      RGB(255, 107, 53),
    /*accentDim*/   RGB(191, 72, 32),
    /*accentGlow*/  RGB(255, 158, 105),
    /*accent2*/     RGB(255, 46, 99),
    /*textPrimary*/ RGB(245, 241, 240),
    /*textSecondary*/ RGB(172, 160, 156),
    /*textMuted*/   RGB(122, 110, 107),
    /*success*/     RGB(74, 222, 128),
    /*warning*/     RGB(250, 204, 21),
    /*danger*/      RGB(239, 68, 68),
    /*info*/        RGB(251, 146, 60),
    /*border*/      RGB(66, 43, 37),
    /*divider*/     RGB(50, 34, 30),
    /*cardRadius*/  7.0f,
    /*btnRadius*/   5.0f,
    /*navStyle*/    NAV_LEFTMARK,
    /*navBtnHeight*/ 28,
    /*navDivider*/  true,
    /*accentBarW*/  3,
    /*softShadow*/  false,
    /*bgElevated*/  RGB(38, 28, 27),
    /*accentSoft*/  RGB(58, 27, 20),
    /*cardBorderAlpha*/ 0.32f,
    /*navHeight*/   46,
    /*navItemRadius*/ 5.0f,
    /*shadowAlpha*/ 0.60f,
    /*shadowSpread*/ 9,
    /*shadowOffsetY*/ 4
};

static const UiSkin* kSkins[] = { &kAurora, &kDaylight, &kMagma };
static const int kSkinCount = 3;

// 默认即皮肤 1，保证任何代码路径下都有合法颜色
UiSkin g_skin = kAurora;

static int ClampId(int id) {
    if (id < 1 || id > kSkinCount) return 1;
    return id;
}

int UiSkin_Load(int id) {
    int real = ClampId(id);
    g_skin = *kSkins[real - 1];
    return real;
}

int UiSkin_ParseCommandLine(const wchar_t* cmdLine) {
    if (!cmdLine) return 0;
    const wchar_t* p = cmdLine;
    while (*p) {
        while (*p == L' ' || *p == L'\t') ++p;
        if (*p != L'-') { ++p; continue; }
        if (wcsncmp(p, L"--skin", 6) == 0) {
            const wchar_t* q = p + 6;
            if (*q == L'=') ++q;
            else {
                while (*q == L' ' || *q == L'\t') ++q;
            }
            int v = _wtoi(q);
            if (v > 0) return v;
        }
        while (*p && *p != L' ') ++p;
    }
    return 0;
}

int UiSkin_ParseEnv() {
    wchar_t buf[32] = {};
    DWORD n = GetEnvironmentVariableW(L"PEANUT_SKIN", buf, 32);
    if (n == 0 || n >= 32) return 0;
    int v = _wtoi(buf);
    return v > 0 ? v : 0;
}

}} // namespace peanut::ui
