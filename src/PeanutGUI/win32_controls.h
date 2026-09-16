// ============================================================
// Peanut WLYZ — Win32 控件轻量封装 v6.0
// 专业深色主题颜色 + 控件辅助函数
// ============================================================

#pragma once

#include <windows.h>
#include <commctrl.h>
#include <uxtheme.h>
#include <string>
#include <functional>
#include <vector>

#pragma comment(lib, "uxtheme.lib")

namespace w32 {

// ── 暗黑主题颜色常量 ───────────────────────────────────
// 背景（炭黑，非蓝紫）
constexpr COLORREF COLOR_BG        = RGB(12,  12,  14);   // 主背景
constexpr COLORREF COLOR_BG_LIGHT  = RGB(18,  18,  22);   // 顶栏
constexpr COLORREF COLOR_BG_PANEL  = RGB(28,  28,  34);   // 卡片/面板
constexpr COLORREF COLOR_BG_INPUT  = RGB(22,  22,  26);   // 输入框背景

// 文字
constexpr COLORREF COLOR_TEXT      = RGB(232, 232, 236);
constexpr COLORREF COLOR_TEXT_DIM  = RGB(150, 150, 160);
constexpr COLORREF COLOR_TEXT_MUTED= RGB(100, 100, 110);

// 强调色
constexpr COLORREF COLOR_ACCENT    = RGB(233, 69,  96);
constexpr COLORREF COLOR_ACCENT2   = RGB(180, 50,  75);

// 状态色
constexpr COLORREF COLOR_SUCCESS   = RGB(0,   200, 83);
constexpr COLORREF COLOR_WARNING   = RGB(255, 214, 0);
constexpr COLORREF COLOR_ERROR     = RGB(255, 23,  68);
constexpr COLORREF COLOR_INFO      = RGB(64,  160, 255);

// 边框
constexpr COLORREF COLOR_BORDER    = RGB(40,  40,  48);
constexpr COLORREF COLOR_DIVIDER   = RGB(32,  32,  38);

// ── 画刷 ───────────────────────────────────────────────────
inline HBRUSH GetDarkBrush() {
    static HBRUSH brush = CreateSolidBrush(COLOR_BG);
    return brush;
}
inline HBRUSH GetLightBrush() {
    static HBRUSH brush = CreateSolidBrush(COLOR_BG_LIGHT);
    return brush;
}
inline HBRUSH GetPanelBrush() {
    static HBRUSH brush = CreateSolidBrush(COLOR_BG_PANEL);
    return brush;
}
inline HBRUSH GetInputBrush() {
    static HBRUSH brush = CreateSolidBrush(COLOR_BG_INPUT);
    return brush;
}

// ── 字体 ───────────────────────────────────────────────────
inline HFONT CreateDefaultFont(int size_delta = 0) {
    return CreateFontW(
        16 + size_delta, 0, 0, 0,
        FW_NORMAL, FALSE, FALSE, FALSE,
        DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
        CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_SWISS,
        L"Microsoft YaHei"
    );
}

inline HFONT CreateLogFont(int size_delta = 2) {
    return CreateFontW(
        18 + size_delta, 0, 0, 0,
        FW_NORMAL, FALSE, FALSE, FALSE,
        DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
        CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_SWISS,
        L"Microsoft YaHei"
    );
}

inline HFONT CreateTitleFont() {
    return CreateFontW(
        22, 0, 0, 0,
        FW_SEMIBOLD, FALSE, FALSE, FALSE,
        DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
        CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_SWISS,
        L"Microsoft YaHei"
    );
}

// ── ListView ───────────────────────────────────────────────
inline void ListView_AddColumn(HWND hList, int index, const wchar_t* text, int width) {
    LVCOLUMNW lvc = {};
    lvc.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_FMT;
    lvc.pszText = const_cast<wchar_t*>(text);
    lvc.cx = width;
    lvc.fmt = LVCFMT_LEFT;
    ListView_InsertColumn(hList, index, &lvc);
}

inline void ListView_AddRow(HWND hList, const std::vector<std::wstring>& cols) {
    if (cols.empty()) return;
    LVITEMW lvi = {};
    lvi.mask = LVIF_TEXT | LVIF_PARAM;
    lvi.iItem = ListView_GetItemCount(hList);
    lvi.pszText = const_cast<wchar_t*>(cols[0].c_str());
    lvi.lParam = lvi.iItem;
    int idx = ListView_InsertItem(hList, &lvi);
    if (idx < 0) return;
    for (size_t i = 1; i < cols.size(); ++i) {
        ListView_SetItemText(hList, idx, static_cast<int>(i),
                              const_cast<wchar_t*>(cols[i].c_str()));
    }
}

inline std::vector<int> ListView_GetSelectedIndices(HWND hList) {
    std::vector<int> indices;
    int count = ListView_GetItemCount(hList);
    for (int i = 0; i < count; ++i) {
        if (ListView_GetItemState(hList, i, LVIS_SELECTED) & LVIS_SELECTED) {
            indices.push_back(i);
        }
    }
    return indices;
}

inline void ListView_SelectAll(HWND hList, bool select) {
    int count = ListView_GetItemCount(hList);
    for (int i = 0; i < count; ++i) {
        ListView_SetItemState(hList, i,
            select ? LVIS_SELECTED : 0, LVIS_SELECTED);
    }
}

inline std::vector<std::wstring> ListView_GetRowText(HWND hList, int index) {
    std::vector<std::wstring> result;
    HWND hHeader = ListView_GetHeader(hList);
    int colCount = Header_GetItemCount(hHeader);
    for (int col = 0; col < colCount; ++col) {
        wchar_t buf[512] = {};
        ListView_GetItemText(hList, index, col, buf, 512);
        result.push_back(buf);
    }
    return result;
}

// ── Rich Edit 日志 (废弃 — 直接用EDIT控件) ────────────────
inline HWND CreateLogEdit(HWND parent, int id, int x, int y, int w, int h) {
    return CreateWindowExW(
        0, L"EDIT", nullptr,
        WS_CHILD | WS_VISIBLE | WS_VSCROLL | ES_LEFT |
        ES_MULTILINE | ES_READONLY | ES_AUTOVSCROLL | WS_BORDER,
        x, y, w, h, parent,
        reinterpret_cast<HMENU>(static_cast<INT_PTR>(id)),
        GetModuleHandle(nullptr), nullptr
    );
}

// ── 对话框辅助 ─────────────────────────────────────────────
inline void DlgItem_SetText(HWND hDlg, int id, const std::wstring& text) {
    SetDlgItemText(hDlg, id, text.c_str());
}

inline std::wstring DlgItem_GetText(HWND hDlg, int id) {
    wchar_t buf[4096] = {};
    GetDlgItemText(hDlg, id, buf, 4096);
    return buf;
}

// ── 剪贴板 ─────────────────────────────────────────────────
inline void Clipboard_SetText(const std::wstring& text) {
    if (!OpenClipboard(nullptr)) return;
    EmptyClipboard();
    size_t size = (text.size() + 1) * sizeof(wchar_t);
    HGLOBAL hMem = GlobalAlloc(GMEM_MOVEABLE, size);
    if (hMem) {
        memcpy(GlobalLock(hMem), text.c_str(), size);
        GlobalUnlock(hMem);
        SetClipboardData(CF_UNICODETEXT, hMem);
    }
    CloseClipboard();
}

inline std::wstring Clipboard_GetText() {
    std::wstring result;
    if (!OpenClipboard(nullptr)) return result;
    HANDLE hData = GetClipboardData(CF_UNICODETEXT);
    if (hData) {
        wchar_t* p = static_cast<wchar_t*>(GlobalLock(hData));
        if (p) { result = p; GlobalUnlock(hData); }
    }
    CloseClipboard();
    return result;
}

// ── 暗色控件辅助 ───────────────────────────────────────────
inline void ApplyDarkListView(HWND hList, COLORREF bg, COLORREF text) {
    if (!hList) return;
    SetWindowTheme(hList, L"", L"");
    ListView_SetBkColor(hList, bg);
    ListView_SetTextBkColor(hList, bg);
    ListView_SetTextColor(hList, text);
    HWND hHeader = ListView_GetHeader(hList);
    if (hHeader) SetWindowTheme(hHeader, L"", L"");
    InvalidateRect(hList, nullptr, TRUE);
}

inline void ApplyDarkEdit(HWND hEdit) {
    if (!hEdit) return;
    SetWindowTheme(hEdit, L"", L"");
}

inline void ApplyDarkCombo(HWND hCombo) {
    if (!hCombo) return;
    SetWindowTheme(hCombo, L"", L"");
}

// ── 初始化 ─────────────────────────────────────────────────
inline void InitCommon() {
    INITCOMMONCONTROLSEX icex = {};
    icex.dwSize = sizeof(icex);
    icex.dwICC = ICC_LISTVIEW_CLASSES | ICC_BAR_CLASSES | ICC_TAB_CLASSES |
                 ICC_STANDARD_CLASSES | ICC_PROGRESS_CLASS | ICC_COOL_CLASSES;
    InitCommonControlsEx(&icex);
    LoadLibraryW(L"Msftedit.dll");
}

} // namespace w32
