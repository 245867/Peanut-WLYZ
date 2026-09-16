// ============================================================
// Peanut WLYZ — 卡密生成/导入对话框  v7.0
// ============================================================

#include "card_dialogs.h"
#include "main_window.h"

#include <windowsx.h>
#include <commctrl.h>
#include <uxtheme.h>
#include <dwmapi.h>
#include <sstream>
#include <ctime>
#include <cstdlib>
#include <algorithm>
#include <fstream>

// ═══════════════════════════════════════════════════════════
//  辅助: UTF-8 ↔ Wide (本地副本)
// ═══════════════════════════════════════════════════════════
static std::string wstring_to_utf8(const std::wstring& ws) {
    if (ws.empty()) return {};
    int len = WideCharToMultiByte(CP_UTF8, 0, ws.c_str(), (int)ws.size(), nullptr, 0, nullptr, nullptr);
    std::string s(len, 0);
    WideCharToMultiByte(CP_UTF8, 0, ws.c_str(), (int)ws.size(), &s[0], len, nullptr, nullptr);
    return s;
}

static std::string utf8_from_wstring(const std::wstring& s) {
    if (s.empty()) return "";
    int len = WideCharToMultiByte(CP_UTF8, 0, s.c_str(), -1, nullptr, 0, nullptr, nullptr);
    if (len <= 0) return "";
    std::vector<char> buf(len);
    WideCharToMultiByte(CP_UTF8, 0, s.c_str(), -1, buf.data(), len, nullptr, nullptr);
    return buf.data();
}

// ═══════════════════════════════════════════════════════════
//  生成卡密对话框 — 控件ID，辅助，颜色
// ═══════════════════════════════════════════════════════════
enum {
    IDC_GEN_COUNT = 9101,
    IDC_GEN_DURVAL = 9102,
    IDC_GEN_TYPE_DAY = 9103,
    IDC_GEN_TYPE_HOUR = 9104,
    IDC_GEN_TYPE_MONTH = 9105,
    IDC_GEN_TYPE_YEAR = 9106,
    IDC_GEN_OK = 9107,
    IDC_GEN_CANCEL = 9108,
    IDC_GEN_TYPE_FOREVER = 9109,
    IDC_GEN_PREFIX = 9110,
    IDC_GEN_REMARK = 9111,
};

static const wchar_t* DefaultPrefixForType(int t) {
    switch (t) {
    case 1: return L"XS_";
    case 2: return L"YK_";
    case 3: return L"NK_";
    case 4: return L"YJ_";
    default: return L"TK_";
    }
}

static int DefaultDurForType(int t) {
    switch (t) {
    case 1: return 24;
    case 2: return 1;
    case 3: return 1;
    case 4: return 999;
    default: return 30;
    }
}

static void ApplyDurDefault(HWND hwnd, int type) {
    wchar_t buf[16];
    swprintf_s(buf, L"%d", DefaultDurForType(type));
    SetWindowTextW(GetDlgItem(hwnd, IDC_GEN_DURVAL), buf);
    SetWindowTextW(GetDlgItem(hwnd, IDC_GEN_PREFIX), DefaultPrefixForType(type));
}

static constexpr COLORREF kGenBg     = RGB(18, 18, 22);
static constexpr COLORREF kGenInput  = RGB(28, 30, 36);
static constexpr COLORREF kGenText   = RGB(230, 230, 235);
static constexpr COLORREF kGenMuted  = RGB(160, 160, 170);
static constexpr COLORREF kGenYellow = RGB(232, 208, 140);
static constexpr COLORREF kGenBtn    = RGB(42, 44, 52);
static constexpr COLORREF kGenBtnOk  = RGB(70, 58, 28);

INT_PTR ShowCardGenDialogBox(HWND parent, GenDlgData* data) {    const wchar_t* cls = L"PeanutCardGenDlgDark";
    static bool registered = false;
    if (!registered) {
        WNDCLASSEXW wc = { sizeof(wc) };
        wc.lpfnWndProc = [](HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) -> LRESULT {
            auto* d = reinterpret_cast<GenDlgData*>(GetWindowLongPtrW(hwnd, GWLP_USERDATA));
            switch (msg) {
            case WM_NCCREATE: {
                auto* cs = reinterpret_cast<CREATESTRUCTW*>(lp);
                SetWindowLongPtrW(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(cs->lpCreateParams));
                return TRUE;
            }
            case WM_CREATE: {
                d = reinterpret_cast<GenDlgData*>(GetWindowLongPtrW(hwnd, GWLP_USERDATA));
                d->brBg = CreateSolidBrush(kGenBg);
                d->brInput = CreateSolidBrush(kGenInput);
                d->font = CreateFontW(22, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
                    DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                    CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_SWISS, L"Microsoft YaHei UI");
                auto add = [&](const wchar_t* c, const wchar_t* t, DWORD st, int x, int y, int ww, int hh, int id) {
                    HWND ctl = CreateWindowExW(0, c, t, WS_CHILD | WS_VISIBLE | st,
                        x, y, ww, hh, hwnd, (HMENU)(INT_PTR)id, GetModuleHandleW(nullptr), nullptr);
                    SendMessageW(ctl, WM_SETFONT, (WPARAM)d->font, TRUE);
                    return ctl;
                };
                // title
                add(L"STATIC", L"生  成  卡  密", SS_CENTER, 0, 6, 420, 32, -1);
                add(L"STATIC", L"", SS_ETCHEDHORZ, 24, 36, 372, 2, -1);
                // row 1: count
                add(L"STATIC", L"数  量:", SS_LEFT, 36, 56, 80, 28, -1);
                add(L"EDIT", L"10", ES_NUMBER | ES_LEFT | ES_AUTOHSCROLL, 130, 54, 100, 30, IDC_GEN_COUNT);
                // row 2: duration
                add(L"STATIC", L"时  长:", SS_LEFT, 36, 94, 80, 28, -1);
                add(L"EDIT", L"30", ES_NUMBER | ES_LEFT | ES_AUTOHSCROLL, 130, 92, 100, 30, IDC_GEN_DURVAL);
                // row 3: unit radios
                add(L"STATIC", L"单  位:", SS_LEFT, 36, 134, 80, 28, -1);
                add(L"BUTTON", L"天", BS_AUTORADIOBUTTON | WS_GROUP, 130, 134, 44, 28, IDC_GEN_TYPE_DAY);
                add(L"BUTTON", L"小时", BS_AUTORADIOBUTTON, 178, 134, 52, 28, IDC_GEN_TYPE_HOUR);
                add(L"BUTTON", L"月", BS_AUTORADIOBUTTON, 236, 134, 44, 28, IDC_GEN_TYPE_MONTH);
                add(L"BUTTON", L"年", BS_AUTORADIOBUTTON, 286, 134, 44, 28, IDC_GEN_TYPE_YEAR);
                add(L"BUTTON", L"永久", BS_AUTORADIOBUTTON, 336, 134, 56, 28, IDC_GEN_TYPE_FOREVER);
                CheckRadioButton(hwnd, IDC_GEN_TYPE_DAY, IDC_GEN_TYPE_FOREVER, IDC_GEN_TYPE_DAY);
                // row 4: prefix
                add(L"STATIC", L"前  缀:", SS_LEFT, 36, 174, 80, 28, -1);
                add(L"EDIT", L"TK_", ES_LEFT | ES_AUTOHSCROLL, 130, 172, 120, 30, IDC_GEN_PREFIX);
                add(L"STATIC", L"共32位", SS_LEFT, 260, 174, 80, 28, -1);
                // row 5: optional remark
                add(L"STATIC", L"备  注:", SS_LEFT, 36, 210, 80, 28, -1);
                add(L"EDIT", L"", ES_LEFT | ES_AUTOHSCROLL, 130, 208, 260, 30, IDC_GEN_REMARK);
                // buttons
                add(L"BUTTON", L"取消", BS_OWNERDRAW, 180, 258, 100, 34, IDC_GEN_CANCEL);
                add(L"BUTTON", L"生成", BS_OWNERDRAW, 290, 258, 100, 34, IDC_GEN_OK);
                SetWindowTheme(GetDlgItem(hwnd, IDC_GEN_COUNT), L"", L"");
                SetWindowTheme(GetDlgItem(hwnd, IDC_GEN_DURVAL), L"", L"");
                for (HWND c = GetWindow(hwnd, GW_CHILD); c; c = GetWindow(c, GW_HWNDNEXT)) {
                    wchar_t cn[32] = {};
                    GetClassNameW(c, cn, 32);
                    if (_wcsicmp(cn, L"Button") == 0) SetWindowTheme(c, L"", L"");
                }
                return 0;
            }
            case WM_ERASEBKGND:
                return 1;
            case WM_PAINT: {
                PAINTSTRUCT ps;
                HDC hdc = BeginPaint(hwnd, &ps);
                RECT rc; GetClientRect(hwnd, &rc);
                FillRect(hdc, &rc, d && d->brBg ? d->brBg : (HBRUSH)GetStockObject(BLACK_BRUSH));
                EndPaint(hwnd, &ps);
                return 0;
            }
            case WM_NCPAINT:
            case WM_NCACTIVATE: {
                LRESULT r = DefWindowProcW(hwnd, msg, wp, lp);
                HDC hdc = GetWindowDC(hwnd);
                RECT rc; GetWindowRect(hwnd, &rc);
                OffsetRect(&rc, -rc.left, -rc.top);
                HPEN pen = CreatePen(PS_SOLID, 3, kGenYellow);
                HPEN old = (HPEN)SelectObject(hdc, pen);
                HBRUSH oldBr = (HBRUSH)SelectObject(hdc, GetStockObject(NULL_BRUSH));
                Rectangle(hdc, 1, 1, rc.right - 1, rc.bottom - 1);
                SelectObject(hdc, oldBr);
                SelectObject(hdc, old);
                DeleteObject(pen);
                ReleaseDC(hwnd, hdc);
                return r;
            }
            case WM_CTLCOLORSTATIC: {
                HDC hdc = (HDC)wp;
                SetBkMode(hdc, TRANSPARENT);
                SetTextColor(hdc, kGenMuted);
                return (LRESULT)(d && d->brBg ? d->brBg : GetStockObject(BLACK_BRUSH));
            }
            case WM_CTLCOLOREDIT: {
                HDC hdc = (HDC)wp;
                SetBkMode(hdc, OPAQUE);
                SetBkColor(hdc, kGenInput);
                SetTextColor(hdc, kGenText);
                return (LRESULT)(d && d->brInput ? d->brInput : GetStockObject(DKGRAY_BRUSH));
            }
            case WM_CTLCOLORBTN: {
                HDC hdc = (HDC)wp;
                SetBkMode(hdc, TRANSPARENT);
                SetTextColor(hdc, kGenText);
                return (LRESULT)(d && d->brBg ? d->brBg : GetStockObject(BLACK_BRUSH));
            }
            case WM_DRAWITEM: {
                auto* dis = (LPDRAWITEMSTRUCT)lp;
                if (!dis || dis->CtlType != ODT_BUTTON) break;
                bool okBtn = (dis->CtlID == IDC_GEN_OK);
                bool pressed = (dis->itemState & ODS_SELECTED) != 0;
                COLORREF bg = okBtn ? (pressed ? RGB(90, 74, 36) : kGenBtnOk)
                                    : (pressed ? RGB(55, 58, 68) : kGenBtn);
                HBRUSH br = CreateSolidBrush(bg);
                FillRect(dis->hDC, &dis->rcItem, br);
                DeleteObject(br);
                HPEN pen = CreatePen(PS_SOLID, 1, kGenYellow);
                HPEN old = (HPEN)SelectObject(dis->hDC, pen);
                SelectObject(dis->hDC, GetStockObject(NULL_BRUSH));
                Rectangle(dis->hDC, dis->rcItem.left, dis->rcItem.top,
                          dis->rcItem.right - 1, dis->rcItem.bottom - 1);
                SelectObject(dis->hDC, old);
                DeleteObject(pen);
                wchar_t text[32] = {};
                GetWindowTextW(dis->hwndItem, text, 32);
                SetBkMode(dis->hDC, TRANSPARENT);
                SetTextColor(dis->hDC, kGenText);
                if (d && d->font) SelectObject(dis->hDC, d->font);
                DrawTextW(dis->hDC, text, -1, (RECT*)&dis->rcItem,
                          DT_CENTER | DT_VCENTER | DT_SINGLELINE);
                return TRUE;
            }
            case WM_COMMAND: {
                int id = LOWORD(wp);
                if (id == IDC_GEN_TYPE_FOREVER) {
                    ApplyDurDefault(hwnd, 4);
                    return 0;
                }
                if (id == IDC_GEN_TYPE_DAY || id == IDC_GEN_TYPE_HOUR ||
                    id == IDC_GEN_TYPE_MONTH || id == IDC_GEN_TYPE_YEAR) {
                    int t = 0;
                    if (id == IDC_GEN_TYPE_HOUR) t = 1;
                    else if (id == IDC_GEN_TYPE_MONTH) t = 2;
                    else if (id == IDC_GEN_TYPE_YEAR) t = 3;
                    ApplyDurDefault(hwnd, t);
                    return 0;
                }
                if (id == IDC_GEN_OK && d) {
                    wchar_t buf[64] = {};
                    GetWindowTextW(GetDlgItem(hwnd, IDC_GEN_COUNT), buf, 64);
                    d->count = _wtoi(buf);
                    if (d->count < 1) d->count = 1;
                    if (d->count > 500) d->count = 500;
                    if (IsDlgButtonChecked(hwnd, IDC_GEN_TYPE_FOREVER) == BST_CHECKED) {
                        d->durType = 4;
                        d->durValue = 999;
                    } else {
                        GetWindowTextW(GetDlgItem(hwnd, IDC_GEN_DURVAL), buf, 64);
                        d->durValue = _wtoi(buf);
                        if (d->durValue < 1) d->durValue = 1;
                        if (IsDlgButtonChecked(hwnd, IDC_GEN_TYPE_DAY) == BST_CHECKED) d->durType = 0;
                        else if (IsDlgButtonChecked(hwnd, IDC_GEN_TYPE_HOUR) == BST_CHECKED) d->durType = 1;
                        else if (IsDlgButtonChecked(hwnd, IDC_GEN_TYPE_MONTH) == BST_CHECKED) d->durType = 2;
                        else d->durType = 3;
                    }
                    GetWindowTextW(GetDlgItem(hwnd, IDC_GEN_PREFIX), buf, 64);
                    d->prefix = wstring_to_utf8(buf);
                    wchar_t remarkBuf[256] = {};
                    GetWindowTextW(GetDlgItem(hwnd, IDC_GEN_REMARK), remarkBuf, 256);
                    d->remark = wstring_to_utf8(remarkBuf);
                    d->ok = true;
                    DestroyWindow(hwnd);
                    return 0;
                }
                if (id == IDC_GEN_CANCEL || id == IDCANCEL) {
                    DestroyWindow(hwnd);
                    return 0;
                }
                break;
            }
            case WM_CLOSE:
                DestroyWindow(hwnd);
                return 0;
            case WM_DESTROY:
                if (d) {
                    if (d->brBg) { DeleteObject(d->brBg); d->brBg = nullptr; }
                    if (d->brInput) { DeleteObject(d->brInput); d->brInput = nullptr; }
                    if (d->font) { DeleteObject(d->font); d->font = nullptr; }
                }
                return 0;
            }
            return DefWindowProcW(hwnd, msg, wp, lp);
        };
        wc.hInstance = GetModuleHandleW(nullptr);
        wc.hbrBackground = CreateSolidBrush(kGenBg);
        wc.hCursor = LoadCursor(nullptr, IDC_ARROW);
        wc.lpszClassName = cls;
        wc.style = CS_DROPSHADOW;
        RegisterClassExW(&wc);
        registered = true;
    }

    RECT prc{};
    GetWindowRect(parent, &prc);
    int w = 420, h = 350;
    int x = prc.left + ((prc.right - prc.left) - w) / 2;
    int y = prc.top + ((prc.bottom - prc.top) - h) / 2;

    HWND dlg = CreateWindowExW(WS_EX_DLGMODALFRAME | WS_EX_TOPMOST, cls, L"生成卡密",
        WS_CAPTION | WS_POPUP | WS_SYSMENU,
        x, y, w, h, parent, nullptr, GetModuleHandleW(nullptr), data);
    if (!dlg) return IDCANCEL;

    // 标题栏暗色
    BOOL dark = TRUE;
    DwmSetWindowAttribute(dlg, 20, &dark, sizeof(dark));

    EnableWindow(parent, FALSE);
    ShowWindow(dlg, SW_SHOW);
    UpdateWindow(dlg);

    MSG msg;
    while (IsWindow(dlg)) {
        BOOL gm = GetMessage(&msg, nullptr, 0, 0);
        if (gm <= 0) break;
        if (!IsDialogMessage(dlg, &msg)) {
            TranslateMessage(&msg);
            DispatchMessage(&msg);
        }
    }
    EnableWindow(parent, TRUE);
    SetForegroundWindow(parent);
    return data->ok ? IDOK : IDCANCEL;
}

// ═══════════════════════════════════════════════════════════
//  生成卡密 — MainWindow 成员
// ═══════════════════════════════════════════════════════════
void MainWindow::ShowCardGenerateDialog() {
    GenDlgData data;
    data.self = this;
    if (ShowCardGenDialogBox(hwndMain_, &data) != IDOK) return;

    int added = 0;
    for (int i = 0; i < data.count; ++i) {
        CardEntry c;
        c.cardkey = GenerateCardKey(data.prefix);
        c.duration_type = data.durType;
        c.duration_value = data.durValue;
        c.status = 0;
        c.remark = data.remark;
        std::replace(c.remark.begin(), c.remark.end(), '|', '/');
        c.usage_count = 0;
        cards_.push_back(std::move(c));
        ++added;
    }
    SaveCards();
    RefreshCardList();
    UpdateDashboardStats();
    NavigateTo(NavTab::CardMgmt);
    LogSuccess("已生成 " + std::to_string(added) + " 条卡密");
}

// ═══════════════════════════════════════════════════════════
//  导入卡密对话框 — 控件ID，颜色
// ═══════════════════════════════════════════════════════════
enum {
    IDC_IMP_TEXT = 9301,
    IDC_IMP_OK   = 9302,
    IDC_IMP_CANCEL = 9303,
};

static constexpr COLORREF kImpBg     = RGB(18, 18, 22);
static constexpr COLORREF kImpInput  = RGB(28, 30, 36);
static constexpr COLORREF kImpText   = RGB(230, 230, 235);
static constexpr COLORREF kImpMuted  = RGB(160, 160, 170);
static constexpr COLORREF kImpYellow = RGB(232, 208, 140);

// ═══════════════════════════════════════════════════════════
//  导入卡密 — MainWindow 成员
// ═══════════════════════════════════════════════════════════
void MainWindow::ShowCardImportDialog() {
    const wchar_t* cls = L"PeanutCardImpDlgDark";
    static bool registered = false;
    if (!registered) {
        WNDCLASSEXW wc = { sizeof(wc) };
        wc.lpfnWndProc = [](HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) -> LRESULT {
            auto* d = reinterpret_cast<ImpDlgData*>(GetWindowLongPtrW(hwnd, GWLP_USERDATA));
            switch (msg) {
            case WM_NCCREATE: {
                auto* cs = reinterpret_cast<CREATESTRUCTW*>(lp);
                SetWindowLongPtrW(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(cs->lpCreateParams));
                return TRUE;
            }
            case WM_CREATE: {
                d = reinterpret_cast<ImpDlgData*>(GetWindowLongPtrW(hwnd, GWLP_USERDATA));
                d->brBg = CreateSolidBrush(kImpBg);
                d->brInput = CreateSolidBrush(kImpInput);
                d->font = CreateFontW(18, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
                    DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                    CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_SWISS, L"Microsoft YaHei UI");
                auto add = [&](const wchar_t* c, const wchar_t* t, DWORD st, int x, int y, int ww, int hh, int id) {
                    HWND ctl = CreateWindowExW(0, c, t, WS_CHILD | WS_VISIBLE | st,
                        x, y, ww, hh, hwnd, (HMENU)(INT_PTR)id, GetModuleHandleW(nullptr), nullptr);
                    SendMessageW(ctl, WM_SETFONT, (WPARAM)d->font, TRUE);
                    return ctl;
                };
                add(L"STATIC", L"请粘贴卡密（每行一条）:", SS_LEFT, 24, 16, 340, 24, -1);
                HWND edText = CreateWindowExW(0, L"EDIT", L"",
                    WS_CHILD | WS_VISIBLE | WS_VSCROLL | ES_LEFT | ES_MULTILINE | ES_AUTOVSCROLL,
                    24, 44, 352, 160, hwnd, (HMENU)(INT_PTR)IDC_IMP_TEXT,
                    GetModuleHandleW(nullptr), nullptr);
                SendMessageW(edText, WM_SETFONT, (WPARAM)d->font, TRUE);
                SetWindowTheme(edText, L"", L"");
                add(L"BUTTON", L"导入", BS_OWNERDRAW, 100, 220, 100, 34, IDC_IMP_OK);
                add(L"BUTTON", L"取消", BS_OWNERDRAW, 220, 220, 100, 34, IDC_IMP_CANCEL);
                for (HWND c = GetWindow(hwnd, GW_CHILD); c; c = GetWindow(c, GW_HWNDNEXT)) {
                    wchar_t cn[32] = {};
                    GetClassNameW(c, cn, 32);
                    if (_wcsicmp(cn, L"Button") == 0) SetWindowTheme(c, L"", L"");
                }
                return 0;
            }
            case WM_ERASEBKGND:
                return 1;
            case WM_PAINT: {
                PAINTSTRUCT ps;
                HDC hdc = BeginPaint(hwnd, &ps);
                RECT rc; GetClientRect(hwnd, &rc);
                FillRect(hdc, &rc, d && d->brBg ? d->brBg : (HBRUSH)GetStockObject(BLACK_BRUSH));
                EndPaint(hwnd, &ps);
                return 0;
            }
            case WM_NCPAINT:
            case WM_NCACTIVATE: {
                LRESULT r = DefWindowProcW(hwnd, msg, wp, lp);
                HDC hdc = GetWindowDC(hwnd);
                RECT rc; GetWindowRect(hwnd, &rc);
                OffsetRect(&rc, -rc.left, -rc.top);
                HPEN pen = CreatePen(PS_SOLID, 3, kImpYellow);
                HPEN old = (HPEN)SelectObject(hdc, pen);
                HBRUSH oldBr = (HBRUSH)SelectObject(hdc, GetStockObject(NULL_BRUSH));
                Rectangle(hdc, 1, 1, rc.right - 1, rc.bottom - 1);
                SelectObject(hdc, oldBr);
                SelectObject(hdc, old);
                DeleteObject(pen);
                ReleaseDC(hwnd, hdc);
                return r;
            }
            case WM_CTLCOLORSTATIC: {
                HDC hdc = (HDC)wp;
                SetBkMode(hdc, TRANSPARENT);
                SetTextColor(hdc, kImpMuted);
                return (LRESULT)(d && d->brBg ? d->brBg : GetStockObject(BLACK_BRUSH));
            }
            case WM_CTLCOLOREDIT: {
                HDC hdc = (HDC)wp;
                SetBkMode(hdc, OPAQUE);
                SetBkColor(hdc, kImpInput);
                SetTextColor(hdc, kImpText);
                return (LRESULT)(d && d->brInput ? d->brInput : GetStockObject(DKGRAY_BRUSH));
            }
            case WM_CTLCOLORBTN: {
                HDC hdc = (HDC)wp;
                SetBkMode(hdc, TRANSPARENT);
                SetTextColor(hdc, kImpText);
                return (LRESULT)(d && d->brBg ? d->brBg : GetStockObject(BLACK_BRUSH));
            }
            case WM_DRAWITEM: {
                auto* dis = (LPDRAWITEMSTRUCT)lp;
                if (!dis || dis->CtlType != ODT_BUTTON) break;
                bool okBtn = (dis->CtlID == IDC_IMP_OK);
                bool pressed = (dis->itemState & ODS_SELECTED) != 0;
                COLORREF bg = okBtn ? (pressed ? RGB(90, 74, 36) : RGB(70, 58, 28))
                                    : (pressed ? RGB(55, 58, 68) : RGB(42, 44, 52));
                HBRUSH br = CreateSolidBrush(bg);
                FillRect(dis->hDC, &dis->rcItem, br);
                DeleteObject(br);
                HPEN pen = CreatePen(PS_SOLID, 1, kImpYellow);
                HPEN old = (HPEN)SelectObject(dis->hDC, pen);
                SelectObject(dis->hDC, GetStockObject(NULL_BRUSH));
                Rectangle(dis->hDC, dis->rcItem.left, dis->rcItem.top,
                          dis->rcItem.right - 1, dis->rcItem.bottom - 1);
                SelectObject(dis->hDC, old);
                DeleteObject(pen);
                wchar_t text[32] = {};
                GetWindowTextW(dis->hwndItem, text, 32);
                SetBkMode(dis->hDC, TRANSPARENT);
                SetTextColor(dis->hDC, kImpText);
                if (d && d->font) SelectObject(dis->hDC, d->font);
                DrawTextW(dis->hDC, text, -1, (RECT*)&dis->rcItem,
                          DT_CENTER | DT_VCENTER | DT_SINGLELINE);
                return TRUE;
            }
            case WM_COMMAND: {
                int id = LOWORD(wp);
                if (id == IDC_IMP_OK && d) {
                    wchar_t buf[8192] = {};
                    GetWindowTextW(GetDlgItem(hwnd, IDC_IMP_TEXT), buf, 8192);
                    d->text = utf8_from_wstring(buf);
                    if (d->text.empty()) {
                        MessageBoxW(hwnd, L"请粘贴要导入的卡密", L"提示", MB_OK | MB_ICONWARNING);
                        return 0;
                    }
                    d->ok = true;
                    DestroyWindow(hwnd);
                    return 0;
                }
                if (id == IDC_IMP_CANCEL || id == IDCANCEL) {
                    DestroyWindow(hwnd);
                    return 0;
                }
                break;
            }
            case WM_CLOSE:
                DestroyWindow(hwnd);
                return 0;
            case WM_DESTROY:
                if (d) {
                    if (d->brBg) { DeleteObject(d->brBg); d->brBg = nullptr; }
                    if (d->brInput) { DeleteObject(d->brInput); d->brInput = nullptr; }
                    if (d->font) { DeleteObject(d->font); d->font = nullptr; }
                }
                return 0;
            }
            return DefWindowProcW(hwnd, msg, wp, lp);
        };
        wc.hInstance = GetModuleHandleW(nullptr);
        wc.hbrBackground = CreateSolidBrush(kImpBg);
        wc.hCursor = LoadCursor(nullptr, IDC_ARROW);
        wc.lpszClassName = cls;
        wc.style = CS_DROPSHADOW;
        RegisterClassExW(&wc);
        registered = true;
    }

    ImpDlgData data;
    data.self = this;

    RECT prc{};
    GetWindowRect(hwndMain_, &prc);
    int w = 400, h = 300;
    int x = prc.left + ((prc.right - prc.left) - w) / 2;
    int y = prc.top + ((prc.bottom - prc.top) - h) / 2;

    HWND dlg = CreateWindowExW(WS_EX_DLGMODALFRAME | WS_EX_TOPMOST, cls, L"导入卡密",
        WS_CAPTION | WS_POPUP | WS_SYSMENU,
        x, y, w, h, hwndMain_, nullptr, GetModuleHandleW(nullptr), &data);
    if (!dlg) return;

    BOOL dark = TRUE;
    DwmSetWindowAttribute(dlg, 20, &dark, sizeof(dark));

    EnableWindow(hwndMain_, FALSE);
    ShowWindow(dlg, SW_SHOW);
    UpdateWindow(dlg);

    MSG msg;
    while (IsWindow(dlg)) {
        BOOL gm = GetMessage(&msg, nullptr, 0, 0);
        if (gm <= 0) break;
        if (!IsDialogMessage(dlg, &msg)) {
            TranslateMessage(&msg);
            DispatchMessage(&msg);
        }
    }
    EnableWindow(hwndMain_, TRUE);
    SetForegroundWindow(hwndMain_);
    if (!data.ok) return;

    // 解析并导入卡密
    int added = 0;
    std::stringstream ss(data.text);
    std::string line;
    while (std::getline(ss, line)) {
        // 去除首尾空白和可能的分隔符
        line.erase(0, line.find_first_not_of(" \t\r\n"));
        line.erase(line.find_last_not_of(" \t\r\n") + 1);
        if (line.empty()) continue;
        // 校验格式：19位或17位（有/无连字符）
        std::string clean;
        for (char ch : line) {
            if (ch != '-' && ch != ' ') clean += toupper(ch);
        }
        if (clean.length() < 16) continue;
        // 检查是否已存在
        bool dup = false;
        for (const auto& c : cards_) {
            if (c.cardkey == clean) { dup = true; break; }
        }
        if (dup) continue;
        CardEntry c;
        c.cardkey = clean;
        c.duration_type = 0;
        c.duration_value = 30;
        c.status = 0;
        c.usage_count = 0;
        cards_.push_back(std::move(c));
        ++added;
    }
    if (added > 0) {
        SaveCards();
        RefreshCardList();
        UpdateDashboardStats();
        LogSuccess("成功导入 " + std::to_string(added) + " 条卡密");
    } else {
        LogWarning("没有新卡密被导入（可能已存在或格式无效）");
    }
}
