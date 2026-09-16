#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <commctrl.h>
#include <uxtheme.h>
#include <string>
#include <thread>
#include <vector>
#include <sstream>
#include <ctime>

#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "uxtheme.lib")

#include "../src/PeanutClient/sdk/peanut_secure_client.h"
#include "../src/PeanutClient/sdk/security_runtime.h"
#include "../src/PeanutClient/sdk/embedded_client_config.h"

#define WM_CLIENT_STATUS        (WM_APP + 1)
#define WM_CLIENT_HEARTBEAT     (WM_APP + 2)
#define WM_CLIENT_PLUGIN_RESULT (WM_APP + 3)
#define WM_CLIENT_UPDATE       (WM_APP + 4)

// 纯白主题：浅灰底 + 蓝色强调
static constexpr COLORREF BG_ROOT   = RGB(245, 247, 250);
static constexpr COLORREF BG_CARD   = RGB(255, 255, 255);
static constexpr COLORREF ACCENT    = RGB(30, 100, 200);
static constexpr COLORREF ACCENT2   = RGB(50, 120, 220);
static constexpr COLORREF GREEN     = RGB(22, 163, 74);
static constexpr COLORREF TEXT_DARK = RGB(20, 24, 32);
static constexpr COLORREF TEXT_GRAY = RGB(80, 90, 105);
static constexpr COLORREF BORDER_C  = RGB(190, 198, 210);
static constexpr COLORREF BG_INPUT  = RGB(255, 255, 255);
static constexpr COLORREF BG_BTN    = RGB(235, 240, 248);

struct ClientState {
    std::string host = "127.0.0.1";
    int port = 9001;
    std::string token, cardkey, machine_code, card_status;
    int usage_minutes = 0;
    long long remaining_seconds = 0;
    bool connected = false, activated = false;
    std::string last_plugin_result;
};

static ClientState g_state;
static std::unique_ptr<peanut::sdk::PeanutSecureClient> g_client;
static HWND g_hwnd = nullptr;
static HWND g_hStatus = nullptr, g_hInfo = nullptr;
static HWND g_hCardKey = nullptr, g_hActBtn = nullptr;
static HWND g_hFuncName = nullptr, g_hFuncParam = nullptr, g_hFuncCallBtn = nullptr;
static HWND g_hPluginResult = nullptr, g_hLog = nullptr;
static HWND g_hExpire = nullptr, g_hUpdateText = nullptr, g_hUpdateProgress = nullptr;
static int g_update_value = 0;
static std::string g_update_text;
static HFONT g_font = nullptr, g_fontBig = nullptr, g_fontMono = nullptr, g_fontTitle = nullptr;
static HBRUSH g_brRoot = nullptr, g_brCard = nullptr, g_brInput = nullptr;
static HWND g_panelLabels[16] = {};
static int g_panelLabelCount = 0;
static void TrackPanelLabel(HWND h) {
    if (h && g_panelLabelCount < 16) g_panelLabels[g_panelLabelCount++] = h;
}
static bool IsPanelLabel(HWND h) {
    for (int i = 0; i < g_panelLabelCount; ++i)
        if (g_panelLabels[i] == h) return true;
    return false;
}
static bool g_heartbeat_running = false;
static peanut::security::AuthorizationGuard g_auth_guard;
static peanut::security::DeviceIdentity g_device_identity;

static std::wstring wstr(const std::string&);
static std::string astr(const std::wstring&);

static std::wstring ConfigPath() {
    wchar_t p[MAX_PATH]{};
    GetModuleFileNameW(nullptr, p, MAX_PATH);
    std::wstring s = p;
    return s.substr(0, s.find_last_of(L"\\/") + 1) + L"client_demo2.ini";
}
static void LoadClientConfig() {
    wchar_t b[256]{};
    auto p = ConfigPath();
    GetPrivateProfileStringW(L"Client", L"cardkey", L"", b, 256, p.c_str());
    g_state.cardkey = astr(b);
    GetPrivateProfileStringW(L"Client", L"host", L"127.0.0.1", b, 256, p.c_str());
    g_state.host = astr(b);
    g_state.port = GetPrivateProfileIntW(L"Client", L"port", 9001, p.c_str());
}
static void SaveClientConfig() {
    auto p = ConfigPath();
    WritePrivateProfileStringW(L"Client", L"cardkey", wstr(g_state.cardkey).c_str(), p.c_str());
    WritePrivateProfileStringW(L"Client", L"host", wstr(g_state.host).c_str(), p.c_str());
    WritePrivateProfileStringW(L"Client", L"port", std::to_wstring(g_state.port).c_str(), p.c_str());
}

static std::wstring wstr(const std::string& s) {
    if (s.empty()) return L"";
    int n = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, nullptr, 0);
    std::vector<wchar_t> b(n);
    MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, b.data(), n);
    return b.data();
}
static std::string astr(const std::wstring& s) {
    if (s.empty()) return "";
    int n = WideCharToMultiByte(CP_UTF8, 0, s.c_str(), -1, nullptr, 0, nullptr, nullptr);
    std::vector<char> b(n);
    WideCharToMultiByte(CP_UTF8, 0, s.c_str(), -1, b.data(), n, nullptr, nullptr);
    return b.data();
}
static std::string GetMachineCode() {
    g_device_identity = peanut::security::CollectDeviceIdentity("startup", "client_demo2");
    return g_device_identity.device_id;
}
static void Log(const std::string& s) {
    if (!g_hLog) return;
    int len = GetWindowTextLength(g_hLog);
    SendMessage(g_hLog, EM_SETSEL, len, len);
    SendMessage(g_hLog, EM_REPLACESEL, FALSE, (LPARAM)wstr(s + "\r\n").c_str());
    SendMessage(g_hLog, EM_SCROLLCARET, 0, 0);
}
static void UpdateInfo() {
    std::string s;
    if (!g_state.connected)
        s = "状态  ·  未连接    服务器  ·  " + g_state.host + ":" + std::to_string(g_state.port);
    else if (!g_state.activated)
        s = "状态  ·  已连接    请输入卡密完成登录";
    else {
        char remain[64] = {};
        if (g_state.remaining_seconds > 0) {
            int d = (int)(g_state.remaining_seconds / 86400);
            int h = (int)((g_state.remaining_seconds % 86400) / 3600);
            int m = (int)((g_state.remaining_seconds % 3600) / 60);
            if (d > 0) snprintf(remain, sizeof(remain), "%d天 %02d:%02d", d, h, m);
            else snprintf(remain, sizeof(remain), "%02d:%02d", h, m);
        } else strcpy(remain, "永久");
        s = "卡密  ·  " + g_state.cardkey +
            "    状态  ·  " + g_state.card_status +
            "    剩余  ·  " + remain +
            "    使用  ·  " + std::to_string(g_state.usage_minutes) + " 分钟";
    }
    SetWindowText(g_hInfo, wstr(s).c_str());
    if (g_hExpire) {
        std::string t = "到期时间  ·  --";
        if (g_state.activated && g_state.remaining_seconds > 0) {
            time_t end = time(nullptr) + g_state.remaining_seconds;
            tm x{};
            localtime_s(&x, &end);
            char b[64];
            strftime(b, sizeof(b), "%Y-%m-%d %H:%M:%S", &x);
            t = std::string("到期时间  ·  ") + b;
        }
        SetWindowText(g_hExpire, wstr(t).c_str());
    }
}
static void HeartbeatThread() {
    int seconds_since_heartbeat = 0;
    while (g_heartbeat_running) {
        Sleep(1000);
        if (!g_heartbeat_running) break;

        // 每秒本地闸门：remaining 倒计时到零或完整性校验失败，立即 fail-closed。
        if (!g_auth_guard.RequireAuthorized()) {
            g_state.card_status = "授权失效";
            g_state.activated = false;
            g_heartbeat_running = false;
            g_auth_guard.Invalidate(g_auth_guard.RemainingSeconds() <= 0
                ? peanut::security::AuthorizationState::AUTH_EXPIRED
                : peanut::security::AuthorizationState::HEARTBEAT_LOST);
            peanut::security::FailClosedOnAuthLoss(g_auth_guard, &g_state.token, true, 42);
            return;
        }

        g_state.remaining_seconds = g_auth_guard.RemainingSeconds();
        PostMessage(g_hwnd, WM_CLIENT_HEARTBEAT, 0, 0);
        if (++seconds_since_heartbeat < 30) continue;
        seconds_since_heartbeat = 0;

        if (!g_client || !g_state.activated) continue;
        std::string status;
        int minutes = 0;
        long long remaining = 0;
        bool ok = g_client->SendHeartbeat(g_state.token, status, minutes, remaining);
        if (ok && g_auth_guard.RecordHeartbeat(true, remaining)) {
            g_state.card_status = status;
            g_state.usage_minutes = minutes;
            g_state.remaining_seconds = remaining;
            continue;
        }

        const std::string server_error = g_client->GetLastServerError();
        if (!server_error.empty()) {
            // 服务端明确拒绝（过期、被踢、会话撤销）：不进入断网容错。
            Log("[授权] 服务端已撤销会话: " + server_error);
            g_auth_guard.Invalidate(server_error.find("过期") != std::string::npos
                ? peanut::security::AuthorizationState::AUTH_EXPIRED
                : peanut::security::AuthorizationState::SERVER_REVOKED);
            g_state.card_status = "授权已撤销";
            g_state.activated = false;
            g_heartbeat_running = false;
            peanut::security::FailClosedOnAuthLoss(g_auth_guard, &g_state.token, true, 43);
            return;
        }

        // 纯传输失败不立刻退出；RequireAuthorized 会在最后一次成功心跳 5 分钟后关闭。
        Log("[心跳] 网络失败，已进入5分钟容错窗口");
    }
}static void ConnectToServer() {
    Log("[客户端] 正在连接 " + g_state.host + ":" + std::to_string(g_state.port) + "...");
    try {
        g_client = std::make_unique<peanut::sdk::PeanutSecureClient>();
        g_client->SetServer(g_state.host, g_state.port);
        g_client->SetTransportMode(peanut::sdk::TransportMode::TCP);
        std::string hmac = peanut::embedded_config::HmacKey();
        std::string cipher = peanut::embedded_config::CipherKeyHex();
        std::string psp = peanut::embedded_config::PspKeyHex();
        std::string rsa = peanut::embedded_config::ServerRsaPubkeyHex();
        g_client->SetCredentials(hmac, cipher);
        g_client->SetPSPKey(psp);
        g_client->SetServerRsaPubkeyHex(rsa);
        peanut::security::SecureErase(hmac);
        peanut::security::SecureErase(cipher);
        peanut::security::SecureErase(psp);
        peanut::security::SecureErase(rsa);
        g_client->SetCallbacks([](const std::string& m, int) { Log("[SDK] " + m); });
        g_state.connected = g_client->Connect();
        if (g_state.connected) {
            peanut::sdk::SessionPolicy sessionPolicy;
            std::string policyError;
            if (g_client->FetchSessionPolicy(sessionPolicy, &policyError)) {
                Log(sessionPolicy.multi_open_enabled
                    ? "[会话策略] 服务端允许同卡多开，最大在线=" + std::to_string(sessionPolicy.max_online_per_card)
                    : "[会话策略] 服务端禁止同卡多开，新登录将使旧会话失效");
            } else {
                Log("[会话策略] 获取失败: " + policyError);
            }
            auto update = peanut::security::CheckAndApplyUpdate(
                *g_client, "client_demo2", "2.1.0",
                [](int v, const std::string& t) {
                    g_update_value = v;
                    g_update_text = t;
                    PostMessage(g_hwnd, WM_CLIENT_UPDATE, 0, 0);
                });
            Log("[更新] " + update.message);
            if (!update.allowed) {
                g_state.connected = false;
                if (update.update_started) PostMessage(g_hwnd, WM_CLOSE, 0, 0);
            }
        }
        Log(g_state.connected ? "[客户端] 连接成功" : "[客户端] 连接失败");
    } catch (const std::exception& e) {
        g_state.connected = false;
        Log(std::string("[客户端] 错误: ") + e.what());
    }
    PostMessage(g_hwnd, WM_CLIENT_STATUS, 0, 0);
}

static void DrawRoundRect(HDC hdc, RECT rc, COLORREF fill, COLORREF border, int radius = 10) {
    HBRUSH br = CreateSolidBrush(fill);
    HPEN pen = CreatePen(PS_SOLID, 1, border);
    HGDIOBJ oldBr = SelectObject(hdc, br);
    HGDIOBJ oldPen = SelectObject(hdc, pen);
    RoundRect(hdc, rc.left, rc.top, rc.right, rc.bottom, radius, radius);
    SelectObject(hdc, oldBr);
    SelectObject(hdc, oldPen);
    DeleteObject(br);
    DeleteObject(pen);
}

static LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    switch (msg) {
    case WM_CREATE: {
        g_hwnd = hwnd;
        g_brRoot = CreateSolidBrush(BG_ROOT);
        g_brCard = CreateSolidBrush(BG_CARD);
        g_brInput = CreateSolidBrush(BG_INPUT);
        {
            LOGFONTW lf = { 17, 0, 0, 0, FW_NORMAL };
            wcscpy_s(lf.lfFaceName, L"Microsoft YaHei");
            g_font = CreateFontIndirectW(&lf);
        }
        {
            LOGFONTW lf = { 20, 0, 0, 0, FW_SEMIBOLD };
            wcscpy_s(lf.lfFaceName, L"Microsoft YaHei");
            g_fontBig = CreateFontIndirectW(&lf);
        }
        {
            LOGFONTW lf = { 22, 0, 0, 0, FW_BOLD };
            wcscpy_s(lf.lfFaceName, L"Microsoft YaHei");
            g_fontTitle = CreateFontIndirectW(&lf);
        }
        {
            LOGFONTW lf = { 18, 0, 0, 0, FW_NORMAL };
            wcscpy_s(lf.lfFaceName, L"Microsoft YaHei");
            g_fontMono = CreateFontIndirectW(&lf);
        }

        auto ctl = [&](const wchar_t* cls, const wchar_t* txt, DWORD style, int x, int y, int w, int h, int id) {
            HWND c = CreateWindowEx(0, cls, txt, WS_CHILD | WS_VISIBLE | style,
                x, y, w, h, hwnd, (HMENU)(INT_PTR)id, nullptr, nullptr);
            if (c && g_font) SendMessage(c, WM_SETFONT, (WPARAM)g_font, TRUE);
            return c;
        };

        HWND hTitle = ctl(L"STATIC", L"纯白验证者", SS_LEFT, 28, 18, 280, 28, -1);
        SendMessage(hTitle, WM_SETFONT, (WPARAM)g_fontTitle, TRUE);
        ctl(L"STATIC", L"Peanut Secure Client  ·  Demo 2", SS_LEFT, 28, 48, 320, 20, -1);
        g_hStatus = ctl(L"STATIC", L"○  未连接", SS_RIGHT, 400, 28, 200, 24, -1);

        g_hInfo = ctl(L"STATIC", L"正在初始化...", SS_LEFT, 44, 100, 530, 48, -1);
        TrackPanelLabel(g_hInfo);

        TrackPanelLabel(ctl(L"STATIC", L"卡密登录", SS_LEFT, 44, 180, 120, 22, -1));
        g_hCardKey = ctl(L"EDIT", L"", ES_LEFT | ES_AUTOHSCROLL, 44, 208, 420, 32, 1001);
        g_hActBtn = ctl(L"BUTTON", L"登  录", BS_OWNERDRAW, 476, 208, 104, 32, 1002);

        TrackPanelLabel(ctl(L"STATIC", L"云函数调用", SS_LEFT, 44, 262, 140, 22, -1));
        TrackPanelLabel(ctl(L"STATIC", L"函数名", SS_LEFT, 44, 290, 60, 20, -1));
        g_hFuncName = ctl(L"EDIT", L"", ES_LEFT | ES_AUTOHSCROLL, 104, 286, 200, 28, 1003);
        TrackPanelLabel(ctl(L"STATIC", L"参数", SS_LEFT, 320, 290, 40, 20, -1));
        g_hFuncParam = ctl(L"EDIT", L"{}", ES_LEFT | ES_AUTOHSCROLL, 360, 286, 106, 28, 1007);
        g_hFuncCallBtn = ctl(L"BUTTON", L"调  用", BS_OWNERDRAW, 476, 286, 104, 28, 1004);

        ctl(L"STATIC", L"返回结果", SS_LEFT, 44, 336, 100, 20, -1);
        g_hPluginResult = ctl(L"EDIT", L"", ES_LEFT | ES_MULTILINE | ES_READONLY | WS_VSCROLL,
            44, 360, 536, 72, 1005);
        SendMessage(g_hPluginResult, WM_SETFONT, (WPARAM)g_fontMono, TRUE);

        ctl(L"STATIC", L"运行日志", SS_LEFT, 44, 444, 100, 20, -1);
        g_hLog = ctl(L"EDIT", L"", ES_LEFT | ES_MULTILINE | ES_READONLY | WS_VSCROLL | ES_AUTOVSCROLL,
            44, 468, 536, 100, 1006);
        SendMessage(g_hLog, WM_SETFONT, (WPARAM)g_fontMono, TRUE);
        SetWindowTheme(g_hPluginResult, L"", L"");
        SetWindowTheme(g_hLog, L"", L"");

        g_hExpire = ctl(L"STATIC", L"到期时间  ·  --", SS_LEFT, 44, 586, 280, 22, 1010);
        g_hUpdateText = ctl(L"STATIC", L"更新  ·  就绪", SS_RIGHT, 320, 586, 260, 22, 1011);
        g_hUpdateProgress = ctl(PROGRESS_CLASSW, L"", PBS_SMOOTH, 320, 612, 260, 8, 1012);
        SetWindowTheme(g_hUpdateProgress, L"", L"");
        SendMessage(g_hUpdateProgress, PBM_SETBKCOLOR, 0, BG_INPUT);
        SendMessage(g_hUpdateProgress, PBM_SETBARCOLOR, 0, ACCENT);
        SendMessage(g_hUpdateProgress, PBM_SETRANGE, 0, MAKELPARAM(0, 100));
        ShowWindow(g_hUpdateProgress, SW_HIDE);

        LoadClientConfig();
        SetWindowText(g_hCardKey, wstr(g_state.cardkey).c_str());
        g_state.machine_code = GetMachineCode();
        std::thread([]() { Sleep(500); ConnectToServer(); }).detach();
        return 0;
    }
    case WM_CTLCOLORSTATIC: {
        HDC hdc = (HDC)wp;
        HWND ctrl = (HWND)lp;
        SetBkMode(hdc, TRANSPARENT);
        SetTextColor(hdc, TEXT_DARK);
        if (IsPanelLabel(ctrl))
            return (LRESULT)g_brCard;
        return (LRESULT)g_brRoot;
    }
    case WM_CTLCOLOREDIT: {
        HDC hdc = (HDC)wp;
        SetBkMode(hdc, OPAQUE);
        SetBkColor(hdc, BG_INPUT);
        SetTextColor(hdc, TEXT_DARK);
        return (LRESULT)g_brInput;
    }
    case WM_DRAWITEM: {
        auto* dis = (LPDRAWITEMSTRUCT)lp;
        if (!dis || dis->CtlType != ODT_BUTTON) break;
        bool pressed = (dis->itemState & ODS_SELECTED) != 0;
        bool isAct = (dis->CtlID == 1002);
        COLORREF bg = pressed ? RGB(226, 232, 240) : (isAct ? ACCENT : BG_BTN);
        COLORREF fg = isAct ? RGB(255, 255, 255) : TEXT_DARK;
        COLORREF bd = isAct ? ACCENT2 : BORDER_C;
        DrawRoundRect(dis->hDC, dis->rcItem, bg, bd, 6);
        wchar_t txt[32] = {};
        GetWindowTextW(dis->hwndItem, txt, 32);
        SetBkMode(dis->hDC, TRANSPARENT);
        SetTextColor(dis->hDC, fg);
        if (g_font) SelectObject(dis->hDC, g_font);
        DrawTextW(dis->hDC, txt, -1, (RECT*)&dis->rcItem, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
        return TRUE;
    }
    case WM_COMMAND: {
        int id = LOWORD(wp);
        if (id == 1002) {
            wchar_t buf[128] = {};
            GetWindowTextW(g_hCardKey, buf, 128);
            std::string cardkey = astr(buf);
            if (cardkey.empty()) { Log("[登录] 请输入卡密"); return 0; }
            g_state.cardkey = cardkey;
            SaveClientConfig();
            if (!g_client || !g_state.connected) {
                Log("[登录] 当前未连接，正在重新连接服务器...");
                ConnectToServer();
                if (!g_state.connected) {
                    Log("[登录] 重连失败，请确认服务端9001已监听");
                    return 0;
                }
            }
            Log("[登录] 正在验证 " + cardkey + "...");
            std::string token, actErr;
            g_auth_guard.BeginLogin();
            if (g_client->Activate(cardkey, g_state.machine_code, token, &actErr) &&
                g_auth_guard.CompleteLogin(token, g_client->GetLastActivationRemainingSeconds(), g_state.machine_code) &&
                g_auth_guard.EnterRunning()) {
                g_state.token = token;
                g_state.cardkey = cardkey;
                g_state.activated = true;
                g_state.card_status = "已激活";
                g_state.remaining_seconds = g_client->GetLastActivationRemainingSeconds();
                SaveClientConfig();
                Log("[登录] 成功，安全会话已建立");
                g_heartbeat_running = true;
                std::thread(HeartbeatThread).detach();
            } else Log("[登录] 失败: " + (actErr.empty() ? "未知错误" : actErr));
            PostMessage(hwnd, WM_CLIENT_STATUS, 0, 0);
        }
        if (id == 1004) {
            if (!g_state.activated || !g_auth_guard.RequireAuthorized()) {
                Log("[调用] 授权无效，请重新登录");
                return 0;
            }
            wchar_t buf[128] = {};
            GetWindowTextW(g_hFuncName, buf, 128);
            std::string name = astr(buf);
            if (name.empty()) { Log("[调用] 请输入函数名"); return 0; }
            GetWindowTextW(g_hFuncParam, buf, 128);
            std::string input = astr(buf);
            if (input.empty()) input = "{}";
            Log("[调用] " + name + " -> " + input);
            std::thread([name, input]() {
                std::string result;
                g_state.last_plugin_result = g_client->CallPlugin(g_state.token, name, input, result)
                    ? result : "[调用] 失败";
                PostMessage(g_hwnd, WM_CLIENT_PLUGIN_RESULT, 0, 0);
            }).detach();
        }
        break;
    }
    case WM_CLIENT_STATUS: {
        std::wstring s = g_state.connected
            ? (g_state.activated ? L"●  已激活" : L"●  已连接")
            : L"○  未连接";
        SetWindowText(g_hStatus, s.c_str());
        UpdateInfo();
        EnableWindow(g_hActBtn, !g_state.activated);
        EnableWindow(g_hFuncCallBtn, g_state.activated);
        break;
    }
    case WM_CLIENT_HEARTBEAT: UpdateInfo(); break;
    case WM_CLIENT_PLUGIN_RESULT:
        SetWindowText(g_hPluginResult, wstr(g_state.last_plugin_result).c_str());
        Log("[调用] 结果已返回");
        break;
    case WM_CLIENT_UPDATE: {
        bool active = g_update_value > 0 && g_update_value < 100;
        SetWindowText(g_hUpdateText, wstr("更新  ·  " + g_update_text).c_str());
        ShowWindow(g_hUpdateProgress, active ? SW_SHOW : SW_HIDE);
        if (active) SendMessage(g_hUpdateProgress, PBM_SETPOS, g_update_value, 0);
        break;
    }
    case WM_ERASEBKGND: return 1;
    case WM_PAINT: {
        PAINTSTRUCT ps;
        HDC hdc = BeginPaint(hwnd, &ps);
        RECT rc;
        GetClientRect(hwnd, &rc);
        FillRect(hdc, &rc, g_brRoot);

        HPEN pen = CreatePen(PS_SOLID, 3, ACCENT);
        HGDIOBJ old = SelectObject(hdc, pen);
        MoveToEx(hdc, 28, 78, nullptr);
        LineTo(hdc, rc.right - 28, 78);
        SelectObject(hdc, old);
        DeleteObject(pen);

        RECT card1 = { 28, 90, rc.right - 28, 160 };
        DrawRoundRect(hdc, card1, BG_CARD, BORDER_C, 12);

        RECT card2 = { 28, 174, rc.right - 28, 252 };
        DrawRoundRect(hdc, card2, BG_CARD, BORDER_C, 12);

        RECT card3 = { 28, 264, rc.right - 28, 326 };
        DrawRoundRect(hdc, card3, BG_CARD, BORDER_C, 12);

        EndPaint(hwnd, &ps);
        return 0;
    }
    case WM_DESTROY:
        peanut::security::ReleaseSingleInstance();
        SaveClientConfig();
        g_heartbeat_running = false;
        if (g_client) g_client->Disconnect();
        if (g_brRoot) DeleteObject(g_brRoot);
        if (g_brCard) DeleteObject(g_brCard);
        if (g_brInput) DeleteObject(g_brInput);
        if (g_font) DeleteObject(g_font);
        if (g_fontBig) DeleteObject(g_fontBig);
        if (g_fontTitle) DeleteObject(g_fontTitle);
        if (g_fontMono) DeleteObject(g_fontMono);
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProc(hwnd, msg, wp, lp);
}

int WINAPI WinMain(HINSTANCE hInst, HINSTANCE, LPSTR, int nCmd) {
    if (peanut::security::HandleUpdaterMode()) return 0;
    if (!peanut::security::TryAcquireSingleInstance(L"Global\\PeanutSecure_ClientDemo2")) {
        MessageBoxW(nullptr, L"本客户端禁止在同一台电脑上多开。", L"Peanut 安全策略", MB_OK | MB_ICONWARNING);
        return 2;
    }
    INITCOMMONCONTROLSEX icc = { sizeof(icc), ICC_STANDARD_CLASSES | ICC_PROGRESS_CLASS };
    InitCommonControlsEx(&icc);

    WNDCLASSEX wc = { sizeof(wc) };
    wc.style = CS_HREDRAW | CS_VREDRAW;
    wc.lpfnWndProc = WndProc;
    wc.hInstance = hInst;
    wc.hCursor = LoadCursor(nullptr, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)GetStockObject(NULL_BRUSH);
    wc.lpszClassName = L"PeanutClientDemo2";
    RegisterClassEx(&wc);

    RECT r = { 0, 0, 620, 650 };
    AdjustWindowRect(&r, WS_OVERLAPPEDWINDOW & ~WS_MAXIMIZEBOX & ~WS_THICKFRAME, FALSE);
    HWND hwnd = CreateWindowEx(0, L"PeanutClientDemo2", L"Peanut · 纯白验证者",
        WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX,
        CW_USEDEFAULT, CW_USEDEFAULT, r.right - r.left, r.bottom - r.top,
        nullptr, nullptr, hInst, nullptr);
    if (!hwnd) return 1;

    ShowWindow(hwnd, nCmd);
    MSG msg;
    while (GetMessage(&msg, nullptr, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }
    return 0;
}
