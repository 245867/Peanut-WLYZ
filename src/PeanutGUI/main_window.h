// ============================================================
// Peanut WLYZ — 主窗口  v7.0
// 暗黑主题 · 原生Win32 + GDI+ 绘制
// 顶部导航 · 全局底部日志
// ============================================================

#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <commctrl.h>
#include <objbase.h>
#include <gdiplus.h>
#include <string>
#include <vector>
#include <functional>
#include <memory>
#include <chrono>
#include <mutex>
#include <map>
#include <httplib.h>

#include "resource.h"
#include "../PeanutClient/protocol/shadow_tunnel.h"
#include "../PeanutClient/api/client_api.h"
#include "../PeanutClient/sdk/peanut_secure_client.h"

// ═══════════════════════════════════════════════════════════
//  深色专业主题颜色常量
// ═══════════════════════════════════════════════════════════
namespace peanut_theme {
    // 暗黑背景（炭黑）
    constexpr COLORREF BG_DEEP       = RGB(14,  14,  16);   // 主背景
    constexpr COLORREF BG_SIDEBAR    = RGB(20,  20,  24);   // 顶栏/底栏
    constexpr COLORREF BG_TOPNAV     = RGB(20,  20,  24);
    constexpr COLORREF BG_LOG        = RGB(18,  18,  22);   // 全局日志
    constexpr COLORREF BG_CARD       = RGB(30,  32,  38);   // 卡片（略提亮，避免死黑）
    constexpr COLORREF BG_INPUT      = RGB(26,  28,  34);   // 列表/输入
    constexpr COLORREF BG_HEADER     = RGB(34,  36,  44);   // 表头
    constexpr COLORREF BG_HOVER      = RGB(40,  42,  52);

    constexpr COLORREF ACCENT        = RGB(220, 70,  90);
    constexpr COLORREF ACCENT_DIM    = RGB(160, 45,  65);
    constexpr COLORREF ACCENT_GLOW   = RGB(255, 100, 120);

    constexpr COLORREF TEXT_PRIMARY  = RGB(228, 230, 235);
    constexpr COLORREF TEXT_SECONDARY= RGB(148, 152, 162);
    constexpr COLORREF TEXT_MUTED    = RGB(100, 104, 114);

    constexpr COLORREF SUCCESS       = RGB(70,  190, 120);
    constexpr COLORREF WARNING       = RGB(230, 180, 60);
    constexpr COLORREF ERROR_COLOR   = RGB(230, 70,  80);
    constexpr COLORREF INFO          = RGB(80,  160, 230);

    // 边框用近黑，避免发白
    constexpr COLORREF BORDER        = RGB(8,   8,   10);
    constexpr COLORREF DIVIDER       = RGB(16,  16,  20);

    inline Gdiplus::Color GpBg()        { return Gdiplus::Color(14,  14,  16); }
    inline Gdiplus::Color GpSidebar()   { return Gdiplus::Color(20,  20,  24); }
    inline Gdiplus::Color GpTopNav()    { return Gdiplus::Color(20,  20,  24); }
    inline Gdiplus::Color GpCard()      { return Gdiplus::Color(30,  32,  38); }
    inline Gdiplus::Color GpAccent()    { return Gdiplus::Color(220, 70,  90); }
    inline Gdiplus::Color GpText()      { return Gdiplus::Color(228, 230, 235); }
    inline Gdiplus::Color GpSuccess()   { return Gdiplus::Color(70,  190, 120); }
    inline Gdiplus::Color GpError()     { return Gdiplus::Color(230, 70,  80); }
    inline Gdiplus::Color GpBorder()    { return Gdiplus::Color(8,   8,   10); }
}

// ═══════════════════════════════════════════════════════════
//  应用配置
// ═══════════════════════════════════════════════════════════
struct AppConfig {
    std::string host            = "127.0.0.1";
    int         port            = 9001;
    std::string hmac_key        = "db6a39f06c16ed5a6412a4b4c34c32d4";
    std::string aes_key_hex     = "27ebb594238231057d38e77d43a376ceac334224389d80be909c5e05911e6670";
    std::string psp_key_hex     = "0E041BFD4F1BC438BE671F65975EE9C23482C2F5D93253976B86D03AF747E171";
    std::string rsa_pubkey_hex;        // 服务端 RSA 公钥 hex (n:e)
    std::string auth_token;           // 激活后的会话 token（远程调用云 DLL）
    int         protocol_mode   = 0;  // TCP
    // UI 记忆
    bool        log_auto_scroll = true;
    int         card_filter     = 0;  // 0全部 1激活 2过期 3禁用
    int         last_nav_tab    = 0;  // NavTab 序号
    int         window_x        = CW_USEDEFAULT;
    int         window_y        = CW_USEDEFAULT;
    int         window_w        = 1280;
    int         window_h        = 800;
    // 卡密权限
    bool        unbind_enabled  = true;
    int         unbind_limit_day  = 1;   // 每天最多解绑次数
    int         unbind_limit_month = 3;  // 每月最多解绑次数
    // 在线并发（服务端强制；客户端另有本机单实例）
    // multi_open_enabled=false 时 max_online 强制为 1（同卡仅保留最新会话）
    bool        multi_open_enabled = false;
    int         max_online_per_card = 1;  // 同卡最多同时在线会话数
    // 防火墙
    int         fw_max_attempts   = 5;   // 允许失败次数
    int         fw_window_minutes = 10;  // 统计窗口(分钟)
    int         fw_ban_minutes    = 30;  // 封禁时长(分钟)
    bool        force_update_enabled = false;
    std::string update_target_file = "client_demo1.exe";
    std::string update_target_sha256;
    std::string update_package_id = "current";
    std::string update_package_path;
    std::string update_package_sha256;
    long long   update_package_size = 0;
    std::string update_latest_version = "2.1.0";
    std::string update_minimum_version = "2.1.0";
};

// ═══════════════════════════════════════════════════════════
//  卡密条目
// ═══════════════════════════════════════════════════════════
struct CardEntry {
    std::string cardkey;
    int         duration_type;   // 0=天, 1=小时, 2=月, 3=年, 4=永久
    int         duration_value;
    int         status;          // 0=未使用, 1=已激活, 2=已过期, 3=已禁用
    std::string machine_code;
    std::string activate_time;
    std::string expire_time;
    std::string remark;
    int         usage_count;
};

// ═══════════════════════════════════════════════════════════
//  导航标签页枚举
// ═══════════════════════════════════════════════════════════
enum class NavTab {
    Dashboard   = 0,
    CardMgmt    = 1,
    PluginCenter= 2,
    Settings    = 3,
    Firewall    = 4
};

// ═══════════════════════════════════════════════════════════
//  顶部导航按钮
// ═══════════════════════════════════════════════════════════
struct NavButton {
    HWND        hwnd;
    NavTab      tab;
    const wchar_t* label;
    const wchar_t* icon;
    bool        isActive;
    bool        isHovered = false;
};

// ═══════════════════════════════════════════════════════════
//  仪表盘统计卡片
// ═══════════════════════════════════════════════════════════
struct StatCard {
    HWND        hwndPanel = nullptr;
    HWND        hwndTitle = nullptr;
    HWND        hwndValue = nullptr;
    HWND        hwndIcon  = nullptr;
    const wchar_t* title = L"";
    const wchar_t* subtext = L"";
    const wchar_t* iconGlyph = L"";  // 展示用符号
    std::wstring value;
    COLORREF    accentColor = RGB(220, 70, 90);
    int         iconKind = 0;  // 0钥匙 1闪电 2服务器 3网络
};

// ═══════════════════════════════════════════════════════════
//  控件ID (扩展)
// ═══════════════════════════════════════════════════════════
// 顶部导航 (9900-9909)
#define IDC_NAV_DASHBOARD       9901
#define IDC_NAV_CARD_MGMT       9902
#define IDC_NAV_PLUGIN_CENTER   9903
#define IDC_NAV_SETTINGS        9904
#define IDC_NAV_FIREWALL       9905
#define IDC_LOG_SPLITTER        9906

// 仪表盘
#define IDC_DASH_REFRESH_BTN    2080
#define IDC_DASH_GENERATE_BTN   2003
#define IDC_DASH_ACTIVITY_LIST  2004

// 卡密管理 (5001-5999 保留原ID)
#define IDC_CARD_FILTER_BTN     5015
#define IDC_CARD_FILTER_ALL     5020
#define IDC_CARD_FILTER_ACTIVE  5021
#define IDC_CARD_FILTER_EXPIRED 5022
#define IDC_CARD_FILTER_DISABLED 5023
#define IDC_CARD_IMPORT_BTN     5011
#define IDC_CARD_EXPORT_BTN     5012
#define IDC_CARD_DELETE_BTN     5013
#define IDC_CARD_DETAIL_LOG     5014

// 插件中心（本地 plugins/ 目录扫描执行）
#define IDC_PLUGIN_REFRESH_BTN  6005
#define IDC_PLUGIN_EXEC_BTN     6006

// 日志
#define IDC_LOG_AUTOSCROLL_CHK  7002
#define IDC_LOG_CLEAR_BTN       7003
#define IDC_LOG_EXPORT_BTN      7004

// 设置
#define IDC_SETT_PROTO_HTTP     8001
#define IDC_SETT_PROTO_TCP      8002
#define IDC_SETT_EDIT_HOST      8003
#define IDC_SETT_EDIT_PORT      8004
#define IDC_SETT_EDIT_HMAC      8005
#define IDC_SETT_EDIT_AES       8006
#define IDC_SETT_COPY_AES       8007
#define IDC_SETT_GEN_AES        8008
#define IDC_SETT_EDIT_PSP       8009
#define IDC_SETT_COPY_PSP       8010
#define IDC_SETT_GEN_PSP        8011
#define IDC_SETT_PLUGIN_NOTE    8012
#define IDC_SETT_UPDATE_ENABLE  8020
#define IDC_SETT_UPDATE_TARGET  8021
#define IDC_SETT_UPDATE_HASH    8022
#define IDC_SETT_UPDATE_URL     8023
#define IDC_SETT_UPDATE_PKG_HASH 8024

// 内容区容器的 tab 面板
#define IDC_PANEL_DASHBOARD     9001
#define IDC_PANEL_CARDMGMT      9002
#define IDC_PANEL_PLUGIN        9003
#define IDC_PANEL_SETTINGS      9005
#define IDC_PANEL_FIREWALL      9007
#define IDC_PANEL_GLOBAL_LOG    9006

// 分割条
#define IDC_SPLITTER_CARDLOG    9501

// ═══════════════════════════════════════════════════════════
//  主窗口类
// ═══════════════════════════════════════════════════════════
class MainWindow {
public:
    MainWindow(HINSTANCE hInst);
    ~MainWindow();

    bool Create(int nCmdShow);
    void Run();

private:
    // 窗口过程
    static LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp);
    static LRESULT CALLBACK NavBtnProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp,
                                        UINT_PTR idSubclass, DWORD_PTR refData);
    static LRESULT CALLBACK DarkParentProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp,
                                            UINT_PTR idSubclass, DWORD_PTR refData);
    static LRESULT CALLBACK DarkHeaderProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp,
                                            UINT_PTR idSubclass, DWORD_PTR refData);

    // 消息处理
    LRESULT HandleMessage(UINT msg, WPARAM wp, LPARAM lp);
    void OnCreate();
    void OnSize(int width, int height);
    void OnCommand(WPARAM wp);
    LRESULT OnNotify(LPARAM lp);
    void OnPaint();
    void OnDrawItem(WPARAM wp, LPARAM lp);
    void OnDestroy();
    void OnTimer(WPARAM wp);

    // GDI+ 绘制
    void PaintTopNav(Gdiplus::Graphics& g);
    void PaintStatusBar(Gdiplus::Graphics& g);
    void DrawRoundedButton(Gdiplus::Graphics& g, const Gdiplus::RectF& rect,
                           const Gdiplus::Color& bg, const Gdiplus::Color& textColor,
                           const std::wstring& text, Gdiplus::Font& font,
                           float radius, bool drawBorder = false);

    // 创建UI
    void CreateTopNav();
    void CreateDashboardPanel();
    void CreateCardManagementPanel();
    void CreatePluginCenterPanel();
    void CreateGlobalLogPanel();
    void CreateSettingsPanel();
    void CreateFirewallPanel();
    void CreateStatusBar();
    void CreateCardDetailSplitter();
    void ApplyDarkTheme();

    // 布局
    void Layout();
    void LayoutDashboard();
    void LayoutCardManagement();
    void LayoutPluginCenter();
    void LayoutGlobalLog();
    void LayoutSettings();
    void LayoutFirewall();

    // 导航
    void NavigateTo(NavTab tab);
    void UpdateActiveNavButton();
    void ShowPanelForTab(NavTab tab);

    // 仪表盘
    void UpdateDashboardStats();

    // 卡密操作
    void RefreshCardList();
    void CopySelectedCards();
    void SelectAllCards();
    void DeselectAllCards();
    void UnbindSelectedCards();
    void EditSelectedCardRemark();
    void DeleteSelectedCards();
    void ShowCardGenerateDialog();
    void ShowCardImportDialog();
    void ShowCardDetail(int index);
    void SaveCards();
    void LoadCards();
    static std::string GenerateCardKey(const std::string& prefix = "");

    // 本地插件
    void ScanLocalPlugins();
    void ExecuteSelectedPlugin();
    void RefreshLocalPluginListUI();

    // 日志
    void Log(const std::string& text, COLORREF color = peanut_theme::TEXT_SECONDARY);
    void LogError(const std::string& text);
    void LogSuccess(const std::string& text);
    void LogWarning(const std::string& text);
    void ClearLog();
    void ExportLog();

    // 设置
    void LoadConfig();
    void SaveConfig();
    void ApplySettingsToUI();
    void UpdateKeyGenButtons();
    void SyncProtocolUi();  // 协议变更后同步主页卡片 + 底栏 + 单选
    static std::wstring ConfigIniPath();
    void PersistUiPrefsFromRuntime();
    void ApplyUiPrefsToRuntime();
    void CaptureWindowPlacement();
    void ReadSettingsFromUI();

    // 配置对话框
    void ShowAboutDialog();

    // 字体
    void CreateFonts();
    void ApplyFontToChildren(HWND parent, HFONT font);

    // 辅助
    void UpdateStatusBar();

    // ═══════════════════════════════════════════════════════
    //  成员变量
    // ═══════════════════════════════════════════════════════
    HINSTANCE   hInst_;
    HWND        hwndMain_               = nullptr;

    // 顶部导航
    HWND        hwndTopNav_             = nullptr;
    std::vector<NavButton> navButtons_;
    NavTab      activeTab_              = NavTab::Dashboard;

    // 内容区面板（不含日志；日志为全局底栏）
    HWND        hwndContentArea_        = nullptr;
    HWND        hwndPanelDashboard_     = nullptr;
    HWND        hwndPanelCardMgmt_      = nullptr;
    HWND        hwndPanelPlugin_        = nullptr;
    HWND        hwndPanelSettings_      = nullptr;
    HWND        hwndPanelFirewall_      = nullptr;

    // 全局日志底栏
    HWND        hwndPanelLogs_          = nullptr;
    HWND        hwndLogSplitter_        = nullptr;

    // 仪表盘
    std::vector<StatCard> statCards_;
    HWND        hwndDashActivityList_   = nullptr;
    HWND        hwndDashRefreshBtn_     = nullptr;
    HWND        hwndDashGenerateBtn_    = nullptr;
    HWND        hwndDashTitle_          = nullptr;
    HWND        hwndDashSummary_        = nullptr;
    HWND        hwndDashQuickPanel_     = nullptr;

    // 卡密管理
    HWND        hwndCardList_           = nullptr;
    HIMAGELIST  hwndCardStateImages_    = nullptr;
    HWND        hwndCardSearchEdit_     = nullptr;
    HWND        hwndCardSearchBtn_      = nullptr;
    HWND        hwndCardFilterBtn_      = nullptr;
    int         cardFilterIndex_        = 0;  // 0全部 1激活 2过期 3禁用
    HWND        hwndCardImportBtn_      = nullptr;
    HWND        hwndCardExportBtn_      = nullptr;
    HWND hwndCardDeleteBtn_   = nullptr;
    HWND hwndCardUnbindBtn_   = nullptr;
    HWND        hwndCardGenerateBtn_    = nullptr;
    HWND        hwndCardDetailLog_      = nullptr;
    HWND        hwndCardSplitter_       = nullptr;
    HWND        hwndCardTopLabel_       = nullptr;
    HWND        hwndCardBottomBtns_     = nullptr;

    // 插件中心
    HWND hwndPluginList_       = nullptr;
    HWND hwndPluginParamEdit_  = nullptr;
    HWND        hwndPluginRefreshBtn_   = nullptr;
    HWND        hwndPluginExecBtn_      = nullptr;
    HWND        hwndPluginTitle_        = nullptr;

    // 日志
    HWND        hwndLogEdit_            = nullptr;
    HWND        hwndLogAutoScrollChk_   = nullptr;
    HWND        hwndLogClearBtn_        = nullptr;
    HWND        hwndLogExportBtn_       = nullptr;
    HWND        hwndLogTitle_           = nullptr;

    // 设置
    HWND        hwndSettProtoHttp_      = nullptr;
    HWND        hwndSettProtoTcp_       = nullptr;
    HWND        hwndSettHostEdit_       = nullptr;
    HWND hwndSettPortEdit_  = nullptr;
    HWND hwndSettPermUnbind_ = nullptr;
    HWND hwndSettPermDayEdit_ = nullptr;
    HWND hwndSettPermMonEdit_ = nullptr;
    HWND hwndSettMultiOpen_   = nullptr;
    HWND hwndSettMaxOnlineEdit_ = nullptr;
    HWND hwndSettFwAttemptEdit_ = nullptr;
    HWND hwndSettFwWindowEdit_  = nullptr;
    HWND hwndSettFwBanEdit_    = nullptr;
    HWND        hwndFwIpList_          = nullptr;
    HWND        hwndFwRuleCard_         = nullptr;
    HWND        hwndFwTitle_            = nullptr;
    HWND        hwndFwListTitle_        = nullptr;
    HWND hwndSettHmacEdit_  = nullptr;
    HWND        hwndSettAesEdit_        = nullptr;
    HWND        hwndSettPspEdit_        = nullptr;
    HWND        hwndSettGenAes_         = nullptr;
    HWND        hwndSettGenPsp_         = nullptr;
    HWND        hwndSettGenAesNote_     = nullptr;
    HWND        hwndSettGenPspNote_     = nullptr;
    HWND        hwndSettGrpSrv_         = nullptr;
    HWND        hwndSettGrpPerm_        = nullptr;
    HWND        hwndSettGrpConc_        = nullptr;
    HWND        hwndSettPluginNote_     = nullptr;
    HWND hwndSettUpdateEnable_ = nullptr;
    HWND hwndSettUpdateTarget_ = nullptr;
    HWND hwndSettUpdateHash_ = nullptr;
    HWND hwndSettUpdateUrl_ = nullptr;
    HWND hwndSettUpdatePackageHash_ = nullptr;

    // 状态栏
    HWND        hwndStatusBar_          = nullptr;
    std::wstring statusParts_[4];
    bool        isConnected_            = false;
    int         protocolMode_           = 0;

    // 字体
    HFONT       hFontDefault_           = nullptr;
    HFONT       hFontLog_               = nullptr;
    HFONT       hFontTitle_             = nullptr;
    HFONT       hFontSidebar_           = nullptr;
    HFONT       hFontStatValue_         = nullptr;
    HFONT       hFontStatTitle_         = nullptr;
    HFONT       hFontLabel_             = nullptr;
    HFONT       hFontButton_            = nullptr;
    HFONT       hFontHeader_            = nullptr;  // 列表表头
    HFONT       hFontSectionTitle_      = nullptr;
    HFONT       hFontCardKey_           = nullptr;  // 卡密列等宽字体，保证视觉长度一致

    // GDI+
    ULONG_PTR   gdiplusToken_           = 0;

    // 画笔/画刷
    HBRUSH      hBrushBg_               = nullptr;
    HBRUSH      hBrushSidebar_          = nullptr;  // 顶栏/状态栏
    HBRUSH      hBrushLog_              = nullptr;
    HBRUSH      hBrushCard_             = nullptr;
    HBRUSH      hBrushInput_            = nullptr;
    HPEN        hPenBorder_             = nullptr;
    HPEN        hPenAccent_             = nullptr;

    // 数据
    AppConfig   config_;
    std::vector<CardEntry> cards_;
    std::mutex  cardsMutex_;
    struct ServerSession {
        std::string cardkey;
        std::string machine_code;
        time_t expires_at = 0;
        time_t last_heartbeat = 0;
        uintptr_t tcp_connection = 0;
    };
    std::map<std::string, ServerSession> serverSessions_;
    std::mutex serverSessionsMutex_;
    bool RegisterServerSession(const std::string& token,
                               const ServerSession& session,
                               std::string& rejection);
    // 本地插件信息
    struct LocalPlugin {
        std::string name;
        std::string description;
        std::string version;
        std::string filename;
        bool enabled = true;
        int function_count = 1;
        int call_count = 0;
        HMODULE module = nullptr;
        int (*exec)(const char*, int, int*, char**) = nullptr;
        void (*free)(char*) = nullptr;
        void (*destroy)() = nullptr;
    };
    std::vector<LocalPlugin> local_plugins_;
    std::unique_ptr<peanut::psp::Encoder> psp_encoder_;

    // 防火墙状态 (IP → 失败次数+时间窗口)
    struct FwEntry { int failures = 0; time_t windowStart = 0; time_t banUntil = 0; };
    std::map<std::string, FwEntry> firewall_;
    std::mutex firewallMutex_;
    // 卡密解绑追踪 (cardkey → {{date, unbind_count}, ...})
    struct UnbindRecord { std::string date; int count = 0; };
    std::map<std::string, std::vector<UnbindRecord>> unbindLog_;
    // HTTP 服务端
    std::shared_ptr<httplib::Server> httpServer_;
    uintptr_t tcpListenSocket_ = static_cast<uintptr_t>(~0ULL);
    std::atomic<bool> tcpServerRunning_{false};
    bool        serverRunning_ = false;
    void StartServer();
    void StopServer();
    bool CheckFirewall(const std::string& ip, std::string& out_msg);
    void RecordFirewallFail(const std::string& ip);
    bool CheckUnbindLimit(const std::string& cardkey, std::string& out_msg);
    void RecordUnbind(const std::string& cardkey);

    // 布局
    int         clientW_ = 1200, clientH_ = 800;
    static constexpr int TOP_NAV_H = 48;
    int         contentX_ = 0;
    int         contentY_ = TOP_NAV_H;
    int         contentW_ = 1200;
    int         contentH_ = 420;
    int         statusBarH_ = 28;
    int         globalLogH_ = 368;     // 全局日志（默认加高）
    int         splitterPos_ = 280;    // 卡密列表/详情分割位置
    int         splitterH_ = 6;
    bool        draggingSplitter_ = false;
    bool        draggingLogSplitter_ = false;
    int         dragStartY_ = 0;
    int         dragStartPos_ = 0;

    // 定时器
    static constexpr UINT_PTR TIMER_CLOCK = 1;
    bool        logAutoScroll_ = true;


};

// 全局实例指针
extern MainWindow* g_pMainWindow;
