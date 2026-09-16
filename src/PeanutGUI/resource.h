// ============================================================
// Peanut WLYZ — 资源定义
// ============================================================

#pragma once

// ── 控件ID ─────────────────────────────────────────────────
#define IDC_STATIC               -1

// 菜单
#define IDM_FILE_EXIT            1001
#define IDM_FILE_SETTINGS        1002
#define IDM_CARD_GENERATE        2001
#define IDM_CARD_IMPORT          2002
#define IDM_CARD_EXPORT          2003
#define IDM_CARD_DELETE          2004
#define IDM_PLUGIN_MANAGE        3001
#define IDM_PLUGIN_RELOAD        3002
#define IDM_PLUGIN_START        3101      // 动态菜单起始
#define IDM_PLUGIN_END          3200      // 动态菜单结束
#define IDM_HELP_ABOUT           4001

// 工具栏
#define IDB_REFRESH              4101
#define IDB_CLEAR_LOG            4102
#define IDB_START_SERVER         4103
#define IDB_STOP_SERVER          4104

// 卡密列表
#define IDC_CARD_LIST            5001
#define IDC_CARD_COPY_SELECTED   5002
#define IDC_CARD_SELECT_ALL      5003
#define IDC_CARD_DESELECT_ALL    5004
#define IDC_CARD_SEARCH          5005
#define IDC_BTN_SEARCH           5006
#define IDC_CARD_UNBIND_BTN      5007
#define IDC_CARD_REMARK_BTN      5008

// 插件列表
#define IDC_PLUGIN_LIST          6001
#define IDC_PLUGIN_PARAM_EDIT    6002

// 日志
#define IDC_LOG_EDIT             7001

// 设置对话框
#define IDD_SETTINGS             100
#define IDC_EDIT_HOST            101
#define IDC_EDIT_PORT            102
#define IDC_EDIT_HMAC_KEY        103
#define IDC_EDIT_AES_KEY         104
#define IDC_BTN_COPY_AES         105
#define IDC_BTN_GEN_AES          106
#define IDC_EDIT_PSP_KEY         107
#define IDC_BTN_COPY_PSP         108
#define IDC_BTN_GEN_PSP          109
#define IDC_BTN_SAVE             110
#define IDC_BTN_CANCEL           111
#define IDC_EDIT_PLUGIN_DIR      112
#define IDC_BTN_BROWSE_PLUGIN    113

// 关于对话框
#define IDD_ABOUT                200

// 状态栏
#define IDC_STATUS_BAR           9801

// 分割条
#define IDC_SPLITTER             9802

// 设置 - 卡密权限
#define IDC_SETT_UNBIND_ENABLE   9601
#define IDC_SETT_UNBIND_DAY      9602
#define IDC_SETT_UNBIND_MONTH    9603
// 设置 - 防火墙
#define IDC_SETT_FW_ATTEMPTS      9604
#define IDC_SETT_FW_WINDOW        9605
#define IDC_SETT_FW_BAN           9606
// 设置 - 在线并发
#define IDC_SETT_MULTI_OPEN       9607
#define IDC_SETT_MAX_ONLINE       9608
