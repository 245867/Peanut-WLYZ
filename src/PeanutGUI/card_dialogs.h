// ============================================================
// Peanut WLYZ — 卡密生成/导入对话框  v7.0
// 独立窗口封装
// ============================================================

#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <string>

class MainWindow;

struct GenDlgData {
    MainWindow* self = nullptr;
    int count = 10;
    int durType = 0;   // 0天 1小时 2月 3年 4永久
    int durValue = 30;
    std::string prefix;
    std::string remark;
    bool ok = false;
    HBRUSH brBg = nullptr;
    HBRUSH brInput = nullptr;
    HFONT font = nullptr;
};

struct ImpDlgData {
    MainWindow* self = nullptr;
    std::string text;
    bool ok = false;
    HBRUSH brBg = nullptr;
    HBRUSH brInput = nullptr;
    HFONT font = nullptr;
};

INT_PTR ShowCardGenDialogBox(HWND parent, GenDlgData* data);

// ShowCardImportDialog is a MainWindow member; declared in main_window.h
