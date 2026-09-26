// ============================================================
// Peanut WLYZ — 程序入口
// 原生Win32应用, 替代Qt的QApplication
// ============================================================

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <commctrl.h>
#include <crtdbg.h>

#include "main_window.h"
#include "../PeanutClient/sdk/anti_debug.h"

// 诊断内存泄露 (Debug模式)
#ifdef _DEBUG
#define _CRTDBG_MAP_ALLOC
#endif

int APIENTRY wWinMain(_In_ HINSTANCE hInstance,
                       _In_opt_ HINSTANCE hPrevInstance,
                       _In_ LPWSTR    lpCmdLine,
                       _In_ int       nCmdShow)
{
    UNREFERENCED_PARAMETER(hPrevInstance);

    // ── 选择界面皮肤 ─────────────────────────────────────────
    // 优先级: 命令行 --skin=N  >  环境变量 PEANUT_SKIN  >  默认 1
    //   1 = 极夜霓虹   2 = 晨曦白   3 = 熔岩黑
    {
        int skinId = peanut::ui::UiSkin_ParseCommandLine(lpCmdLine);
        if (skinId <= 0) skinId = peanut::ui::UiSkin_ParseEnv();
        if (skinId <= 0) skinId = 1;
        peanut::ui::UiSkin_Load(skinId);
    }

    // Layer 0: 反调试入口守卫 (SDK, Release-only)
    peanut::security::antidebug::StartupGuard();

    wchar_t modulePath[MAX_PATH] = {};
    if (GetModuleFileNameW(nullptr, modulePath, MAX_PATH)) {
        wchar_t* slash = wcsrchr(modulePath, L'\\');
        if (slash) { *slash = L'\0'; SetCurrentDirectoryW(modulePath); }
    }

    // 启用内存泄露检测 (Debug)
    _CrtSetDbgFlag(_CRTDBG_ALLOC_MEM_DF | _CRTDBG_LEAK_CHECK_DF);

    // 初始化公共控件
    INITCOMMONCONTROLSEX icex = {};
    icex.dwSize = sizeof(icex);
    icex.dwICC = ICC_LISTVIEW_CLASSES | ICC_BAR_CLASSES | ICC_STANDARD_CLASSES;
    InitCommonControlsEx(&icex);

    // 创建主窗口
    MainWindow app(hInstance);
    if (!app.Create(nCmdShow)) {
        MessageBoxW(nullptr, L"窗口创建失败", L"错误", MB_OK | MB_ICONERROR);
        return 1;
    }

    // 消息循环
    app.Run();

    return 0;
}
