// ============================================================
// Peanut WLYZ SDK — 注册表检测 实现
// ============================================================

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <stdio.h>
#include "anti_registry.h"

#if defined(PEANUT_RELEASE) || defined(VM_PROTECT_ACTIVE)

namespace peanut { namespace security { namespace registry {

// 获取当前 exe 文件名 (不含路径)
static bool GetExeBaseName(wchar_t* out, DWORD outLen) {
    wchar_t full[MAX_PATH] = {};
    DWORD len = GetModuleFileNameW(nullptr, full, MAX_PATH);
    if (len == 0 || len >= MAX_PATH) return false;

    // 找最后一个 '\' 或 '/'
    wchar_t* base = full + len;
    while (base > full && base[-1] != L'\\' && base[-1] != L'/')
        --base;

    wcsncpy_s(out, outLen, base, _TRUNCATE);
    return true;
}

bool DetectIfeoDebugger() {
    wchar_t exeName[MAX_PATH] = {};
    if (!GetExeBaseName(exeName, MAX_PATH)) return false;

    // 构造 IFEO 路径: HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\<exe>
    wchar_t path[512] = {};
    swprintf_s(path, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\"
                L"Image File Execution Options\\%s", exeName);

    HKEY hk = nullptr;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, path, 0, KEY_READ, &hk) != ERROR_SUCCESS) {
        // 没有 IFEO 键 → 安全
        return false;
    }

    // 检查 Debugger 值
    wchar_t debugger[512] = {};
    DWORD size = sizeof(debugger);
    DWORD type = 0;
    if (RegQueryValueExW(hk, L"Debugger", nullptr, &type,
        reinterpret_cast<LPBYTE>(debugger), &size) == ERROR_SUCCESS) {
        if (type == REG_SZ || type == REG_EXPAND_SZ) {
            if (wcslen(debugger) > 0) {
                RegCloseKey(hk);
                return true;  // ⚠️ Debugger 字段非空
            }
        }
    }

    // 检查 GlobalFlag (如果 != 0 → 可能有调试器)
    DWORD globalFlag = 0;
    size = sizeof(globalFlag);
    if (RegQueryValueExW(hk, L"GlobalFlag", nullptr, nullptr,
        reinterpret_cast<LPBYTE>(&globalFlag), &size) == ERROR_SUCCESS) {
        if (globalFlag != 0) {
            RegCloseKey(hk);
            return true;  // ⚠️ GlobalFlag 非零 → 调试配置
        }
    }

    // 检查 MitigationOptions (如果存在 → 调试环境)
    DWORD mitigationOptions = 0;
    size = sizeof(mitigationOptions);
    if (RegQueryValueExW(hk, L"MitigationOptions", nullptr, nullptr,
        reinterpret_cast<LPBYTE>(&mitigationOptions), &size) == ERROR_SUCCESS) {
        if (mitigationOptions != 0) {
            RegCloseKey(hk);
            return true;
        }
    }

    RegCloseKey(hk);
    return false;
}

bool DetectAeDebug() {
    HKEY hk = nullptr;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\AeDebug",
        0, KEY_READ, &hk) != ERROR_SUCCESS) {
        return false;  // 没有 AeDebug 键 → 安全
    }

    // 检查 Auto 值: 1 = 自动启动调试器
    DWORD autoVal = 0;
    DWORD size = sizeof(autoVal);
    if (RegQueryValueExW(hk, L"Auto", nullptr, nullptr,
        reinterpret_cast<LPBYTE>(&autoVal), &size) == ERROR_SUCCESS) {
        if (autoVal == 1) {
            RegCloseKey(hk);
            return true;  // ⚠️ AeDebug 设为自动
        }
    }

    // 检查 Debugger 值: 非默认就可能是被改了
    // 默认值通常是: "drwtsn32.exe -p %ld -e %ld -g"
    // 或 vsjitdebugger.exe, windbg.exe 等
    wchar_t default_debugger[] = L"drwtsn32.exe";
    wchar_t debugger[512] = {};
    size = sizeof(debugger);
    DWORD type = 0;
    if (RegQueryValueExW(hk, L"Debugger", nullptr, &type,
        reinterpret_cast<LPBYTE>(debugger), &size) == ERROR_SUCCESS &&
        type == REG_SZ) {
        // 如果不包含默认调试器名 → 被替换为其他调试器
        if (wcslen(debugger) > 0) {
            // 全转小写比较
            wchar_t lower[512] = {};
            wcsncpy_s(lower, debugger, _TRUNCATE);
            for (auto& c : lower) {
                if (c) c = towlower(c);
            }
            for (auto& c : default_debugger) {
                if (c) c = towlower(c);
            }

            bool isDefault = (wcsstr(lower, default_debugger) != nullptr);
            // 也检查常见默认值
            isDefault = isDefault || (wcsstr(lower, L"vsjitdebugger.exe") != nullptr);

            RegCloseKey(hk);
            return !isDefault;
        }
    }

    RegCloseKey(hk);
    return false;
}

bool DetectRegistryTampering() {
    return DetectIfeoDebugger() || DetectAeDebug();
}

}}} // namespace

#endif
