// ============================================================
// Peanut WLYZ SDK — 沙箱检测 实现
// ============================================================

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <stdio.h>
#include <psapi.h>
#include <intrin.h>
#include "anti_sandbox.h"

#if defined(PEANUT_RELEASE) || defined(VM_PROTECT_ACTIVE)

#pragma comment(lib, "psapi.lib")

namespace peanut { namespace security { namespace sandbox {

static bool Detect_UptimeTooShort() {
    return (GetTickCount64() < 600000);
}

static bool Detect_LowResolution() {
    int w = GetSystemMetrics(SM_CXSCREEN);
    int h = GetSystemMetrics(SM_CYSCREEN);
    return (w < 1024 || h < 768);
}

static bool Detect_LowMemory() {
    MEMORYSTATUSEX mem = { sizeof(mem) };
    if (GlobalMemoryStatusEx(&mem)) return (mem.ullTotalPhys < 2ULL * 1024 * 1024 * 1024);
    return false;
}

static bool Detect_SingleCpu() {
    SYSTEM_INFO si = {}; GetSystemInfo(&si);
    return (si.dwNumberOfProcessors <= 1);
}

static bool Detect_LowDiskSpace() {
    ULARGE_INTEGER total = {};
    if (GetDiskFreeSpaceExW(L"C:\\", nullptr, &total, nullptr)) return (total.QuadPart < 40ULL * 1024 * 1024 * 1024);
    return false;
}

static int g_mouseMoveCount = 0;
static ULONGLONG g_mouseMonitorStart = 0;

static void InitMouseMonitor() {
    g_mouseMonitorStart = GetTickCount64();
    g_mouseMoveCount = 0;
}

static bool Detect_NoMouseActivity() {
    static POINT lastPos = {};
    POINT curPos = {};
    if (GetCursorPos(&curPos)) {
        if (curPos.x != lastPos.x || curPos.y != lastPos.y) {
            ++g_mouseMoveCount;
            lastPos = curPos;
        }
    }
    ULONGLONG elapsed = GetTickCount64() - g_mouseMonitorStart;
    if (elapsed > 300000) return (g_mouseMoveCount < 3);
    return false;
}

static bool Detect_LowProcessCount() {
    DWORD pids[1024] = {}; DWORD needed = 0;
    if (EnumProcesses(pids, sizeof(pids), &needed)) {
        DWORD count = needed / sizeof(DWORD);
        return (count < 30);
    }
    return false;
}

static bool Detect_NoDesktopApps() {
    static const wchar_t* kDesktopIndicators[] = {
        L"chrome.exe", L"firefox.exe", L"msedge.exe",
        L"explorer.exe", L"dwm.exe", L"sihost.exe", L"taskhostw.exe"
    };
    const int numIndicators = sizeof(kDesktopIndicators) / sizeof(kDesktopIndicators[0]);
    int foundCount = 0;
    DWORD pids[1024] = {}; DWORD needed = 0;
    if (!EnumProcesses(pids, sizeof(pids), &needed)) return false;
    DWORD count = needed / sizeof(DWORD);
    for (DWORD i = 0; i < count && i < 1024; ++i) {
        if (pids[i] == 0) continue;
        HANDLE hp = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pids[i]);
        if (!hp) continue;
        wchar_t name[MAX_PATH] = {}; DWORD sz = MAX_PATH;
        if (QueryFullProcessImageNameW(hp, 0, name, &sz)) {
            wchar_t* base = name + sz;
            while (base > name && base[-1] != L'\\' && base[-1] != L'/') --base;
            for (wchar_t* cp = base; *cp; ++cp) *cp = towlower(*cp);
            for (int di = 0; di < numIndicators; ++di) {
                wchar_t cmp[64] = {};
                wcsncpy_s(cmp, kDesktopIndicators[di], _TRUNCATE);
                for (wchar_t* cp2 = cmp; *cp2; ++cp2) *cp2 = towlower(*cp2);
                if (wcscmp(base, cmp) == 0) { ++foundCount; break; }
            }
        }
        CloseHandle(hp);
    }
    return (foundCount < 4);
}

void InitSandboxDetection() { InitMouseMonitor(); }

bool DetectSandboxQuick() {
    int score = 0;
    score += Detect_LowResolution()    ? 2 : 0;
    score += Detect_LowMemory()        ? 1 : 0;
    score += Detect_SingleCpu()        ? 2 : 0;
    score += Detect_LowDiskSpace()     ? 1 : 0;
    score += Detect_LowProcessCount()  ? 1 : 0;
    score += Detect_NoDesktopApps()    ? 1 : 0;
    return score >= 4;
}

bool DetectSandboxSlow() {
    int score = 0;
    score += Detect_LowResolution()     ? 2 : 0;
    score += Detect_LowMemory()         ? 1 : 0;
    score += Detect_SingleCpu()         ? 2 : 0;
    score += Detect_LowDiskSpace()      ? 1 : 0;
    score += Detect_LowProcessCount()   ? 1 : 0;
    score += Detect_NoDesktopApps()     ? 1 : 0;
    score += Detect_UptimeTooShort()    ? 1 : 0;
    score += Detect_NoMouseActivity()   ? 2 : 0;
    return score >= 5;
}

bool DetectSandbox() { return DetectSandboxQuick() || DetectSandboxSlow(); }

}}} // namespace

#endif
