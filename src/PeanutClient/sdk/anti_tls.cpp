// ============================================================
// Peanut WLYZ SDK — TLS Callback 入口守卫 实现
// ============================================================

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <winternl.h>
#include <intrin.h>
#include "anti_tls.h"

#if defined(PEANUT_RELEASE) || defined(VM_PROTECT_ACTIVE)

#pragma comment(linker, "/INCLUDE:_tls_used")

typedef NTSTATUS (NTAPI *pNtQI_t)(HANDLE, ULONG, PVOID, ULONG, PULONG);
typedef NTSTATUS (NTAPI *pNtQSIS_t)(ULONG, PVOID, ULONG, PULONG);

static FARPROC GetNtFunc(const char* name) {
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (!ntdll) return nullptr;
    return GetProcAddress(ntdll, name);
}

static int IsDebuggerPresentByPEB() {
#ifdef _WIN64
    BYTE b = *((BYTE*)__readgsqword(0x60) + 2);
    return b != 0;
#else
    BYTE b = 0;
    __asm {
        mov eax, fs:[30h]
        movzx eax, byte ptr [eax + 2]
        mov b, al
    }
    return b != 0;
#endif
}

static int HasDebugPort() {
    auto fn = reinterpret_cast<pNtQI_t>(GetNtFunc("NtQueryInformationProcess"));
    if (!fn) return 0;
    DWORD64 port = 0;
    NTSTATUS st = fn(GetCurrentProcess(), 7,
                     &port, sizeof(port), nullptr);
    return (st >= 0 && port != 0);
}

static int HasDebugObject() {
    auto fn = reinterpret_cast<pNtQI_t>(GetNtFunc("NtQueryInformationProcess"));
    if (!fn) return 0;
    HANDLE h = nullptr;
    NTSTATUS st = fn(GetCurrentProcess(), 30,
                     &h, sizeof(h), nullptr);
    return (st >= 0 && h != nullptr);
}

static int HasKernelDebugger() {
    auto fn = reinterpret_cast<pNtQSIS_t>(GetNtFunc("NtQuerySystemInformation"));
    if (!fn) return 0;
    struct { BOOLEAN enabled; BOOLEAN not_present; } info = {};
    NTSTATUS st = fn(35, &info, sizeof(info), nullptr);
    return (st >= 0 && info.enabled);
}

static int HasNtGlobalFlag() {
#ifdef _WIN64
    DWORD flags = *((DWORD*)(__readgsqword(0x60) + 0xBC));
    return (flags & 0x70) != 0;
#else
    DWORD flags = 0;
    __asm {
        mov eax, fs:[30h]
        mov eax, [eax + 0x68]
        mov flags, eax
    }
    return (flags & 0x70) != 0;
#endif
}

// 原 CloseHandle(0xDEADC0DE) 陷阱检测已移除：它假设"无调试器时 Win32 会抛
// EXCEPTION_INVALID_HANDLE"，但现代 Windows 上无论有没有调试器，CloseHandle
// 对无效句柄都只返回 FALSE 而不抛异常，该检测恒定命中，导致进程在 TLS 回调
// 阶段就被误杀 (0xDEAD)。改用 ProcessDebugFlags，可靠且不依赖异常分发。
static int HasDebugFlags() {
    auto fn = reinterpret_cast<pNtQI_t>(GetNtFunc("NtQueryInformationProcess"));
    if (!fn) return 0;
    ULONG flags = 1;
    NTSTATUS st = fn(GetCurrentProcess(), 31,
                     &flags, sizeof(flags), nullptr);
    return (st >= 0 && flags == 0);
}

bool EarlyStartupCheck() {
    int score = 0;
    score += IsDebuggerPresentByPEB() ? 1 : 0;
    score += HasNtGlobalFlag()       ? 2 : 0;
    score += HasDebugPort()          ? 2 : 0;
    score += HasDebugObject()        ? 2 : 0;
    score += HasKernelDebugger()     ? 3 : 0;
    score += HasDebugFlags()         ? 2 : 0;
    return score < 5;
}
#pragma section(".CRT$XLY", long, read)

extern "C" void __stdcall TlsAntiDebugCallback(PVOID, DWORD reason, PVOID) {
    if (reason == DLL_PROCESS_ATTACH) {
        if (!EarlyStartupCheck()) {
            TerminateProcess(GetCurrentProcess(), 0xDEAD);
        }
        auto fn = reinterpret_cast<NTSTATUS(NTAPI*)(HANDLE,ULONG,PVOID,ULONG)>(
            GetNtFunc("NtSetInformationProcess"));
        if (fn) {
            fn(GetCurrentProcess(), 30, nullptr, 0);
        }
    }
}

__declspec(allocate(".CRT$XLY"))
PIMAGE_TLS_CALLBACK g_tls_callback_anti = TlsAntiDebugCallback;

#endif
