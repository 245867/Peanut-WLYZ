// ============================================================
// Peanut WLYZ SDK — 反调试实现
//
// 四层纵深防御:
//   L0 入口守卫: PEB / DebugPort / NtGlobalFlag / 父进程 / KernelDebugger
//   L1 运行时:   watchdog 线程 (HW BP / INT3 / DLL枚举 / RDTSC计时)
//   L2 API守卫:  轻量 QuickCheck (PEB + 时间)
//   L3 加密守卫:  全局安全标志 (IsSafe/MarkCompromised)
// ============================================================

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <psapi.h>
#include <tlhelp32.h>
#include <intrin.h>
#include <winternl.h>
#include <algorithm>

#include "anti_debug.h"
#include "anti_pe.h"
#include "anti_memory.h"
#include "anti_stack.h"
#include "anti_registry.h"
#include "anti_veh.h"
#include "anti_sandbox.h"
#include "anti_flow.h"
#include "anti_iat.h"
#include "../vmprotect_markers.h"

#pragma comment(lib, "psapi.lib")

namespace peanut { namespace security { namespace antidebug {

// ═══════════════════════════════════════════════════════════
//  内部: NT API 动态链接 (避免 IAT 暴露)
// ═══════════════════════════════════════════════════════════

typedef NTSTATUS (NTAPI *pNtQueryInformationProcess_t)(
    HANDLE, ULONG, PVOID, ULONG, PULONG);
typedef NTSTATUS (NTAPI *pNtQuerySystemInformation_t)(
    ULONG, PVOID, ULONG, PULONG);
typedef NTSTATUS (NTAPI *pNtSetInformationProcess_t)(
    HANDLE, ULONG, PVOID, ULONG);
typedef NTSTATUS (NTAPI *pNtClose_t)(HANDLE);

static pNtQueryInformationProcess_t g_NtQueryInformationProcess = nullptr;
static pNtQuerySystemInformation_t g_NtQuerySystemInformation   = nullptr;
static pNtSetInformationProcess_t  g_NtSetInformationProcess     = nullptr;

enum {
    ProcessDebugPort           = 7,
    ProcessDebugObjectHandle   = 30,
    ProcessDebugFlags          = 31,
    SystemKernelDebuggerInformation = 35,
};

struct SYSTEM_KERNEL_DEBUGGER_INFORMATION {
    BOOLEAN KernelDebuggerEnabled;
    BOOLEAN KernelDebuggerNotPresent;
};

static void InitNtFunctions() {
    static bool done = false;
    if (done) return;
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (ntdll) {
        g_NtQueryInformationProcess = reinterpret_cast<pNtQueryInformationProcess_t>(
            GetProcAddress(ntdll, "NtQueryInformationProcess"));
        g_NtQuerySystemInformation  = reinterpret_cast<pNtQuerySystemInformation_t>(
            GetProcAddress(ntdll, "NtQuerySystemInformation"));
        g_NtSetInformationProcess   = reinterpret_cast<pNtSetInformationProcess_t>(
            GetProcAddress(ntdll, "NtSetInformationProcess"));
    }
    done = true;
}

// ═══════════════════════════════════════════════════════════
//  内部: 编译期 XOR 字符串混淆
// ═══════════════════════════════════════════════════════════

template<size_t N>
struct XorStr {
    char data[N];
    constexpr XorStr(const char (&s)[N]) : data{} {
        for (size_t i = 0; i < N; ++i) data[i] = s[i] ^ 0x5A;
    }
    std::string decode() const {
        std::string r(data, N - 1);
        for (auto& c : r) c ^= 0x5A;
        return r;
    }
};

// ═══════════════════════════════════════════════════════════
//  内部: 全局状态
// ═══════════════════════════════════════════════════════════

static std::atomic<bool> g_safe{true};
static std::atomic<bool> g_watchdog_running{false};
static HANDLE g_watchdog_thread = nullptr;
static DWORD g_watchdog_tid = 0;

#define SCORE_THRESHOLD 5

// ═══════════════════════════════════════════════════════════
//  L0 检测项
// ═══════════════════════════════════════════════════════════

// 1. PEB.BeingDebugged (内联汇编/intrinsic 绕过 hook)
static bool Detect_PEB_BeingDebugged() {
#ifdef _WIN64
    // x64: PEB at gs:[60h], BeingDebugged at offset 2
    // MSVC x64 不支持 __asm, 用 __readgsbyte intrinsic
    BYTE beingDebugged = *reinterpret_cast<BYTE*>(__readgsqword(0x60) + 2);
    return beingDebugged != 0;
#else
    BYTE beingDebugged = 0;
    __asm {
        mov eax, fs:[30h]
        movzx eax, byte ptr [eax + 2]
        mov beingDebugged, al
    }
    return beingDebugged != 0;
#endif
}

// 2. PEB.NtGlobalFlag (0x70 = 调试标志)
static bool Detect_NtGlobalFlag() {
#ifdef _WIN64
    // x64: PEB.NtGlobalFlag at PEB+0xBC
    DWORD flags = *reinterpret_cast<DWORD*>(__readgsqword(0x60) + 0xBC);
    return (flags & 0x70) != 0;
#else
    DWORD flags = 0;
    __asm {
        mov eax, fs:[30h]
        mov eax, [eax + 0x68]   // PEB.NtGlobalFlag offset in x86
        mov flags, eax
    }
    return (flags & 0x70) != 0;
#endif
}

// 3. DebugPort
static bool Detect_DebugPort() {
    if (!g_NtQueryInformationProcess) return false;
    DWORD64 port = 0;
    NTSTATUS st = g_NtQueryInformationProcess(
        GetCurrentProcess(), ProcessDebugPort, &port, sizeof(port), nullptr);
    return NT_SUCCESS(st) && port != 0;
}

// 4. DebugObjectHandle
static bool Detect_DebugObjectHandle() {
    if (!g_NtQueryInformationProcess) return false;
    HANDLE handle = nullptr;
    NTSTATUS st = g_NtQueryInformationProcess(
        GetCurrentProcess(), ProcessDebugObjectHandle, &handle, sizeof(handle), nullptr);
    return NT_SUCCESS(st) && handle != nullptr;
}

// 5. KernelDebugger
static bool Detect_KernelDebugger() {
    if (!g_NtQuerySystemInformation) return false;
    SYSTEM_KERNEL_DEBUGGER_INFORMATION info = {};
    NTSTATUS st = g_NtQuerySystemInformation(
        SystemKernelDebuggerInformation, &info, sizeof(info), nullptr);
    return NT_SUCCESS(st) && info.KernelDebuggerEnabled;
}

// 6. ProcessDebugFlags (NoDebugInherit)
//
// 原先这里用 CloseHandle(0xDEADC0DE) 是否抛 EXCEPTION_INVALID_HANDLE 来
// 判断"调试器是否吞掉了异常"。这个前提在现代 Windows 上不成立：即便没有
// 调试器，CloseHandle 对无效句柄也只返回 FALSE、不抛异常，于是该检测恒定
// 判为"有调试器"，属于稳定误报，已移除。
//
// 改用 NtQueryInformationProcess(ProcessDebugFlags)：返回的 flags 为 0
// 表示进程正处于被调试状态，这是可靠且不依赖异常分发的判定。
static bool Detect_DebugFlags() {
    if (!g_NtQueryInformationProcess) return false;
    ULONG flags = 1;
    NTSTATUS st = g_NtQueryInformationProcess(
        GetCurrentProcess(),
        static_cast<ULONG>(ProcessDebugFlags),
        &flags, sizeof(flags), nullptr);
    return NT_SUCCESS(st) && flags == 0;
}

// 7. 父进程检测
static bool Detect_SuspiciousParent() {
    DWORD myPid = GetCurrentProcessId();
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return false;

    PROCESSENTRY32W pe = { sizeof(pe) };
    DWORD parentPid = 0;
    if (Process32FirstW(hSnap, &pe)) {
        do {
            if (pe.th32ProcessID == myPid) {
                parentPid = pe.th32ParentProcessID;
                break;
            }
        } while (Process32NextW(hSnap, &pe));
    }
    CloseHandle(hSnap);

    if (parentPid == 0) return false;

    // 获取父进程名
    wchar_t parentName[MAX_PATH] = {};
    HANDLE hParent = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, parentPid);
    bool suspicious = true;
    if (hParent) {
        DWORD size = MAX_PATH;
        if (QueryFullProcessImageNameW(hParent, 0, parentName, &size)) {
            // explorer.exe / cmd.exe / powershell.exe 是正常启动方式
            std::wstring name = parentName;
            for (auto& c : name) c = towlower(c);
            if (name.find(L"\\explorer.exe") != std::wstring::npos ||
                name.find(L"\\cmd.exe") != std::wstring::npos ||
                name.find(L"\\pwsh.exe") != std::wstring::npos ||
                name.find(L"\\powershell.exe") != std::wstring::npos ||
                name.find(L"\\devenv.exe") != std::wstring::npos) {
                suspicious = false;
            }
        }
        CloseHandle(hParent);
    }
    return suspicious;
}

// ═══════════════════════════════════════════════════════════
//  L1 检测项
// ═══════════════════════════════════════════════════════════

// 8. 硬件断点 (DR0~DR3)
static bool Detect_HardwareBreakpoints() {
    CONTEXT ctx = {};
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    // GetThreadContext 获取当前线程的调试寄存器
    HANDLE hThread = GetCurrentThread();
    if (GetThreadContext(hThread, &ctx)) {
        return (ctx.Dr0 != 0) || (ctx.Dr1 != 0) ||
               (ctx.Dr2 != 0) || (ctx.Dr3 != 0);
    }
    return false;
}

// 9. 软件断点扫描 (0xCC / INT3)
//
// 注意: 不能直接统计 .text 里 0xCC 的绝对数量。MSVC 会用 0xCC (INT3)
// 做函数间的对齐填充，一个正常的 Release 二进制在 .text 开头 4KB 里
// 就有上百个 0xCC，按数量阈值判断必然误报。
//
// 正确做法是拿内存中的 .text 和磁盘上的原始 .text 逐字节对比，
// 只统计"磁盘上不是 0xCC、内存里却变成 0xCC"的位置 —— 这才是
// 调试器下断点或 inline patch 留下的痕迹。磁盘镜像读不到时按
// 无法判断处理，不误杀。
static bool Detect_Int3Patches() {
    HMODULE base = GetModuleHandleW(nullptr);
    if (!base) return false;

    auto* dos = reinterpret_cast<PIMAGE_DOS_HEADER>(base);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;
    auto* nt = reinterpret_cast<PIMAGE_NT_HEADERS>(
        reinterpret_cast<BYTE*>(base) + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return false;

    DWORD textRva = 0, textSize = 0;
    DWORD textRaw = 0, textRawSize = 0;
    auto* section = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
        if (memcmp(section[i].Name, ".text", 5) == 0) {
            textRva     = section[i].VirtualAddress;
            textSize    = section[i].Misc.VirtualSize;
            textRaw     = section[i].PointerToRawData;
            textRawSize = section[i].SizeOfRawData;
            break;
        }
    }
    if (textRva == 0 || textSize == 0 || textRaw == 0 || textRawSize == 0)
        return false;

    // 读取磁盘上的原始 .text 作为基准
    wchar_t path[MAX_PATH] = {};
    if (!GetModuleFileNameW(nullptr, path, MAX_PATH)) return false;

    HANDLE hFile = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, nullptr,
                               OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) return false;

    DWORD compareSize = (textSize < textRawSize) ? textSize : textRawSize;
    // 只比对前 64KB，足够覆盖入口区域且避免整段读取的开销
    const DWORD kScanLimit = 64 * 1024;
    if (compareSize > kScanLimit) compareSize = kScanLimit;

    std::vector<BYTE> diskText(compareSize);
    LARGE_INTEGER off = {};
    off.QuadPart = textRaw;
    if (!SetFilePointerEx(hFile, off, nullptr, FILE_BEGIN)) {
        CloseHandle(hFile);
        return false;
    }
    DWORD read = 0;
    BOOL ok = ReadFile(hFile, diskText.data(), compareSize, &read, nullptr);
    CloseHandle(hFile);
    if (!ok || read != compareSize) return false;

    BYTE* memText = reinterpret_cast<BYTE*>(base) + textRva;
    int injectedInt3 = 0;
    for (DWORD i = 0; i < compareSize; ++i) {
        // 只认"磁盘非 0xCC、内存变 0xCC"的字节，填充和对齐不受影响
        if (memText[i] == 0xCC && diskText[i] != 0xCC) {
            ++injectedInt3;
        }
    }
    // 正常情况下为 0；出现单个被改写点即高度可疑
    return injectedInt3 > 0;
}


// 10. 可疑 DLL 检测
static bool Detect_SuspiciousDlls() {
    static const wchar_t* kBadDlls[] = {
        L"frida-agent",      // Frida
        L"scylla_hide",       // ScyllaHide
        L"titanhide",         // TitanHide
        L"hyperdbg",          // HyperDbg
        L"x64dbg",            // x64dbg 注入
        L"cheatengine",       // Cheat Engine
        L"speedhack",         // Cheat Engine speedhack
        L"kernel32.ollydbg",  // OllyDbg 注入
    };
    constexpr int kBadCount = sizeof(kBadDlls) / sizeof(kBadDlls[0]);

    HMODULE mods[256] = {};
    DWORD needed = 0;
    HANDLE hProc = GetCurrentProcess();
    if (!EnumProcessModules(hProc, mods, sizeof(mods), &needed))
        return false;

    int modCount = ((static_cast<int>(needed / sizeof(HMODULE))) < (256) ? (static_cast<int>(needed / sizeof(HMODULE))) : (256));
    wchar_t name[MAX_PATH];

    for (int i = 0; i < modCount; ++i) {
        if (GetModuleBaseNameW(hProc, mods[i], name, MAX_PATH)) {
            for (auto& c : std::wstring(name)) c = towlower(c);
            for (int j = 0; j < kBadCount; ++j) {
                std::wstring bad = kBadDlls[j];
                for (auto& c : bad) c = towlower(c);
                if (wcsstr(name, bad.c_str())) return true;
            }
        }
    }
    return false;
}

// 11. RDTSC 时间偏差检测
static bool Detect_TimingAnomaly() {
    // 连续两次 RDTSC，差值 > 500ms (以3GHz计 ≈ 1.5B 周期) → 被暂停过(单步)
    uint64_t t1 = __rdtsc();
    uint64_t t2 = __rdtsc();
    uint64_t diff = t2 - t1;

    // 正常两次连续的 RDTSC 差 < 1000 周期
    // 如果 > 500000 周期 → 可疑 (单步执行会让时间膨胀)
    constexpr uint64_t kMaxNormalCycles = 500000;
    return diff > kMaxNormalCycles;
}

// ═══════════════════════════════════════════════════════════
//  完整检测 (内部)
// ═══════════════════════════════════════════════════════════

static void PopulateReport(DetectionReport& r) {
    r.score = 0;

    r.debugger_present  = Detect_PEB_BeingDebugged();       if (r.debugger_present)  { r.score += 1; r.details += "PEB_BeingDebugged; "; }
    r.debug_port        = Detect_DebugPort();                if (r.debug_port)        { r.score += 2; r.details += "DebugPort; "; }
    r.kernel_debugger   = Detect_KernelDebugger();           if (r.kernel_debugger)   { r.score += 3; r.details += "KernelDebugger; "; }
    r.nt_global_flag    = Detect_NtGlobalFlag();             if (r.nt_global_flag)    { r.score += 2; r.details += "NtGlobalFlag; "; }

    { bool v = Detect_DebugObjectHandle(); if (v) { r.score += 2; r.details += "DebugObjHandle; "; } }
    { bool v = Detect_DebugFlags(); if (v) { r.score += 2; r.details += "DebugFlags; "; } }
    { bool v = Detect_SuspiciousParent(); if (v) { r.score += 2; r.details += "ParentProcess; "; } r.suspicious_parent = v; }
    { bool v = registry::DetectRegistryTampering(); if (v) { r.score += 2; r.details += "RegistryTamper; "; } }

    // L1
    r.hardware_bp = Detect_HardwareBreakpoints();           if (r.hardware_bp) { r.score += 3; r.details += "HW_BP; "; }
    r.int3_patch  = Detect_Int3Patches();                   if (r.int3_patch)  { r.score += 2; r.details += "INT3; "; }
    r.suspicious_dll = Detect_SuspiciousDlls();              if (r.suspicious_dll) { r.score += 3; r.details += "BadDLL; "; }
    r.timing_anomaly = Detect_TimingAnomaly();               if (r.timing_anomaly) { r.score += 1; r.details += "Timing; "; }

    // Phase 2: 内存页属性 / VEH链 / 调用栈 / 沙箱
    { bool v = memguard::DetectWritableCodePages(); if (v) { r.score += 3; r.details += "WritableCode; "; } }
    { bool v = vehguard::DetectVehChainTampering(); if (v) { r.score += 2; r.details += "VEHChain; "; } }
    { bool v = stackguard::VerifyCallerInText(); if (!v) { r.score += 4; r.details += "ForeignCaller; "; } }

    if (r.score == 0) r.details = "clean";
}

// ═══════════════════════════════════════════════════════════
//  静默退出
// ═══════════════════════════════════════════════════════════

static void SilentExit() {
    // 自毁: 立即终止，不写日志不弹窗
    // RaiseFailFastException 会立即终止进程且不运行全局析构/atexit
    // 这样攻击者更难追踪退出原因
    TerminateProcess(GetCurrentProcess(), 0xDEAD);
}

// ═══════════════════════════════════════════════════════════
//  L0: StartupGuard
// ═══════════════════════════════════════════════════════════

bool StartupGuard() {
#ifdef PEANUT_RELEASE
    InitNtFunctions();

    DetectionReport r;
    PopulateReport(r);

    if (r.score >= SCORE_THRESHOLD) {
        SilentExit();
        return false;
    }

    // Phase 2: PE头自擦除 (脱壳对抗)
    peguard::ErasePEHeaders();

    // Phase 2: 沙箱检测初始化 + 慢速检测 (2/3阈值才退出，降低误报)
    sandbox::InitSandboxDetection();
    if (sandbox::DetectSandbox()) {
        SilentExit();
        return false;
    }
#endif
    return true;
}

// ═══════════════════════════════════════════════════════════
//  L1: Watchdog
// ═══════════════════════════════════════════════════════════

static std::function<void()> g_on_threat;

static DWORD WINAPI WatchdogProc(LPVOID) {
#ifdef PEANUT_RELEASE
    g_watchdog_running = true;
    int consecutiveHits = 0;

    while (g_watchdog_running) {
        // 随机间隔 2~5 秒
        int delayMs = 2000 + (rand() % 3000);
        Sleep(delayMs);

        if (!g_watchdog_running) break;

        DetectionReport r;
        PopulateReport(r);

        if (r.score >= SCORE_THRESHOLD) {
            ++consecutiveHits;
            if (consecutiveHits >= 2) {
                // 连续两次命中 → 确认威胁
                MarkCompromised();
                if (g_on_threat) {
                    g_on_threat();
                }
                SilentExit();
            }
        } else {
            consecutiveHits = 0;
        }
    }
#endif
    return 0;
}

void StartWatchdog(std::function<void()> on_threat) {
#ifdef PEANUT_RELEASE
    g_on_threat = std::move(on_threat);
    g_watchdog_thread = CreateThread(
        nullptr, 0,
        WatchdogProc, nullptr,
        0,
        &g_watchdog_tid);
#endif
}

void StopWatchdog() {
#ifdef PEANUT_RELEASE
    g_watchdog_running = false;
    if (g_watchdog_thread) {
        WaitForSingleObject(g_watchdog_thread, 3000);
        CloseHandle(g_watchdog_thread);
        g_watchdog_thread = nullptr;
    }
#endif
}

// ═══════════════════════════════════════════════════════════
//  L2: QuickCheck
// ═══════════════════════════════════════════════════════════

bool QuickCheck() {
#ifdef PEANUT_RELEASE
    if (!g_safe.load(std::memory_order_relaxed)) return false;

    // L2轻量检测: PEB + DebugPort + 调用栈 + 沙箱快速
    if (Detect_PEB_BeingDebugged() || Detect_DebugPort()) {
        MarkCompromised();
        return false;
    }
    if (!stackguard::VerifyCallerInText()) {
        MarkCompromised();
        return false;
    }
    if (sandbox::DetectSandboxQuick()) {
        MarkCompromised();
        return false;
    }
#endif
    return g_safe.load(std::memory_order_relaxed);
}

// ═══════════════════════════════════════════════════════════
//  L3: 安全标志
// ═══════════════════════════════════════════════════════════

bool IsSafe() {
    return g_safe.load(std::memory_order_relaxed);
}

void MarkCompromised() {
    g_safe.store(false, std::memory_order_release);
}

// ═══════════════════════════════════════════════════════════
//  反调试器附加
// ═══════════════════════════════════════════════════════════

bool PreventDebuggerAttach() {
#ifdef PEANUT_RELEASE
    InitNtFunctions();
    if (g_NtSetInformationProcess) {
        // 清除调试端口，阻止后续附加
        NTSTATUS st = g_NtSetInformationProcess(
            GetCurrentProcess(), ProcessDebugObjectHandle, nullptr, 0);
        return NT_SUCCESS(st);
    }
#endif
    return true;
}

// ═══════════════════════════════════════════════════════════
//  完整检测报告 (调试用)
// ═══════════════════════════════════════════════════════════

DetectionReport FullDetection() {
    InitNtFunctions();
    DetectionReport r;
    PopulateReport(r);
    return r;
}

}}} // namespace
