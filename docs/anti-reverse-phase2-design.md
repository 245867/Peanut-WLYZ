# Peanut_WLYZ 反逆向 Phase 2 — PE变形 / 内存保护 / 注册表检测 / 环境对抗

> 日期: 2026-07-31
> 基础: Phase 1 四层反调试已完成 (L0 入口守卫 + L1 Watchdog + L2 QuickCheck + L3 加密守卫)
> Phase 2 目标: 从「检测调试器」升级到「让逆向工程本身变得极其痛苦」

---

## 一、PE 文件层变形

### 1.1 IAT 运行时动态解析（消除静态导入表可见性）

**问题**: 当前 exe 的 IAT 完整暴露所有 Win32 API 调用——用 PE-Bear / IDA / DIE 一眼看到 `IsDebuggerPresent`、`CreateThread`、`NtQueryInformationProcess`，攻击者立刻知道有哪些反调手段。

**方案**: 编译后脚本处理 → 删除原始导入表条目 → 改为运行时 `GetProcAddress` + hash 查表解析。

```cpp
// anti_iat.h — 新增模块
namespace peanut { namespace security { namespace iat {

// DJB2 hash: 编译期计算 API 名字符串 hash
constexpr DWORD HashAPI(const char* name) {
    DWORD h = 5381;
    for (; *name; ++name) h = ((h << 5) + h) + (BYTE)*name;
    return h;
}

// 运行时: hash 查表获取函数指针
inline FARPROC ResolveByHash(DWORD moduleHash, DWORD funcHash);

// 使用示例:
// auto pCreateThread = ResolveByHash("kernel32.dll"_h, "CreateThread"_h);
// pCreateThread(nullptr, 0, &worker, nullptr, 0, &tid);

struct IATEntry {
    DWORD moduleHash;  // 模块名字符串 hash
    DWORD funcHash;    // 函数名字符串 hash
    void** ppfn;       // 写入目标
};

// 初始化: 遍历表，逐项解析并写入 ppfn
void InitIAT(const IATEntry* table, size_t count);

}}} // namespace
```

**对抗效果**: 静态分析工具看到的导入表为空或被垃圾填充 → IDA 无法直接识别 API 调用 → 必须动态调试才能理解控制流。

**实现量**: ~200行 C++ + Python 脚本提取原 IAT 生成 hash 表 + 修改 PE 截断 IAT 目录。

---

### 1.2 PE 头运行时自擦除（反 Dump）

**问题**: 加壳前的原生 PE 结构在内存中完整 → ProcessHacker/x64dbg "Dump PE" 一键抓到完整 exe → 再静态分析。

**方案**: 初始化完成后，`VirtualProtect` + `SecureZeroMemory` 擦除 PE 头中的关键字段：

```cpp
// anti_pe.h — 新增模块
namespace peanut { namespace security { namespace pe {

struct PEEraseConfig {
    bool eraseDosHeader    = true;  // MZ 签名 + DOS stub
    bool eraseRichHeader   = true;  // VS Rich header
    bool eraseSectionNames = true;  // .text/.data/.rdata → 随机填充
    bool eraseDebugDir     = true;  // PDB 路径/RVA (即使无 PDB 也有残留)
    bool zeroUnusedGap     = true;  // section 之间的 padding 清零
};

// 在 wWinMain 初始化最后调用
void ErasePEHeader(const PEEraseConfig& cfg = {}) {
    HMODULE base = GetModuleHandleW(nullptr);
    auto* dos    = (PIMAGE_DOS_HEADER)base;
    auto* nt     = (PIMAGE_NT_HEADERS)((BYTE*)base + dos->e_lfanew);

    DWORD old;
    // 1. 擦除 DOS 头 (保留 e_lfanew 用于后续 PE 解析)
    if (cfg.eraseDosHeader) {
        VirtualProtect(dos, dos->e_lfanew, PAGE_READWRITE, &old);
        SecureZeroMemory(dos, dos->e_lfanew);
        dos->e_magic = 0; // MZ → 0
    }

    // 2. 擦除 section 名称
    if (cfg.eraseSectionNames) {
        auto* sec = IMAGE_FIRST_SECTION(nt);
        VirtualProtect(sec, nt->FileHeader.NumberOfSections * sizeof(IMAGE_SECTION_HEADER),
                       PAGE_READWRITE, &old);
        for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
            memset(sec[i].Name, 0, 8);
        }
    }

    // 3. 擦除 Debug Directory
    if (cfg.eraseDebugDir && nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].Size) {
        auto& dd = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG];
        VirtualProtect((BYTE*)base + dd.VirtualAddress, dd.Size, PAGE_READWRITE, &old);
        SecureZeroMemory((BYTE*)base + dd.VirtualAddress, dd.Size);
        dd.Size = 0;
        dd.VirtualAddress = 0;
    }
}

}}} // namespace
```

**对抗效果**: 
- Dump 出的 PE 无 MZ 头、无区段名 → PE 解析器无法重建完整文件
- Debug Directory 被擦 → 符号恢复/PDB 定位失效
- 与 VMProtect 的内存保护不冲突（VMProtect 保护的是虚拟化代码段，我们擦的是 PE 元数据）

---

### 1.3 重定位表删除 + 基址固化

**问题**: .reloc 段暴露所有代码/数据位置的绝对地址 → 攻击者可通过重定位表反向推导代码布局 → 写 shellcode patch 时精确定位。

**方案**: 
- 链接时固定 ImageBase (如 0x140000000)，同时在 wWinMain 入口检查实际加载地址
- 如果加载地址 ≠ 固定基址（ASLR 生效），用 NtUnmapViewOfSection + 重新映射到固定地址
- 成功后删除 .reloc 段

```
// 链接器选项:
/FIXED             // 禁止生成重定位
/BASE:0x140000000  // 固定基址
/DYNAMICBASE:NO    // 禁止 ASLR (需自己处理重定位)
```

**替代方案（更优雅）**: 自定义重定位表 → 编译器正常生成 → 构建脚本将 .reloc 内容 AES 加密 → 运行时 TLS callback 中解密并执行 → PE 头中重定位目录 RVA 指向垃圾 → 攻击者抓到的地址表全是密文。

---

### 1.4 TLS Callback 入口劫持（在 main 之前跑）

**问题**: 当前所有初始化在 `wWinMain` 中 → 调试器在 `wWinMain` 入口下断一步到位 → Phase 1 的 `StartupGuard` 被掐断即可绕过。

**方案**: 把 `StartupGuard` + `ErasePEHeader` 移到 TLS callback → 在 CRT 初始化之前执行 → 攻击者必须在系统加载器阶段就介入（难度 ×10）。

```cpp
// anti_tls.cpp — 新增
#include <windows.h>
#include "anti_debug.h"
#include "anti_pe.h"

#pragma section(".CRT$XLY", long, read)  // TLS callback section

extern "C" void __stdcall AntiDebugTlsCallback(PVOID, DWORD reason, PVOID) {
    if (reason == DLL_PROCESS_ATTACH) {
        // 此处比 wWinMain 早执行——CRT 未初始化、IAT 未解析
        // 只能做纯 Windows API 调用（不能用 std::string / cout 等）
        peanut::security::antidebug::InitNtFunctions(); // 需要暴露到头文件
        if (!peanut::security::antidebug::StartupGuardTLS()) {
            TerminateProcess(GetCurrentProcess(), 0xDEAD);
        }
    }
}

// __declspec(allocate(".CRT$XLY")) — 链接器会收集到 TLS callback 数组
__declspec(allocate(".CRT$XLY"))
PIMAGE_TLS_CALLBACK g_tls_callback = AntiDebugTlsCallback;

#ifdef _WIN64
#pragma comment(linker, "/INCLUDE:_tls_used")
#else
#pragma comment(linker, "/INCLUDE:__tls_used")
#endif
```

**对抗效果**:
- IDA/x64dbg 默认断在 `wWinMain` → 此时反调试已跑完并退出了
- 攻击者必须在系统加载器事件上设断（`LdrpCallTlsInitializers`）才能拦截 → 从用户态退到内核态入口

---

### 1.5 Section 之间插入守卫页（Guard Pages）

**问题**: 攻击者 dump 内存后，可以逐 section 分析。如果我们在 section 之间放 `PAGE_NOACCESS` 页 → 任何越界扫描触发异常 → VEH 捕获后自毁。

**方案**: 编译后用脚本在区段描述中插入虚拟区段，运行时分配 `PAGE_NOACCESS` 守卫页：

```cpp
void InsertGuardPages() {
    // 在 .text 和 .data 之间、.data 和 .rdata 之间
    // 各自分配一个 PAGE_NOACCESS 4KB 页
    // 然后注册 VEH 处理器:
    //   如果是正常的跨 section 访问 → 不应该发生 → 自毁
    //   如果是我们自己的代码有意触发 → 白名单地址
}
```

---

## 二、R3 内存保护

### 2.1 代码段 Page-In/Page-Out 加解密（VEH 按需解密）

**问题**: Phase 1 做了 0xCC 字节扫描，但攻击者可以 dump 后离线分析。如果代码在内存中一直是明文 → dump = 完整逆向。

**方案**: 敏感函数编译到独立 section → 默认 `PAGE_NOACCESS` → 首次调用触发 `EXCEPTION_ACCESS_VIOLATION` → VEH 处理器解密 section → 改为 `PAGE_EXECUTE_READ` → 执行完再加密回去。

```cpp
// anti_memory.h — 新增模块
namespace peanut { namespace security { namespace memguard {

struct ProtectedSection {
    BYTE*  base;
    SIZE_T size;
    BYTE   xorKey[16];   // AES-128 key
    bool   isEncrypted;   // 当前是否加密态
};

// 初始化: 编译后脚本用 AES 加密 .psec section → 运行时注册 VEH
void InitSectionGuard();

// VEH 处理器:
LONG CALLBACK SectionGuardVEH(PEXCEPTION_POINTERS ep) {
    // 1. 检查异常地址是否在 ProtectedSection 范围内
    // 2. 是 → 解密该 section → PAGE_EXECUTE_READ → 返回 EXCEPTION_CONTINUE_EXECUTION
    // 3. 否 → EXCEPTION_CONTINUE_SEARCH

    // 执行完 → 设置 hardware breakpoint 或 hook 返回地址
    //  → 在函数返回时重新加密 + PAGE_NOACCESS
}

}}} // namespace
```

**实现量**: ~400行 C++。关键技术难点：如何在函数返回时重新加密——三种方案：
- **方案 A**: Hook 返回地址（栈上改 return addr → 先跳转到加密 stub → jmp 原始返回地址）
- **方案 B**: 在 `SectionGuardVEH` 中设硬件断点在返回地址 (x64 有 4 个 DR 可用)
- **方案 C**: 直接 hook 函数序言 → 不靠 VEH，在编译期替换函数入口为解密 stub（更可控）

**推荐方案 C**: 编译后用脚本给关键函数包解密/加密壳，不依赖 VEH，更稳定。

---

### 2.2 调用栈验证（反 ROP / 反 inline hook）

**问题**: Frida / Detours / Microsoft Detours 通过 inline hook 修改函数开头 5 字节 → `jmp hook_handler` → 攻击者全程监控函数调用。

**方案**: 在每个敏感函数（`wy_rsa_decrypt`、`Activate`、`SendRequest`）开头验证返回地址所属模块 + 调用深度 + 栈对齐：

```cpp
// anti_stack.h — 新增模块
namespace peanut { namespace security { namespace stackguard {

// 验证: 调用者的返回地址必须在自身 .text 段内
inline bool VerifyCallerInText() {
    // _ReturnAddress() 返回调用者的返回地址
    PVOID retAddr = _ReturnAddress();

    // 取自身 .text 段范围
    HMODULE base = GetModuleHandleW(nullptr);
    auto* dos     = (PIMAGE_DOS_HEADER)base;
    auto* nt      = (PIMAGE_NT_HEADERS)((BYTE*)base + dos->e_lfanew);
    auto* sec     = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
        if (memcmp(sec[i].Name, ".text", 5) == 0) {
            BYTE* start = (BYTE*)base + sec[i].VirtualAddress;
            BYTE* end   = start + sec[i].Misc.VirtualSize;
            return (BYTE*)retAddr >= start && (BYTE*)retAddr < end;
        }
    }
    return false;  // .text 段不存在?
}

// 在关键函数入口使用宏:
#define VERIFY_CALLER() \
    if (!stackguard::VerifyCallerInText()) { \
        antidebug::MarkCompromised(); \
        antidebug::SilentExit(); \
    }

}}} // namespace
```

**对抗效果**: Frida 的 `Interceptor.attach()` 修改了函数开头 → 返回地址指向 Frida 的 trampoline → 不在 .text 段 → 立即检测。

---

### 2.3 内存页属性完整性巡检（反 hook / 反内存补丁）

**问题**: inline hook 需要把目标页改为 `PAGE_EXECUTE_READWRITE` → 正常代码页是 `PAGE_EXECUTE_READ`。

**方案**: Watchdog 线程除了做调试器检测，还要巡检所有 `.text` 页的 `Protect` 属性：

```cpp
static bool Detect_WritableCodePages() {
    HMODULE base = GetModuleHandleW(nullptr);
    auto* dos = (PIMAGE_DOS_HEADER)base;
    auto* nt  = (PIMAGE_NT_HEADERS)((BYTE*)base + dos->e_lfanew);
    auto* sec = IMAGE_FIRST_SECTION(nt);

    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
        if (sec[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) {
            // 执行段: 逐页检查
            BYTE* secBase = (BYTE*)base + sec[i].VirtualAddress;
            SIZE_T secSize = sec[i].Misc.VirtualSize;

            MEMORY_BASIC_INFORMATION mbi;
            for (BYTE* p = secBase; p < secBase + secSize; p += mbi.RegionSize) {
                VirtualQuery(p, &mbi, sizeof(mbi));
                // 可执行段不允许可写
                if (mbi.Protect & (PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) {
                    return true;  // 有人改了页属性!
                }
            }
        }
    }
    return false;
}
```

**对抗效果**: 任何需要改页属性的 hook 框架（detours、minhook）全部暴露。

---

### 2.4 VEH 链完整性验证（反 anti-anti-debug）

**问题**: 高级攻击者会注册自己的 VEH → 拦截我们的 `EXCEPTION_ACCESS_VIOLATION`（如 `CloseHandle(0xDEADC0DE)` 异常检测）→ 吃掉异常 → 我们的检测失效。

**方案**: 用 `RtlRemoveVectoredExceptionHandler` 无效？不可能删别人的。改用：
```cpp
// 注册一个 VEH 在最前面，故意触发一个独特的异常
// 如果我们的 VEH 没有被调用 → 有其他 VEH 拦截了 → 检测到反反调手段

static volatile bool g_veh_test_passed = false;
static LONG CALLBACK VehIntegrityTest(PEXCEPTION_POINTERS) {
    g_veh_test_passed = true;  // 我们的 VEH 被调用了
    return EXCEPTION_CONTINUE_SEARCH;
}

static bool Detect_VEH_Chain_Tampering() {
    PVOID handle = AddVectoredExceptionHandler(1, VehIntegrityTest); // 第一个
    g_veh_test_passed = false;
    __try { RaiseException(0xEEEE0001, 0, 0, nullptr); }
    __except (EXCEPTION_EXECUTE_HANDLER) {}
    RemoveVectoredExceptionHandler(handle);
    return !g_veh_test_passed;  // 如果我们的 VEH 没被调 → 被拦截/删除了
}
```

---

## 三、注册表 & 环境检测

### 3.1 调试器注册表项检测

```cpp
// 需要检查的注册表路径:
static const wchar_t* kDebuggerRegistryKeys[] = {
    // 系统级 (IFEO = Image File Execution Options, 调试器自动启动)
    L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options",
    // AeDebug (系统崩溃调试器)
    L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\AeDebug",
    // MITM 代理证书
    L"SOFTWARE\\Microsoft\\SystemCertificates\\ROOT\\Certificates\\*",
    // .NET 调试 (虽然我们是 native, 但攻击者可能用 dnSpy 分析)
    L"SOFTWARE\\Microsoft\\.NETFramework\\DbgJITDebugLaunchSetting",
    L"SOFTWARE\\Microsoft\\.NETFramework\\DbgManagedDebugger",
};

bool Detect_Debugger_Registry() {
    // 检查 IFEO 下是否有自身进程名 → 有 = 调试器被设为自动启动
    wchar_t path[MAX_PATH];
    swprintf_s(path, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\"
                L"Image File Execution Options\\%s", GetExeName());
    HKEY hk;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, path, 0, KEY_READ, &hk) == ERROR_SUCCESS) {
        wchar_t debugger[512] = {};
        DWORD size = sizeof(debugger);
        if (RegQueryValueExW(hk, L"Debugger", nullptr, nullptr,
            (LPBYTE)debugger, &size) == ERROR_SUCCESS) {
            RegCloseKey(hk);
            return true;  // 被设了调试器!
        }
        RegCloseKey(hk);
    }
    return false;
}
```

### 3.2 虚拟机检测（注册表 + WMI + 硬件）

```cpp
// 检测 VMware / VirtualBox / QEMU / Sandboxie / Cuckoo 等
static const wchar_t* kVmRegistryPaths[] = {
    L"HARDWARE\\ACPI\\DSDT\\VBOX__",                     // VirtualBox
    L"HARDWARE\\ACPI\\RSDT\\VBOX__",
    L"SOFTWARE\\VMware, Inc.\\VMware Tools",              // VMware Tools
    L"SOFTWARE\\Oracle\\VirtualBox Guest Additions",      // VirtualBox Guest Additions
    L"HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 0\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0",
    L"SYSTEM\\ControlSet001\\Services\\VBoxGuest",        // VBox 服务
    L"SYSTEM\\ControlSet001\\Services\\VBoxMouse",
    L"SYSTEM\\ControlSet001\\Services\\VBoxService",
    L"SYSTEM\\ControlSet001\\Services\\VBoxSF",
    L"SYSTEM\\ControlSet001\\Services\\VBoxVideo",
    L"SOFTWARE\\Microsoft\\Virtual Machine\\Guest\\Parameters",  // Hyper-V
    L"SOFTWARE\\Citrix\\",                                // Xen
    L"HARDWARE\\ACPI\\DSDT\\QEMU",                        // QEMU
};

// 硬件检测:
bool Detect_VM_Hardware() {
    // 1. 硬盘名检测
    // 2. 网卡 MAC OUI 检测 (VMware: 00:50:56, 00:0C:29, VirtualBox: 08:00:27)
    // 3. CPUID leaf 0x40000000 → Hypervisor 签名字符串
    return false;  // 视需求实现
}
```

### 3.3 沙箱/分析环境检测

```cpp
bool Detect_Sandbox() {
    // 1. 运行时间 < 5 分钟 (自动化沙箱不会等太久)
    if (GetTickCount64() < 300000) return true;

    // 2. 屏幕分辨率 ≤ 800x600 (沙箱常见小窗口)
    int w = GetSystemMetrics(SM_CXSCREEN);
    int h = GetSystemMetrics(SM_CYSCREEN);
    if (w <= 800 || h <= 600) return true;

    // 3. 鼠标移动量 < 阈值 (沙箱无真实用户)
    // 4. 最近文件数 < 10 (新安装的 VM)
    // 5. CPU 核心数 = 1

    return false;
}
```

---

## 四、导入表 & 延迟加载变形

### 4.1 API 调用间接化（syscall stub / 自建跳板）

**问题**: 即使 IAT 加密，运行时所有 API 调用都要经过 `call qword ptr [IAT]` → 在 IDA 中按 `X` 交叉引用 → 所有调用点暴露。

**方案**: 把常用 API 包一层跳板函数，跳板本身做随机延迟/垃圾指令插入：

```cpp
// 每编译一次随机变换
__declspec(noinline) NTSTATUS NtQueryInformationProcess_Wrapper(
    HANDLE h, ULONG infoClass, PVOID info, ULONG len, PULONG retLen)
{
    // 插入随机垃圾指令 (编译器优化关掉)
    volatile int junk1 = __rdtsc() & 0xFF;
    volatile int junk2 = junk1 ^ 0xDEAD;
    (void)junk2;

    // 真正调用
    return g_NtQueryInformationProcess(h, infoClass, info, len, retLen);
}
```

### 4.2 伪造导入表（蜜罐）

**问题**: 攻击者一定会看导入表。如果把 `IsDebuggerPresent` 放在导入表 → 他们立刻知道有反调。

**方案**: 主动在 IAT 中添加但**从不调用**的函数：
- `IsDebuggerPresent` → 攻击者 hook 了这个 → 我们实际用 PEB 直接读
- `OutputDebugStringA` → 正常程序不会导入 → 用来迷惑
- `SetUnhandledExceptionFilter` → 看似要设异常处理 → 实际我们用 VEH
- `CreateToolhelp32Snapshot` → 看似要遍历进程 → 实际我们用 `NtQuerySystemInformation` 直接调

这些函数在 IAT 中，但永远不被调用 → 攻击者 hook 它们 → 浪费精力 + 暴露自己。

---

## 五、控制流混淆

### 5.1 控制流平坦化（补充 VMProtect 未覆盖的路径）

**问题**: 当前只有 100 个 VMProtect 标记 → 大部分逻辑路径是明文 → 攻击者可以正面硬上、绕过 VMP 标记去看明文的 `Activate` 逻辑。

**方案**: 对 SDK 的 `peanut_secure_client.cpp` 中非 VMP 标记函数做手写控制流混淆：

```cpp
// 原始:
bool Foo(int x) {
    if (x > 10) return A(); else return B();
}

// 混淆后:
bool Foo(int x) {
    int state = ((__rdtsc() & 1) ? 0 : 0);  // 垃圾指令，始终 = 0
    while (true) {
        switch (state) {
        case 0:
            if (x > 10) { state = 1; continue; }
            else        { state = 2; continue; }
        case 1: return A();
        case 2: return B();
        }
    }
}
```

**对关键函数**: `PSPHandshake`、`SendRequest`、`FetchSessionPolicy` — 这些是攻击者的必经之路 → 手动展开 if-else 为 switch-case 状态机。

### 5.2 不透明谓词注入

```cpp
// 编译器无法优化掉的永远-真/永远-假条件:
// (x * (x-1) % 2 == 0) — 两个连续整数的积永远是偶数 → 恒真
// 攻击者肉眼分析时必须一个个解 → 极度耗时

#define OPAQUE_TRUE  ((__rdtsc() * (__rdtsc() - 1)) % 2 == 0)
#define OPAQUE_FALSE (((__rdtsc() + 1) * (__rdtsc() + 2)) % 2 == 0)

if (OPAQUE_TRUE) {
    // 实际执行的代码
    real_work();
} else {
    // 永不执行 → 但 IDA 会画出两条分支 → 混淆攻击者
    fake_decoy();
}
```

---

## 六、实施优先级

| 优先级 | 模块 | 理由 |
|---|---|---|
| **P0** | TLS Callback 入口劫持 | 以最小成本把反调试提到 CRT 之前，性价比极高 |
| **P0** | PE 头运行时自擦除 | ~100 行代码，完全废掉 dump 分析 |
| **P1** | IAT 运行时动态解析 | 废掉导入表静态分析，让 IDA 瞎掉 |
| **P1** | 内存页属性巡检 | 直接检测任何 hook 框架 |
| **P1** | 调用栈验证 | 对抗 Frida inline hook |
| **P2** | 注册表检测 | 检测 IFEO/AeDebug 等调试器配置 |
| **P2** | VEH 链完整性 | 对抗高级 anti-anti-debug |
| **P2** | 控制流混淆（手动） | 让非 VMP 路径也难以阅读 |
| **P3** | 按需加解密 (Section Guard) | 实现复杂，但效果最好 |
| **P3** | 虚拟机/沙箱检测 | 对抗自动化分析平台 |
| **P3** | 伪造导入表 | 让攻击者 wasting time |

---

## 七、与现有架构的集成

```
anti_debug.cpp/h    ← Phase 1 四层防线 (保留，补齐 TLS 入口)
anti_pe.cpp/h       ← 新增: PE 头自擦除
anti_iat.cpp/h      ← 新增: IAT 动态解析 + 伪造导入
anti_memory.cpp/h   ← 新增: 页属性巡检 + 守卫页
anti_stack.cpp/h    ← 新增: 调用栈验证
anti_registry.cpp/h ← 新增: 注册表检测
anti_env.cpp/h      ← 新增: VM/沙箱环境检测

全部放 src/PeanutClient/sdk/ 下，统一 namespace peanut::security
编译宏: #ifdef PEANUT_RELEASE (Peanut_WLYZ) / #ifdef VM_PROTECT_ACTIVE (方案C)
```

---

## 八、构建脚本扩展 (build_all.ps1 增加 Phase 2 编译后处理)

```powershell
# Phase 2 构建后步骤:
# 1. 编译 exe → 正常输出
# 2. Python 脚本: 提取 IAT → 生成 hash 表 .cpp → 重新编译
# 3. Python 脚本: 加密 .psec section → 替换原 section
# 4. Python 脚本: 删除 .reloc section → 修复 PE 头
# 5. Python 脚本: 填充 section 间 gap → 随机字节
```

---

*本文档为 Phase 2 设计草案，具体实现细节以代码为准。
具体哪些先做，你决定。*
