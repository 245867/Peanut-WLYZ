# Peanut WLYZ 反调试 / 反逆向安全加固 — 规划文档

> 版本: v1.0-draft  
> 日期: 2026-07-30  
> 目标: 在现有 VMProtect + WY 加密的基础上，补充代码级反调试、入口守卫与运行时完整性检查

---

## 1. 设计原则

| 原则 | 说明 |
|---|---|
| **Fail-Closed** | 检测到调试/篡改一律静默退出，不做弹窗告知攻击者 |
| **分层防御** | 入口 → 运行时 → API 三层不互相依赖，单层绕过仍有后续层 |
| **最小暴露** | 反调逻辑不暴露字符串、不集中调 Win32 API（分散+混淆） |
| **延迟生效** | 检测结果延迟 5~30 秒后生效，增加调试定位难度 |
| **不破坏可用性** | Debug 构建全跳过，Release-only |

---

## 2. 防御分层

```
┌─────────────────────────────────────────────────────┐
│ Layer 0: 入口守卫 (main/WinMain → 第一行 C++ 代码)    │
│  ⤷ Startup 调试器检测 + 父进程检查 + 反附加保护         │
├─────────────────────────────────────────────────────┤
│ Layer 1: 运行时守护 (独立 watchdog 线程，每 2~5s 轮询)  │
│  ⤷ 调试器重检测 / 硬件断点扫描 / 完整性校验 / 反内存补丁 │
├─────────────────────────────────────────────────────┤
│ Layer 2: API 层守卫 (每次 SDK 调用必经)                │
│  ⤷ 关键函数入口心跳 / HMAC 状态链 / 时间检测           │
├─────────────────────────────────────────────────────┤
│ Layer 3: 加密层守卫 (WY-cipher / RSA 内部)             │
│  ⤷ 密钥自毁 / 调用栈验证 / 内存页属性检测              │
└─────────────────────────────────────────────────────┘
```

---

## 3. Layer 0 — 入口守卫

**触发时机**: `wWinMain` / `main` 第一行，VMProtect 之前。

### 3.1 调试器存在性检测（Startup Checklist）

使用 Windows 官方 + 未公开 API 组合，每项独立评分，总分 ≥ 阈值 → 退出。

| 检测项 | 方法 | 权重 |
|---|---|---|
| `IsDebuggerPresent()` | PEB.BeingDebugged | ★ |
| `CheckRemoteDebuggerPresent(GetCurrentProcess(), &ret)` | 内核调试端口 | ★ |
| `NtQueryInformationProcess(ProcessDebugPort)` | 调试端口 (ring3) | ★★ |
| `NtQueryInformationProcess(ProcessDebugObjectHandle)` | 调试对象句柄 | ★★ |
| PEB.NtGlobalFlag (0x70) | `mov eax, fs:[30h]; mov eax, [eax+68h]` → 0x70 = 调试 | ★★ |
| `NtQuerySystemInformation(SystemKernelDebugger)` | 内核调试器 | ★★★ |
| `CloseHandle((HANDLE)0xDEADC0DE)` 异常检测 | 调试器拦截异常 | ★ |
| 进程启动父进程名检测 | 父进程非 explorer.exe → 可疑 (被调试启动) | ★★ |
| 命令行参数扫描 | `-debug` / `--inspect` / Frida/GDB 特征 | ★ |

**阈值**: 总分 ≥ 5 则判定为存在调试器。

### 3.2 反调试器附加（Anti-Attach）

```cpp
// 调用一次后，后续任何调试器通过 DebugActiveProcess 附加都会失败
// 方案: 让自身进程成为自己的调试器（自调试）
//   → NtDebugActiveProcess(GetCurrentProcess(), ...) 到伪调试器进程
//   → 或直接 NtSetInformationProcess(ProcessDebugObjectHandle, NULL)
typedef NTSTATUS (NTAPI *pNtSetInformationProcess)(HANDLE, ULONG, PVOID, ULONG);
// ProcessDebugObjectHandle = 0x1E, 传入 NULL 断开调试端口
```

### 3.3 静态反汇编保护入口

入口 `wWinMain` 包裹 `VMProtectBeginUltra("EntryGuard")`，确保入口函数本身被虚拟化，对抗静态分析。

---

## 4. Layer 1 — 运行时守护

**触发时机**: 独立低优先级线程，每 2~5 秒随机间隔唤醒。

### 4.1 心跳重检

每次唤醒重新执行 Layer 0 全部检测项（不退出直接做标记），若连续 N 次命中 → 触发清退。

### 4.2 硬件断点扫描 (Hardware Breakpoint Detection)

```cpp
// 读取当前线程的 DR0~DR3 调试寄存器
// 任何非零值 → 有硬件断点在监视 → 立即清退
// 使用 GetThreadContext / 内联 asm mov drX 方式
// (x64 受限于 PatchGuard，但仍可读 CONTEXT)
```

- 主线程 + watchdog 线程均检查
- x86 直接 `mov eax, dr0` 等；x64 用 `GetThreadContext` + `CONTEXT_DEBUG_REGISTERS`

### 4.3 代码段完整性校验

```cpp
// 选 3~5 个关键函数（分散在 SDK/API/加密层）
// 运行时计算 CRC32 / WY-Hash 摘要
// 与编译期固化的预期值对比
// 不匹配 → 内存被修改（inline hook / 补丁）→ 清退
```

**选点策略**: 不选热点函数（容易被找到），选冷路径校验函数。

### 4.4 反内存补丁 (Software Breakpoint Scan)

```cpp
// 扫描 .text 段关键区域，检测 0xCC (INT3) 字节
// 0xCC 出现在非预期位置 = 调试器断点
// 使用 VirtualProtect 临时解开只读 → 检查 → 恢复
```

### 4.5 反 DLL 注入检测

| 检测项 | 方法 |
|---|---|
| 陌生 DLL 枚举 | `EnumProcessModules` 获取列表，对比白名单 |
| 可疑模块名 | Frida (`frida-agent*.dll`)、x64dbg (`x64dbg.dll`)、Cheat Engine (`cheatengine*.dll`) |
| 导出函数扫描 | 遍历模块导出表，检测 `DllMain` 额外调用 |

### 4.6 时间反检测

```cpp
// 取两次高精度时间（QueryPerformanceCounter / RDTSC）
// 差值异常大 (>500ms) → 调试器单步执行被暂停过 → 清退
// 使用 RDTSC 内联汇编绕过 hook
```

---

## 5. Layer 2 — API 层守卫

**触发时机**: 每次 `PeanutSecureClient` SDK 调用（Activate/Heartbeat/FetchPlugin 等）。

### 5.1 状态链 HMAC (已有基础，增强)

```cpp
// 已有的 AuthorizationGuard 守卫链
// 增强: 每个 API 入口互相传递 HMAC，下一个 API 验证上一个的 HMAC
// 断链 = 状态被外部篡改 → 立即 Invalidate(SECURITY_SHUTDOWN)
```

### 5.2 API 入口前置检测 (轻量)

每个 SDK 公开函数开头添加（不替代 Layer 1，Layer 1 负责深度扫描）：

```cpp
// 轻量快速检查: PEB 标志 + 时间偏差
// 命中则直接跳过 API 返回错误码
// 不立即终止（给 Layer 1 时间确认，避免误报）
```

### 5.3 调用来源验证

```cpp
// 通过 _ReturnAddress() 获取调用方地址
// 验证是否在自身模块地址范围内
// 不在 → 来自外部注入代码 → 拒绝服务
```

---

## 6. Layer 3 — 加密层守卫

**触发时机**: `wy_rsa_encrypt` / `wy_cbc_encrypt` / `wy_hash` 等加密原语被调用。

### 6.1 密钥自毁

```cpp
// 检测到调试/篡改后:
//   → SecureZeroMemory 立即擦除 aes_key / psp_key / rsa_priv
//   → 后续所有加密操作返回全零 → 通信必然失败 → 服务端端拒绝
// 触发条件: Layer 1 的全局原子标志位
```

### 6.2 内存页属性检测

```cpp
// 检查存放密钥的内存页是否被标记为 PAGE_EXECUTE_READWRITE (异常)
// 正常应为 PAGE_READWRITE
// 异常 → 有人映射了恶意页 → 自毁
```

### 6.3 调用栈完整性

```cpp
// RtlCaptureStackBackTrace 取调用栈
// 比较预期调用链 vs 实际调用链
// 意外帧 = inline hook / VEH 劫持 → 返回垃圾数据
```

---

## 7. 主流 & 非主流调试器覆盖

| 调试器 | 特性 | 针对性检测 |
|---|---|---|
| **x64dbg / OllyDbg** | 用户态 ring3，PEB / INT3 / 硬件断点 | PEB + DR0~DR3 + 0xCC 扫描 + 窗口类名/进程名 |
| **IDA Pro (调试器)** | 远程调试 / 本地调试 | DebugPort + ProcessDebugObjectHandle |
| **WinDbg** | 内核/用户态双模 | SystemKernelDebugger + DebugPort |
| **Cheat Engine** | 用户态，专攻游戏/应用 | 进程名 (`cheatengine-x86_64.exe`) + 窗口类名 + VEH 链扫描 |
| **Frida** | 动态插桩，inject .dylib/.dll | DLL 名 (`frida-agent*.dll`) + 命名管道 `\\.\pipe\frida-*` |
| **TitanHide** | 内核反反调试驱动 | SystemKernelDebugger 绕过检测 → 用计时 RDTSC 兜底 |
| **ScyllaHide** | 用户态 hook 各种反调函数 | 不直接调用 IsDebuggerPresent，改用内联 asm 读 PEB |
| **HyperDbg** | 基于 VT-x 虚拟化 | EPT hook 检测困难 → RDTSC 时间 + 硬件断点 (VMCS 不会暴露给 DR) |
| **dbghelp 静态分析** | 非运行时，符号/PDB 泄露 | Release 不发布 PDB / 去除导出符号 |

---

## 8. 实施阶段

### Phase 1: 基础防线（本次）

| 文件 | 新增内容 |
|---|---|
| `src/PeanutClient/sdk/anti_debug.h` | 反调试工具宏 + 内联函数 |
| `src/PeanutClient/sdk/anti_debug.cpp` | 全量检测实现 (PEB/DR/INT3/DLL/时间) |
| `src/PeanutGUI/main.cpp` | wWinMain 首行插入 `AntiDebug::StartupGuard()` |
| `src/PeanutClient/sdk/security_runtime.cpp` | watchdog 线程 + Layer 1 运行时守卫 |
| `src/PeanutClient/sdk/peanut_secure_client.cpp` | 每个 API 入口插入 `ANTIDBG_API_GUARD()` |
| `src/PeanutClient/crypto/wy_cipher.cpp` | 加密前检查全局安全标志 + 内存页验证 |
| `src/PeanutClient/crypto/wy_rsa.cpp` | 同上 |

### Phase 2: 深度加固（后续）

- 代码段 CRC 自校验（编译期注入摘要）
- 反 EPT hook 检测
- 异常处理链 (VEH) 完整性验证
- 网络层：心跳包内含反调状态码，服务端可主动撤销令牌

### Phase 3: 加壳后保护（部署前）

- VMProtect 导入保护（IAT 加密）
- VMProtect 内存保护（防 dump）
- VMProtect 反调试选项启用
- 剥离所有调试符号 + PDB

---

## 9. 关键设计决策（待确认）

| 决策点 | 选项 A | 选项 B | 建议 |
|---|---|---|---|
| 检测到调试器后行为 | 静默退出 (ExitProcess) | 假运行 + 间歇性异常 (浪费攻击者时间) | 选项 B（干扰更大） |
| watchdog 线程隐蔽性 | 独立 CreateThread | 伪装成工作线程 / 定时器回调 | 独立线程 + 随机名称 |
| 字符串混淆 | 编译期 XOR 宏 | 运行时栈上构造 | 编译期 XOR（无运行时开销） |
| 检测失败是否自毁密钥 | 立即自毁 | 延迟 5~10s 后自毁 | 立即（Fail-Fast） |

---

## 10. API 设计预览

```cpp
// anti_debug.h — 公共接口

namespace peanut { namespace security { namespace antidebug {

// 启动一次性检测 (Layer 0), 返回 true = 安全
bool StartupGuard();

// 启动 watchdog 线程 (Layer 1), 失败回调 = 清理线程
void StartWatchdog(std::function<void()> on_threat);

// 停止 watchdog
void StopWatchdog();

// 快速轻量检查 (Layer 2 API 入口用), 返回 true = 安全
bool QuickCheck();

// 全局安全标志: Layer 1 检测到威胁时置位, Layer 3 加密层读取
bool IsSafe();
void MarkCompromised();

// 反调试器附加 (自调试)
bool PreventDebuggerAttach();

}}} // namespace
```

---

## 11. 编译控制

```cpp
// 所有反调代码包裹:
#ifdef PEANUT_RELEASE
  // 反调逻辑
#else
  // Debug 构建空实现, 不影响调试体验
#endif
```

在 `.vcxproj` Release 配置中定义 `PEANUT_RELEASE` 宏（`VM_PROTECT_ACTIVE` 同级）。

---

*本规划文档为设计草案，具体实现细节以代码为准。*
