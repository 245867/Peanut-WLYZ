# Phase 2 逆向防护强化 — 进度

## 状态: 所有模块实现+集成完成，13/13 编译通过

## 已完成

| 序号 | 模块 | 优先级 | 状态 |
|------|------|--------|------|
| 1 | anti_tls.cpp/h | P0 | ✅ 实现+集成 (TLS callback 在 wWinMain 前执行) |
| 2 | anti_pe.cpp/h | P0 | ✅ 实现+集成 (PE头运行时自擦除, StartupGuard内调用) |
| 3 | anti_iat.cpp/h | P1 | ✅ 实现 (IAT hash运行时解析, 可选模块) |
| 4 | anti_memory.cpp/h | P1 | ✅ 实现+集成 (内存页属性巡检, watchdog内调用) |
| 5 | anti_stack.cpp/h | P1 | ✅ 实现+集成 (调用栈验证, QuickCheck内调用) |
| 6 | anti_registry.cpp/h | P2 | ✅ 实现+集成 (IFEO/AeDebug检测, watchdog内调用) |
| 7 | anti_veh.cpp/h | P2 | ✅ 实现+集成 (VEH链完整性, watchdog内调用) |
| 8 | anti_flow.h | P3 | ✅ 实现 (控制流混淆宏, 编译后可接入) |
| 9 | anti_sandbox.cpp/h | P3 | ✅ 实现+集成 (QuickCheck+StartupGuard, 不检测VMware) |

## 集成点

- **StartupGuard**: PE头自擦除 + 注册表检测 + 沙箱慢速检测
- **Watchdog (PopulateReport)**: 内存页属性 + VEH链
- **QuickCheck**: 调用栈验证 + 沙箱快速检测
- **TLS callback**: 独立入口检测 (PEB/DebugPort/NtGlobalFlag), wWinMain前执行

## 编译验证

- Peanut_WLYZ build_all.ps1: 13/13 PASS (2026-07-31)
- 0 errors, 0 warnings

## 待办

- 双仓库回传至 方案C
- 真机/沙箱环境功能测试