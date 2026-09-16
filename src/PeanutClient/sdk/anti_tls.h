// ============================================================
// Peanut WLYZ SDK — TLS Callback 入口劫持
// 对抗: IDA/x64dbg WinMain 入口断点
// 原理: StartupGuard + InitNtFunctions 在 CRT 初始化前执行
// ============================================================

#pragma once

#if defined(PEANUT_RELEASE) || defined(VM_PROTECT_ACTIVE)

namespace peanut { namespace security { namespace tlsguard {

// TLS callback 版本的反调试启动 (不依赖 CRT)
// 返回 false = 检测到威胁, 调用方应 TerminateProcess
bool EarlyStartupCheck();

}}} // namespace

#else
namespace peanut { namespace security { namespace tlsguard {
inline bool EarlyStartupCheck() { return true; }
}}}
#endif
