// ============================================================
// Peanut WLYZ SDK — 反调试 / 反逆向模块 (anti_debug)
//
// 四层纵深防御:
//   Layer 0: StartupGuard()     — 入口一次性全量检测
//   Layer 1: StartWatchdog()    — 独立线程运行时守卫
//   Layer 2: QuickCheck()       — API 入口轻量检测
//   Layer 3: IsSafe() / MarkCompromised() — 加密层安全标志
//
// 所有检测仅在 PEANUT_RELEASE 下生效，Debug 构建全跳过。
// ============================================================
#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <atomic>
#include <functional>
#include <string>
#include <vector>

namespace peanut { namespace security { namespace antidebug {

// ── 公共接口 ────────────────────────────────────────────────

/// Layer 0: 一次性启动检测。返回 true = 通过 / false = 检测到威胁（已退出）。
/// 调用时机：wWinMain / main 第一行，VMProtect 标记之前。
/// 检测到威胁直接 TerminateProcess，不返回。
bool StartupGuard();

/// Layer 1: 启动独立 watchdog 线程。
/// on_threat 回调在检测到威胁时被调用（可能在任意线程上下文执行）。
void StartWatchdog(std::function<void()> on_threat);

/// 停止 watchdog 线程（程序退出前调用）。
void StopWatchdog();

/// Layer 2: 快速轻量检测，供 SDK API 入口调用。
/// 返回 true = 安全，false = 可能存在调试器。
bool QuickCheck();

/// Layer 3: 全局安全标志，供加密层读取。
/// watchdog 检测到威胁时置 false，加密/解密前应检查此标志。
bool IsSafe();

/// 标记为已被入侵（加密层检测到异常时调用）。
void MarkCompromised();

/// 反调试器附加: 让自己成为自己的调试器 / 断开调试端口。
/// 调用后外部调试器无法附加。
bool PreventDebuggerAttach();

/// 检测结果汇总（用于诊断 / 日志）
struct DetectionReport {
    bool debugger_present   = false;
    bool debug_port         = false;
    bool kernel_debugger    = false;
    bool nt_global_flag     = false;
    bool hardware_bp        = false;
    bool int3_patch         = false;
    bool suspicious_dll     = false;
    bool suspicious_parent  = false;
    bool timing_anomaly     = false;
    int  score              = 0;
    std::string details;
};

/// 执行完整检测但不退出，返回报告（调试用）。
DetectionReport FullDetection();

}}} // namespace
