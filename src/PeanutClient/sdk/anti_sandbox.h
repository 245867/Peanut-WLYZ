// ============================================================
// Peanut WLYZ SDK — 沙箱 / 分析环境检测 (不含 VM 检测)
// 不对抗: VMware/VirtualBox 等合法虚拟机
// 对抗: 自动化分析平台 (sandbox/沙箱/低交互环境)
// 原理: 运行时间太短 / 屏幕分辨率过小 / 无用户交互 / CPU 核心数异常
// ============================================================

#pragma once

#if defined(PEANUT_RELEASE) || defined(VM_PROTECT_ACTIVE)

namespace peanut { namespace security { namespace sandbox {

// 快速检测 (StartupGuard阶段可用, 仅静态指标)
bool DetectSandboxQuick();

// 慢速/动态检测 (需要等待运行时间积累, watchdog阶段)
bool DetectSandboxSlow();

// 综合检测 (快速+慢速)
bool DetectSandbox();

void InitSandboxDetection();

}}} // namespace

#else
namespace peanut { namespace security { namespace sandbox {
inline bool DetectSandboxQuick() { return false; }
inline bool DetectSandboxSlow() { return false; }
inline bool DetectSandbox() { return false; }
inline void InitSandboxDetection() {}
}}}
#endif
