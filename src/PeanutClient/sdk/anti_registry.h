// ============================================================
// Peanut WLYZ SDK — 注册表 & 系统配置检测
// 对抗: IFEO 调试器自动启动 / AeDebug / 系统分析工具
// 不检测: VMware (客户合法需求)
// ============================================================

#pragma once

#if defined(PEANUT_RELEASE) || defined(VM_PROTECT_ACTIVE)

namespace peanut { namespace security { namespace registry {

// IFEO 检查: 是否有人给我们的 exe 设了 Debugger 注册表项
bool DetectIfeoDebugger();

// AeDebug 检查: 系统崩溃调试器是否被设
bool DetectAeDebug();

// 综合检查: 任一命中返回 true
bool DetectRegistryTampering();

}}} // namespace

#else
namespace peanut { namespace security { namespace registry {
inline bool DetectIfeoDebugger() { return false; }
inline bool DetectAeDebug() { return false; }
inline bool DetectRegistryTampering() { return false; }
}}}
#endif
