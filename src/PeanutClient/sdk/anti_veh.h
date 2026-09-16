// ============================================================
// Peanut WLYZ SDK — VEH 链完整性检测
// 对抗: 攻击者注册 VEH 拦截我们的异常检测
// 原理: 注册 VEH 在第一个位置, 触发特殊异常, 验证我们的 VEH 被调用
// ============================================================

#pragma once

#if defined(PEANUT_RELEASE) || defined(VM_PROTECT_ACTIVE)

namespace peanut { namespace security { namespace vehguard {

// 检测 VEH 链是否被篡改 (有人在我们前面注册了 VEH)
// 返回 true = 被篡改 (不安全)
bool DetectVehChainTampering();

}}} // namespace

#else
namespace peanut { namespace security { namespace vehguard {
inline bool DetectVehChainTampering() { return false; }
}}}
#endif
