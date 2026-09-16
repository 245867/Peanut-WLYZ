// ============================================================
// Peanut WLYZ SDK — PE 头运行时自擦除
// 对抗: ProcessHacker / x64dbg / DIE dump 离线分析
// 擦除: MZ签名 / 区段名 / Debug Directory
// 保留: PE签名 + OptionalHeader (系统运行时仍需)
// ============================================================

#pragma once

#if defined(PEANUT_RELEASE) || defined(VM_PROTECT_ACTIVE)

namespace peanut { namespace security { namespace peguard {

// 在 wWinMain 末尾调用 (所有初始化完成后)
void ErasePEHeaders();

}}} // namespace

#else
// Debug → 空实现
namespace peanut { namespace security { namespace peguard {
inline void ErasePEHeaders() {}
}}}
#endif
