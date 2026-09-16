// ============================================================
// Peanut WLYZ SDK — 内存页属性巡检
// 对抗: detours / minhook / 任何需要 PAGE_EXECUTE_READWRITE 的 hook 框架
// 巡检: .text 段所有页必须是 PAGE_EXECUTE_READ (不可写)
// ============================================================

#pragma once

#if defined(PEANUT_RELEASE) || defined(VM_PROTECT_ACTIVE)

namespace peanut { namespace security { namespace memguard {

// 巡检可执行页 — 发现 PAGE_EXECUTE_READWRITE 返回 true
bool DetectWritableCodePages();

// 在 watchdog 线程中周期性调用

}}} // namespace

#else
namespace peanut { namespace security { namespace memguard {
inline bool DetectWritableCodePages() { return false; }
}}}
#endif
