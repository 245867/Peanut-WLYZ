// ============================================================
// Peanut WLYZ SDK — 调用栈验证
// 对抗: Frida Interceptor.attach / inline hook
// 原理: _ReturnAddress() 必须在自身 .text 段内
// ============================================================

#pragma once

#if defined(PEANUT_RELEASE) || defined(VM_PROTECT_ACTIVE)

namespace peanut { namespace security { namespace stackguard {

// 验证调用者返回地址在 .text 段内 → 防止外部 trampoline
bool VerifyCallerInText();

// 在关键函数入口使用的宏:
//   STACKGUARD_VERIFY();  // 放在函数第一行

}}} // namespace

#define STACKGUARD_VERIFY() \
    do { if (!::peanut::security::stackguard::VerifyCallerInText()) { \
        ::peanut::security::antidebug::MarkCompromised(); \
    } } while(0)

#else
namespace peanut { namespace security { namespace stackguard {
inline bool VerifyCallerInText() { return true; }
}}}
#define STACKGUARD_VERIFY() ((void)0)
#endif
