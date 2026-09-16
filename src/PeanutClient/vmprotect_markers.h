// VMProtect 标记宏 — 未启用 VM_PROTECT_ACTIVE 时为空，仅供加壳工具识别
// 用法:
//   { VMProtectScope scope("FuncName"); ... }  // 推荐：任意 return 都会 End
//   或 VMProtectBeginUltra("x"); ... VMProtectEnd();
#pragma once

#ifdef VM_PROTECT_ACTIVE
#include <VMProtectSDK.h>
#else
#define VMProtectBegin(name)
#define VMProtectEnd()
#define VMProtectBeginVirtualization(name)
#define VMProtectBeginMutation(name)
#define VMProtectBeginUltra(name)
#define VMProtectBeginVirtualizationLockByKey(name)
#define VMProtectBeginUltraLockByKey(name)
#endif

// RAII：保证每条返回路径都调用 VMProtectEnd（真 VMP 时配对正确）
struct VMProtectScope {
    explicit VMProtectScope(const char* name) {
        (void)name;
        VMProtectBeginUltra(name);
    }
    ~VMProtectScope() { VMProtectEnd(); }
    VMProtectScope(const VMProtectScope&) = delete;
    VMProtectScope& operator=(const VMProtectScope&) = delete;
};
