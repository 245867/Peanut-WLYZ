// ============================================================
// Peanut WLYZ SDK — VEH 链完整性检测 实现
// ============================================================

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include "anti_veh.h"

#if defined(PEANUT_RELEASE) || defined(VM_PROTECT_ACTIVE)

namespace peanut { namespace security { namespace vehguard {

static volatile LONG g_veh_test_called = 0;

static LONG CALLBACK VehIntegrityProbe(PEXCEPTION_POINTERS) {
    // 原子写: 我们的 VEH 被调用了 → 链顶还在
    InterlockedExchange(&g_veh_test_called, 1);
    return EXCEPTION_CONTINUE_SEARCH;  // 继续传递给下一个 handler
}

bool DetectVehChainTampering() {
    g_veh_test_called = 0;

    // 注册 VEH 在第一个位置 (First=1)
    PVOID handle = AddVectoredExceptionHandler(1, VehIntegrityProbe);
    if (!handle) return true;  // 注册失败 → 异常

    // 触发一个自定义异常 (不用 0xEEEE → 避免杀软误报)
    __try {
        RaiseException(0xEEEE0001, EXCEPTION_NONCONTINUABLE, 0, nullptr);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        // 预期: 我们的 VEH 被调用 → EXCEPTION_CONTINUE_SEARCH → 到这儿
    }

    RemoveVectoredExceptionHandler(handle);

    // 如果 g_veh_test_called != 1 → 我们的 VEH 被跳过了
    return (InterlockedCompareExchange(&g_veh_test_called, 0, 0) != 1);
}

}}} // namespace

#endif
