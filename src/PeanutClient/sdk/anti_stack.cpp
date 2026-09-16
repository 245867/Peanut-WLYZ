// ============================================================
// Peanut WLYZ SDK — 调用栈验证 实现
// ============================================================

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include "anti_stack.h"

#if defined(PEANUT_RELEASE) || defined(VM_PROTECT_ACTIVE)

namespace peanut { namespace security { namespace stackguard {

// 缓存 .text 段范围 (只在第一次调用时计算)
static bool GetTextRange(BYTE*& outStart, BYTE*& outEnd) {
    static BYTE* s_textStart = nullptr;
    static BYTE* s_textEnd   = nullptr;
    static bool  s_inited    = false;

    if (!s_inited) {
        HMODULE base = GetModuleHandleW(nullptr);
        if (base) {
            auto* dos = reinterpret_cast<PIMAGE_DOS_HEADER>(base);
            if (dos->e_magic == IMAGE_DOS_SIGNATURE) {
                auto* nt = reinterpret_cast<PIMAGE_NT_HEADERS>(
                    reinterpret_cast<BYTE*>(base) + dos->e_lfanew);
                auto* sec = IMAGE_FIRST_SECTION(nt);
                for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
                    if (memcmp(sec[i].Name, ".text", 5) == 0) {
                        s_textStart = reinterpret_cast<BYTE*>(base) + sec[i].VirtualAddress;
                        s_textEnd   = s_textStart + sec[i].Misc.VirtualSize;
                        break;
                    }
                }
            }
        }
        s_inited = true;
    }
    outStart = s_textStart;
    outEnd   = s_textEnd;
    return s_textStart != nullptr;
}

bool VerifyCallerInText() {
    BYTE* start = nullptr;
    BYTE* end   = nullptr;
    if (!GetTextRange(start, end)) return true;  // 无法判断时不误杀

    // _ReturnAddress() 返回当前函数被调用者的返回地址
    // 注意: 这里返回的是 VerifyCallerInText 的调用者 → 即关键函数的返回地址
    // 我们需要再往上回溯一层 → 调用 VerifyCallerInText 的是关键函数本身
    // 所以关键函数的返回地址在关键函数的 caller 的代码段中

    // 用 _AddressOfReturnAddress() 获取栈上返回地址的位置
    // + sizeof(void*) 跳过当前帧 → 得到调用 VerifyCallerInText 的返回地址
    // 这是 VerifyCallerInText 的返回地址 (即关键函数中的 next instruction)
    // 这在 .text 内 → 但我们需要的是关键函数的 caller
    // 
    // 更准确的方法: RtlCaptureStackBackTrace
    // 取 2 级调用栈:
    //   [0] = VerifyCallerInText  ← 自身
    //   [1] = 关键函数            ← 应该在 .text 内
    //   [2] = 关键函数的调用者    ← 关键函数的返回地址在这里
    //
    // 但如果关键函数被 inline hook:
    //   [2] 指向 hook trampoline → 不在 .text 段 → 检测成功

    PVOID trace[3] = {};
    WORD captured = RtlCaptureStackBackTrace(0, 3, trace, nullptr);

    if (captured >= 3) {
        BYTE* callerRetAddr = reinterpret_cast<BYTE*>(trace[2]);
        // caller 的返回地址必须在 .text 内
        if (callerRetAddr >= start && callerRetAddr < end) {
            return true;
        }
        // 不在 .text → 来自外部 trampoline (Frida/detours 等)
        return false;
    }

    // 无法获取足够调用栈 → 不误判
    return true;
}

}}} // namespace

#endif
