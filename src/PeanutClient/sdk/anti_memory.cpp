// ============================================================
// Peanut WLYZ SDK — 内存页属性巡检 实现
// ============================================================

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include "anti_memory.h"

#if defined(PEANUT_RELEASE) || defined(VM_PROTECT_ACTIVE)

namespace peanut { namespace security { namespace memguard {

bool DetectWritableCodePages() {
    HMODULE base = GetModuleHandleW(nullptr);
    if (!base) return false;

    auto* dos = reinterpret_cast<PIMAGE_DOS_HEADER>(base);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;

    auto* nt = reinterpret_cast<PIMAGE_NT_HEADERS>(
        reinterpret_cast<BYTE*>(base) + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return false;

    auto* sec = IMAGE_FIRST_SECTION(nt);
    WORD count = nt->FileHeader.NumberOfSections;

    for (WORD i = 0; i < count; ++i) {
        // 只检查可执行段
        if (!(sec[i].Characteristics & IMAGE_SCN_MEM_EXECUTE))
            continue;

        BYTE* secBase = reinterpret_cast<BYTE*>(base) + sec[i].VirtualAddress;
        BYTE* secEnd  = secBase + sec[i].Misc.VirtualSize;

        MEMORY_BASIC_INFORMATION mbi;
        for (BYTE* p = secBase; p < secEnd; p += mbi.RegionSize) {
            if (!VirtualQuery(p, &mbi, sizeof(mbi)))
                break;

            // 可执行段不允许可写
            DWORD protect = mbi.Protect;
            // 注意: PAGE_EXECUTE_WRITECOPY 也是可写的 (copy-on-write)
            if (protect & (PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) {
                return true;  // ⚠️ 有人在执行段上开了写权限
            }
        }
    }
    return false;
}

}}} // namespace

#endif
