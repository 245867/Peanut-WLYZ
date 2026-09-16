// ============================================================
// Peanut WLYZ SDK — IAT 运行时动态解析 实现
// ============================================================

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include "anti_iat.h"

#if defined(PEANUT_RELEASE) || defined(VM_PROTECT_ACTIVE)

namespace peanut { namespace security { namespace iat {

static DWORD HashDJB2_Runtime(const wchar_t* str) {
    DWORD h = 5381;
    while (*str) {
        wchar_t c = towlower(*str);
        h = ((h << 5) + h) + static_cast<BYTE>(c);
        ++str;
    }
    return h;
}

static DWORD HashDJB2_RuntimeA(const char* str) {
    DWORD h = 5381;
    while (*str) {
        h = ((h << 5) + h) + static_cast<BYTE>(*str);
        ++str;
    }
    return h;
}

HMODULE FindModuleByHash(DWORD targetHash) {
    static const wchar_t* kModuleNames[] = {
        L"kernel32.dll", L"ntdll.dll", L"user32.dll",
        L"advapi32.dll", L"psapi.dll", L"kernelbase.dll"
    };
    static const DWORD kModuleHashes[] = {
        MODULE_KERNEL32, MODULE_NTDLL, MODULE_USER32,
        MODULE_ADVAPI32, MODULE_PSAPI,
        HashDJB2("kernelbase.dll")
    };
    for (int i = 0; i < 6; ++i) {
        if (kModuleHashes[i] == targetHash) {
            HMODULE h = GetModuleHandleW(kModuleNames[i]);
            if (h) return h;
        }
    }
    return nullptr;
}

FARPROC ResolveByHash(DWORD moduleHash, DWORD funcHash) {
    HMODULE hMod = FindModuleByHash(moduleHash);
    if (!hMod) return nullptr;

    auto* dos = reinterpret_cast<PIMAGE_DOS_HEADER>(hMod);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return nullptr;

    auto* nt = reinterpret_cast<PIMAGE_NT_HEADERS>(
        reinterpret_cast<BYTE*>(hMod) + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return nullptr;

    auto& expDir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (expDir.Size == 0) return nullptr;

    auto* exp = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(
        reinterpret_cast<BYTE*>(hMod) + expDir.VirtualAddress);

    auto* names   = reinterpret_cast<DWORD*>(reinterpret_cast<BYTE*>(hMod) + exp->AddressOfNames);
    auto* ordinals= reinterpret_cast<WORD*>(reinterpret_cast<BYTE*>(hMod) + exp->AddressOfNameOrdinals);
    auto* funcs   = reinterpret_cast<DWORD*>(reinterpret_cast<BYTE*>(hMod) + exp->AddressOfFunctions);

    for (DWORD i = 0; i < exp->NumberOfNames; ++i) {
        const char* name = reinterpret_cast<const char*>(reinterpret_cast<BYTE*>(hMod) + names[i]);
        if (HashDJB2_RuntimeA(name) == funcHash) {
            return reinterpret_cast<FARPROC>(
                reinterpret_cast<BYTE*>(hMod) + funcs[ordinals[i]]);
        }
    }
    return nullptr;
}

int ResolveIATTable(const IATResolveEntry* table, size_t count) {
    int failed = 0;
    for (size_t i = 0; i < count; ++i) {
        if (!table[i].ppfnTarget) continue;
        FARPROC fn = ResolveByHash(table[i].moduleHash, table[i].funcHash);
        if (fn) {
            *table[i].ppfnTarget = fn;
        } else {
            ++failed;
        }
    }
    return failed;
}

}}} // namespace

#endif
