// ============================================================
// Peanut WLYZ SDK — IAT 运行时动态解析 (DJB2 hash 查表)
// 对抗: IDA / PE-Bear / DIE 导入表静态分析
// 原理: 编译期 hash API 名 → 运行时 GetProcAddress 查表
// ============================================================

#pragma once

#if defined(PEANUT_RELEASE) || defined(VM_PROTECT_ACTIVE)

#include <windows.h>

namespace peanut { namespace security { namespace iat {

// ═══════════════════════════════════════════════════════════
//  编译期 DJB2 Hash (C++14 constexpr)
// ═══════════════════════════════════════════════════════════

constexpr DWORD HashDJB2(const char* str, DWORD h = 5381) {
    return (*str == '\0') ? h : HashDJB2(str + 1, ((h << 5) + h) + static_cast<BYTE>(*str));
}

// 方便宏: HASH_API("CreateThread") → 编译期常量
#define HASH_API(name) peanut::security::iat::HashDJB2(name)

// 模块名 hash (kernel32.dll, ntdll.dll, user32.dll 等)
constexpr DWORD MODULE_KERNEL32  = HashDJB2("kernel32.dll");
constexpr DWORD MODULE_NTDLL     = HashDJB2("ntdll.dll");
constexpr DWORD MODULE_USER32    = HashDJB2("user32.dll");
constexpr DWORD MODULE_ADVAPI32  = HashDJB2("advapi32.dll");
constexpr DWORD MODULE_PSAPI     = HashDJB2("psapi.dll");

// ═══════════════════════════════════════════════════════════
//  运行时: Hash → Module → GetProcAddress
// ═══════════════════════════════════════════════════════════

// 内部: 字符串 hash 查找模块句柄
HMODULE FindModuleByHash(DWORD hash);

// 内部: 模块 hash + 函数 hash → 函数指针
FARPROC ResolveByHash(DWORD moduleHash, DWORD funcHash);

// ═══════════════════════════════════════════════════════════
//  IAT 条目表 (由构建脚本生成, 或手动编写)
// ═══════════════════════════════════════════════════════════

struct IATResolveEntry {
    DWORD  moduleHash;
    DWORD  funcHash;
    void** ppfnTarget;   // 指向函数指针变量的指针
};

// 遍历表, 逐项解析
// 返回 false 的项目表示解析失败 (模块/函数不存在)
int ResolveIATTable(const IATResolveEntry* table, size_t count);

// ═══════════════════════════════════════════════════════════
//  懒加载包装: 首次调用时解析
// ═══════════════════════════════════════════════════════════

// 用法示例:
//
//   static void* s_pLoadLibraryA = nullptr;
//   auto fn = IAT_LAZY(s_pLoadLibraryA, MODULE_KERNEL32, HASH_API("LoadLibraryA"));
//   return reinterpret_cast<decltype(&LoadLibraryA)>(fn)("user32.dll");
//
#define IAT_LAZY(cache, modHash, funcHash) \
    ([](void*& c, DWORD m, DWORD f) -> FARPROC { \
        if (!c) c = ::peanut::security::iat::ResolveByHash(m, f); \
        return reinterpret_cast<FARPROC>(c); \
    }(cache, modHash, funcHash))

}}} // namespace

#else
namespace peanut { namespace security { namespace iat {
constexpr DWORD HashDJB2(const char* str, DWORD h = 5381) {
    return (*str == '\0') ? h : HashDJB2(str + 1, ((h << 5) + h) + static_cast<BYTE>(*str));
}
#define HASH_API(name) 0  // Debug 下不用 hash
constexpr DWORD MODULE_KERNEL32 = 0;
constexpr DWORD MODULE_NTDLL    = 0;
constexpr DWORD MODULE_USER32   = 0;
constexpr DWORD MODULE_ADVAPI32 = 0;
constexpr DWORD MODULE_PSAPI    = 0;
inline HMODULE FindModuleByHash(DWORD) { return GetModuleHandleW(nullptr); }
inline FARPROC ResolveByHash(DWORD, DWORD) { return nullptr; }
struct IATResolveEntry { DWORD mod; DWORD fn; void** p; };
inline int ResolveIATTable(const IATResolveEntry*, size_t) { return 0; }
#define IAT_LAZY(c, m, f) __noop()
}}}
#endif
