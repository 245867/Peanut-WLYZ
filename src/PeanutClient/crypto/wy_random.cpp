// ============================================================
// WY-Random — 安全随机数生成实现
// 唯一系统依赖: Windows CryptoAPI (CryptGenRandom)
// 支持系统: Windows XP SP3 及以上
// ============================================================

#include "wy_random.h"
#include "../vmprotect_markers.h"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <wincrypt.h>

#pragma comment(lib, "advapi32.lib")

namespace wy {

// ── 全局 CSP 句柄（懒初始化，进程级复用） ────────────────
static HCRYPTPROV g_hProv = 0;
static bool        g_init_ok = false;

static bool ensure_prov() {
    if (g_init_ok) return true;
    if (!CryptAcquireContextW(&g_hProv, nullptr, nullptr,
                               PROV_RSA_FULL,
                               CRYPT_VERIFYCONTEXT | CRYPT_SILENT)) {
        // 回退: 尝试创建新容器
        if (!CryptAcquireContextW(&g_hProv, nullptr, nullptr,
                                   PROV_RSA_FULL,
                                   CRYPT_NEWKEYSET | CRYPT_VERIFYCONTEXT | CRYPT_SILENT)) {
            return false;
        }
    }
    g_init_ok = true;
    return true;
}

size_t wy_random_bytes(uint8_t* buf, size_t len) {
    if (!buf || len == 0) return 0;
    if (!ensure_prov()) return 0;
    if (!CryptGenRandom(g_hProv, static_cast<DWORD>(len), buf))
        return 0;
    return len;
}

uint32_t wy_random_u32() {
    uint32_t val = 0;
    wy_random_bytes(reinterpret_cast<uint8_t*>(&val), sizeof(val));
    return val;
}

uint64_t wy_random_u64() {
    uint64_t val = 0;
    wy_random_bytes(reinterpret_cast<uint8_t*>(&val), sizeof(val));
    return val;
}

uint64_t wy_random_range(uint64_t max) {
    if (max <= 1) return 0;
    // 无偏采样: 拒绝超出均匀范围的值
    uint64_t limit = UINT64_MAX - (UINT64_MAX % max);
    for (;;) {
        uint64_t r = wy_random_u64();
        if (r < limit) return r % max;
    }
}

} // namespace wy
