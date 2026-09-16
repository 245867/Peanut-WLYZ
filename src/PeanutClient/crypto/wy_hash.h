// ============================================================
// WY-Hash — 自研 256-bit 密码学哈希函数
// Merkle-Damgård 结构 · 自定义压缩函数
// 零外部依赖 · 纯 C++ 实现
// ============================================================

#pragma once

#include <cstdint>
#include <cstddef>
#include <string>

namespace wy {

// ── 常量 ───────────────────────────────────────────────────
constexpr size_t WY_HASH_BLOCK_SIZE  = 64;    // 512-bit 块
constexpr size_t WY_HASH_OUTPUT_SIZE = 32;    // 256-bit 输出
constexpr size_t WY_HASH_STATE_SIZE  = 8;     // 8 个 32-bit 状态字

/**
 * @brief WY-Hash 上下文结构
 *
 * 使用自定义 Merkle-Damgård 结构：
 *   - 消息分块: 512-bit
 *   - 压缩函数: 80 轮自定义变换
 *   - 输出: 256-bit 摘要
 */
struct wy_hash_ctx {
    uint32_t state[WY_HASH_STATE_SIZE];  // 当前哈希状态
    uint64_t total_bytes;                // 已处理总字节数
    uint8_t  buffer[WY_HASH_BLOCK_SIZE]; // 数据缓冲
    size_t   buf_used;                   // 缓冲区已用字节
};

/**
 * @brief 初始化哈希上下文
 */
void wy_hash_init(wy_hash_ctx* ctx);

/**
 * @brief 追加数据（支持增量更新）
 */
void wy_hash_update(wy_hash_ctx* ctx, const uint8_t* data, size_t len);

/**
 * @brief 完成哈希计算，输出 256-bit 摘要
 *
 * @param ctx   哈希上下文（调用后不可再用）
 * @param digest 输出缓冲区，至少 32 字节
 */
void wy_hash_final(wy_hash_ctx* ctx, uint8_t* digest);

// ── 便捷接口 ───────────────────────────────────────────────

/**
 * @brief 一次性哈希计算
 *
 * @param data   输入数据
 * @param len    数据长度
 * @param digest 输出: 32 字节摘要
 */
inline void wy_hash(const uint8_t* data, size_t len, uint8_t* digest) {
    wy_hash_ctx ctx;
    wy_hash_init(&ctx);
    wy_hash_update(&ctx, data, len);
    wy_hash_final(&ctx, digest);
}

/**
 * @brief HMAC-WY256 — 基于 WY-Hash 的消息认证码
 *
 * 标准 HMAC 构造:
 *   o_key_pad = key ⊕ 0x5C5C...
 *   i_key_pad = key ⊕ 0x3636...
 *   HMAC = H(o_key_pad || H(i_key_pad || message))
 *
 * @param key     密钥
 * @param key_len 密钥长度
 * @param data    消息数据
 * @param len     消息长度
 * @param mac     输出: 32 字节 MAC
 */
void wy_hmac(const uint8_t* key, size_t key_len,
             const uint8_t* data, size_t len,
             uint8_t* mac);

/**
 * @brief HKDF 密钥派生 (基于 HMAC-WY256)
 *
 * HKDF-Expand:
 *   T(0) = ""
 *   T(i) = HMAC(prk, T(i-1) || info || byte(i))  for i = 1..N
 *
 * @param prk      伪随机密钥 (来自 Extract 步骤)
 * @param prk_len  PRK 长度
 * @param info     上下文信息
 * @param info_len 上下文长度
 * @param out      输出派生密钥
 * @param out_len  需要的输出长度
 */
void wy_hkdf_expand(const uint8_t* prk, size_t prk_len,
                    const uint8_t* info, size_t info_len,
                    uint8_t* out, size_t out_len);

/**
 * @brief HKDF-Extract + Expand 完整流程
 *
 * HKDF-Extract: PRK = HMAC(salt, ikm)
 * HKDF-Expand:  OKM = HKDF-Expand(PRK, info, L)
 *
 * @param ikm      输入密钥材料
 * @param ikm_len  IKM 长度
 * @param salt     盐（可null，默认全零）
 * @param salt_len 盐长度
 * @param info     上下文信息
 * @param info_len 上下文长度
 * @param out      输出密钥
 * @param out_len  输出长度
 */
void wy_hkdf(const uint8_t* ikm, size_t ikm_len,
             const uint8_t* salt, size_t salt_len,
             const uint8_t* info, size_t info_len,
             uint8_t* out, size_t out_len);

// ── 工具函数 ───────────────────────────────────────────────

/**
 * @brief 将摘要转为 hex 字符串
 */
std::string wy_hash_to_hex(const uint8_t* digest);

/**
 * @brief 常量时间比较（防时序攻击）
 */
bool wy_const_time_eq(const uint8_t* a, const uint8_t* b, size_t len);

} // namespace wy
