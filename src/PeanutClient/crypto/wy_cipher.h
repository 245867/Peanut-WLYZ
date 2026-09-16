// ============================================================
// WY-Cipher — 自研对称加密算法
// 256-bit 密钥 · 256-bit 块 · Feistel 网络 32 轮
// 自定义 S-Box + P-Box + 密钥扩展
// 零外部依赖 · 纯 C++
// ============================================================

#pragma once

#include <cstdint>
#include <cstddef>
#include <string>
#include <vector>

namespace wy {

// ── 常量 ───────────────────────────────────────────────────
constexpr size_t WY_CIPHER_KEY_SIZE   = 32;   // 256-bit 密钥
constexpr size_t WY_CIPHER_BLOCK_SIZE = 32;   // 256-bit 块
constexpr size_t WY_CIPHER_ROUNDS     = 32;   // 32 轮 Feistel
constexpr size_t WY_CIPHER_IV_SIZE    = 16;   // 128-bit IV (用于 CBC)

/**
 * @brief WY-Cipher 密钥表
 */
struct wy_cipher_key {
    uint32_t round_keys[WY_CIPHER_ROUNDS][8];  // 每轮 8 个 32-bit 子密钥
    uint32_t sbox[256];                        // 此密钥派生的 S-Box
};

/**
 * @brief 从原始密钥派生轮密钥表
 *
 * @param raw_key 32 字节原始密钥
 * @param out_key 输出: 密钥表
 */
void wy_cipher_key_schedule(const uint8_t* raw_key, wy_cipher_key* out_key);

/**
 * @brief 加密一个 256-bit (32字节) 块
 *
 * @param key  密钥表
 * @param src  明文, 32 字节 (会被原地修改为密文)
 */
void wy_cipher_encrypt_block(const wy_cipher_key* key, uint8_t* block);

/**
 * @brief 解密一个 256-bit (32字节) 块
 *
 * @param key  密钥表
 * @param src  密文, 32 字节 (会被原地修改为明文)
 */
void wy_cipher_decrypt_block(const wy_cipher_key* key, uint8_t* block);

// ── CBC 模式 ───────────────────────────────────────────────

/**
 * @brief CBC 模式加密
 *
 * @param key   密钥表
 * @param iv    16 字节初始向量
 * @param data  明文输入
 * @param len   数据长度 (必须是 32 的倍数, 自动 PKCS7 填充首个块)
 * @return      密文 (长度 = 原始长度 + 填充)
 */
std::vector<uint8_t> wy_cbc_encrypt(const wy_cipher_key* key,
                                     const uint8_t* iv, const uint8_t* data, size_t len);

/**
 * @brief CBC 模式解密
 *
 * @param key   密钥表
 * @param iv    16 字节初始向量
 * @param data  密文输入
 * @param len   数据长度 (必须是 32 的倍数)
 * @return      明文 (自动去除 PKCS7 填充)
 */
std::vector<uint8_t> wy_cbc_decrypt(const wy_cipher_key* key,
                                     const uint8_t* iv, const uint8_t* data, size_t len);

/**
 * @brief 生成随机 256-bit 密钥
 *
 * @return 32 字节随机密钥的 hex 字符串 (64 字符)
 */
std::string wy_cipher_generate_key_hex();

} // namespace wy
