// ============================================================
// WY-Random — 安全随机数生成
// 自研加密库组件，唯一系统依赖: Windows CryptoAPI (CryptGenRandom)
// 支持系统: Windows XP SP3 及以上
// ============================================================

#pragma once

#include <cstdint>
#include <cstddef>

namespace wy {

/**
 * @brief 填充指定长度的密码学安全随机字节
 *
 * 使用 Windows CryptoAPI 的 CryptGenRandom 作为熵源。
 * 这是整个自研加密库中唯一的系统API依赖。
 *
 * @param buf  输出缓冲区
 * @param len  需要的随机字节数
 * @return     成功写入的字节数（通常等于 len），失败返回 0
 */
size_t wy_random_bytes(uint8_t* buf, size_t len);

/**
 * @brief 生成 32-bit 安全随机整数
 */
uint32_t wy_random_u32();

/**
 * @brief 生成 64-bit 安全随机整数
 */
uint64_t wy_random_u64();

/**
 * @brief 生成范围 [0, max) 内的安全随机整数
 */
uint64_t wy_random_range(uint64_t max);

} // namespace wy
