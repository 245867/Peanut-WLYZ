// ============================================================
// WY-RSA — 自研非对称加密（RSA 2048-bit）
// 自研大整数运算 · 零外部依赖
// 支持系统: Windows XP SP3 及以上
// ============================================================

#pragma once

#include <cstdint>
#include <cstddef>
#include <string>
#include <vector>

namespace wy {

// ── 大整数常量 ─────────────────────────────────────────────
constexpr size_t WY_RSA_BITS        = 2048;     // RSA 密钥长度
constexpr size_t WY_RSA_WORDS       = 64;       // 2048/32 = 64 个 uint32_t
constexpr size_t WY_RSA_BYTES       = 256;      // 2048/8
constexpr size_t WY_RSA_MAX_PLAIN   = 245;      // 最大明文长度 (预留 11 字节 PKCS#1 填充)

// ── 大整数类型 ─────────────────────────────────────────────

/**
 * @brief 大整数 (2048-bit)
 *
 * 使用 uint32_t 数组存储，word[0] 为最低有效字（小端序）。
 */
struct wy_bigint {
    uint32_t words[WY_RSA_WORDS];

    wy_bigint();
    explicit wy_bigint(uint32_t val);
    explicit wy_bigint(const uint8_t* bytes, size_t len);  // 大端字节
    explicit wy_bigint(const std::string& hex);

    // 导出
    std::string to_hex() const;
    std::vector<uint8_t> to_bytes() const;

    // 信息
    bool is_zero() const;
    bool is_one() const;
    bool is_even() const;
    int  bit_length() const;  // 有效比特位数

    // 比较
    bool operator==(const wy_bigint& other) const;
    bool operator!=(const wy_bigint& other) const;
    bool operator<(const wy_bigint& other) const;
    bool operator>(const wy_bigint& other) const;
    bool operator<=(const wy_bigint& other) const;
    bool operator>=(const wy_bigint& other) const;

    // 算术 (产生新值)
    wy_bigint operator+(const wy_bigint& other) const;
    wy_bigint operator-(const wy_bigint& other) const;
    wy_bigint operator*(const wy_bigint& other) const;
    wy_bigint operator/(const wy_bigint& other) const;
    wy_bigint operator%(const wy_bigint& other) const;

    // 原地算术
    wy_bigint& operator+=(const wy_bigint& other);
    wy_bigint& operator-=(const wy_bigint& other);

    // 移位
    wy_bigint operator<<(unsigned bits) const;
    wy_bigint operator>>(unsigned bits) const;

    // 位运算
    wy_bigint operator&(const wy_bigint& other) const;
    wy_bigint operator|(const wy_bigint& other) const;
    wy_bigint operator^(const wy_bigint& other) const;

    // 数论
    wy_bigint mod_pow(const wy_bigint& exponent, const wy_bigint& modulus) const;
    wy_bigint mod_inv(const wy_bigint& modulus) const;  // 模逆元 (扩展欧几里得)
    wy_bigint gcd(const wy_bigint& other) const;
    bool is_probable_prime(int iterations = 10) const;  // Fermat 素性测试
};

// ── RSA 密钥类型 ───────────────────────────────────────────

/**
 * @brief RSA 公钥
 */
struct wy_rsa_pubkey {
    wy_bigint n;   // 模数
    wy_bigint e;   // 公开指数 (默认 65537)
};

/**
 * @brief RSA 私钥
 */
struct wy_rsa_prikey {
    wy_bigint n;   // 模数
    wy_bigint d;   // 私有指数
    wy_bigint p;   // 素数 p
    wy_bigint q;   // 素数 q
};

/**
 * @brief RSA 密钥对
 */
struct wy_rsa_keypair {
    wy_rsa_pubkey pub;
    wy_rsa_prikey pri;
};

// ── RSA 接口 ───────────────────────────────────────────────

/**
 * @brief 生成 RSA 2048-bit 密钥对
 *
 * 算法流程:
 *   1. 随机生成两个 1024-bit 素数 p, q
 *   2. n = p * q
 *   3. φ(n) = (p-1)(q-1)
 *   4. 选择 e = 65537
 *   5. d = e⁻¹ mod φ(n)
 *
 * @return 密钥对
 */
wy_rsa_keypair wy_rsa_generate_keypair();

/**
 * @brief RSA 加密 (公钥)
 *
 * 使用 PKCS#1 v1.5 填充:
 *   EB = 00 || BT || PS || 00 || D
 *   其中 BT=02(加密), PS=随机非零字节 ≥8 字节
 *
 * @param plaintext  明文
 * @param plain_len  明文长度 (最大 245 字节)
 * @param pubkey     公钥
 * @return           密文 (256 字节)
 */
std::vector<uint8_t> wy_rsa_encrypt(const uint8_t* plaintext, size_t plain_len,
                                     const wy_rsa_pubkey* pubkey);

/**
 * @brief RSA 解密 (私钥)
 *
 * @param ciphertext 密文 (256 字节)
 * @param prikey     私钥
 * @return           明文
 */
std::vector<uint8_t> wy_rsa_decrypt(const uint8_t* ciphertext, size_t cipher_len,
                                     const wy_rsa_prikey* prikey);

/**
 * @brief RSA 签名 (私钥)
 *
 * @param data  待签名数据
 * @param len   数据长度
 * @param prikey 私钥
 * @return      签名 (256 字节)
 */
std::vector<uint8_t> wy_rsa_sign(const uint8_t* data, size_t len,
                                  const wy_rsa_prikey* prikey);

/**
 * @brief RSA 验签 (公钥)
 *
 * @param data      原始数据
 * @param data_len  数据长度
 * @param signature 签名 (256 字节)
 * @param pubkey    公钥
 * @return          true=验签通过
 */
bool wy_rsa_verify(const uint8_t* data, size_t data_len,
                   const uint8_t* signature,
                   const wy_rsa_pubkey* pubkey);

// ── 密钥序列化 ─────────────────────────────────────────────

/**
 * @brief 将公钥导出为 hex 字符串 (n:512字符,e:8字符)
 */
std::string wy_rsa_pubkey_to_hex(const wy_rsa_pubkey* pubkey);

/**
 * @brief 从 hex 字符串导入公钥
 */
wy_rsa_pubkey wy_rsa_pubkey_from_hex(const std::string& hex);

/**
 * @brief 将私钥导出为 hex 字符串
 */
std::string wy_rsa_prikey_to_hex(const wy_rsa_prikey* prikey);

/**
 * @brief 从 hex 字符串导入私钥
 */
wy_rsa_prikey wy_rsa_prikey_from_hex(const std::string& hex);

} // namespace wy
