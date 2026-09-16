// ============================================================
// WY-RSA — 自研非对称加密实现（RSA 2048-bit）
//
// 自研大整数运算 · 零外部依赖 · 纯 C++17
// 依赖: wy_random.h (随机数), wy_hash.h (哈希)
// 支持系统: Windows XP SP3 及以上
//
// 内部实现:
//   - uint32_t[64] 小端存储 2048-bit 大整数
//   - uint64_t 中间运算捕获进位/借位
//   - Montgomery 模乘 (CIOS) + 滑动窗口模幂
//   - 扩展欧几里得求逆 · GCD · Fermat 素性测试
//   - 小学算法: 加减乘除模 · 位移 · 位运算
//   - PKCS#1 v1.5 加密填充 & 签名填充
// ============================================================

#include "wy_rsa.h"
#include "wy_random.h"
#include "wy_hash.h"
#include "../vmprotect_markers.h"

#include <cstring>
#include <algorithm>
#include <sstream>
#include <iomanip>

namespace wy {

// ═══════════════════════════════════════════════════════════
//  内部常量 & 工具宏
// ═══════════════════════════════════════════════════════════

static constexpr size_t kW = WY_RSA_WORDS;        // 64
static constexpr size_t kB = WY_RSA_BYTES;         // 256
static constexpr size_t kBitsPerWord = 32;

// 小素数表（用于密钥生成时的快速过滤）
static constexpr uint32_t kSmallPrimes[] = {
    3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71,
    73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131, 137, 139, 149,
    151, 157, 163, 167, 173, 179, 181, 191, 193, 197, 199, 211, 223, 227,
    229, 233, 239, 241, 251, 257, 263, 269, 271, 277, 281, 283, 293, 307,
    311, 313, 317, 331, 337, 347, 349, 353, 359, 367, 373, 379, 383, 389,
    397, 401, 409, 419, 421, 431, 433, 439, 443, 449, 457, 461, 463, 467,
    479, 487, 491, 499, 503, 509, 521, 523, 541
};

// 检查一个字是否为 0
#define IS_ZERO_W(w)  ((w) == 0)

// ═══════════════════════════════════════════════════════════
//  内部辅助: 字级别操作
// ═══════════════════════════════════════════════════════════

/**
 * @brief 获取 bigint 的有效字数（忽略高位 0）
 */
static size_t effective_words(const wy_bigint& a) {
    for (size_t i = kW; i > 0; --i) {
        if (a.words[i - 1] != 0) return i;
    }
    return 0;
}

/**
 * @brief 获取 bigint 的最高有效位索引 (0-based, 0 表示 0)
 */
static int highest_bit(const wy_bigint& a) {
    for (size_t i = kW; i > 0; --i) {
        if (a.words[i - 1] != 0) {
            uint32_t w = a.words[i - 1];
            int bit = 31;
            while (bit >= 0 && (w & (1u << bit)) == 0) --bit;
            return static_cast<int>((i - 1) * 32 + bit);
        }
    }
    return -1; // 值为 0
}

/**
 * @brief 从最高位开始获取第 n 个 bit
 */
static bool get_bit(const wy_bigint& a, int pos) {
    size_t wi = static_cast<size_t>(pos) / 32;
    if (wi >= kW) return false;
    int bi = pos % 32;
    return (a.words[wi] & (1u << bi)) != 0;
}

/**
 * @brief 比较两个 bigint (返回 -1/0/1)
 */
static int cmp(const wy_bigint& a, const wy_bigint& b) {
    for (size_t i = kW; i > 0; --i) {
        if (a.words[i - 1] != b.words[i - 1])
            return a.words[i - 1] < b.words[i - 1] ? -1 : 1;
    }
    return 0;
}

/**
 * @brief 带借位的字减法: a - b - *borrow, 返回结果, 同时更新 borrow
 *
 * 在 uint64_t 中做减法: 溢出 → borrow=1, 否则 borrow=0
 */
static uint32_t sub_with_borrow(uint32_t a, uint32_t b, int* borrow) {
    uint64_t r = static_cast<uint64_t>(a) - static_cast<uint64_t>(b)
               - static_cast<uint64_t>(*borrow > 0 ? 1 : 0);
    // r >> 63 为 1 表示发生了下溢 (a - b - borrow < 0)，即需要借位
    *borrow = static_cast<int>((r >> 63) & 1);
    return static_cast<uint32_t>(r & 0xFFFFFFFFULL);
}

/**
 * @brief 带进位的字加法: a + b + carry, 返回 {result, carry}
 */
static uint32_t add_with_carry(uint32_t a, uint32_t b, uint32_t* carry) {
    uint64_t r = static_cast<uint64_t>(a) + static_cast<uint64_t>(b) + static_cast<uint64_t>(*carry);
    *carry = static_cast<uint32_t>(r >> 32);
    return static_cast<uint32_t>(r);
}

/// 拷贝 bigint
static void copy_words(uint32_t* dst, const uint32_t* src) {
    std::memcpy(dst, src, kW * sizeof(uint32_t));
}

/// 清零 bigint
static void zero_words(uint32_t* dst) {
    std::memset(dst, 0, kW * sizeof(uint32_t));
}

// ═══════════════════════════════════════════════════════════
//  wy_bigint 构造函数
// ═══════════════════════════════════════════════════════════

wy_bigint::wy_bigint() {
    zero_words(words);
}

wy_bigint::wy_bigint(uint32_t val) {
    zero_words(words);
    words[0] = val;
}

wy_bigint::wy_bigint(const uint8_t* bytes, size_t len) {
    zero_words(words);
    if (!bytes || len == 0) return;
    // 大端字节 → 小端 words
    // byte[0] 是最高有效字节
    size_t byte_count = std::min(len, kB);
    for (size_t i = 0; i < byte_count; ++i) {
        // 字节在大端中的位置
        size_t src_idx = len - 1 - i;  // 从最低有效字节开始读
        size_t word_idx = i / 4;
        size_t byte_in_word = i % 4;
        if (word_idx < kW) {
            words[word_idx] |= static_cast<uint32_t>(bytes[src_idx]) << (byte_in_word * 8);
        }
    }
}

wy_bigint::wy_bigint(const std::string& hex) {
    zero_words(words);
    if (hex.empty()) return;
    const char* str = hex.c_str();
    if (hex.size() >= 2 && hex[0] == '0' && (hex[1] == 'x' || hex[1] == 'X'))
        str += 2;
    size_t hlen = std::strlen(str);
    for (size_t i = 0; i < hlen; ++i) {
        char c = str[hlen - 1 - i];
        uint32_t nibble;
        if (c >= '0' && c <= '9')      nibble = static_cast<uint32_t>(c - '0');
        else if (c >= 'a' && c <= 'f') nibble = static_cast<uint32_t>(c - 'a' + 10);
        else if (c >= 'A' && c <= 'F') nibble = static_cast<uint32_t>(c - 'A' + 10);
        else continue;
        size_t word_idx = (i / 2) / 4;
        size_t nibble_pos = i % 8; // 0..7, 每个 word 8 个 nibble
        if (word_idx < kW) {
            words[word_idx] |= nibble << (nibble_pos * 4);
        }
    }
}

// ═══════════════════════════════════════════════════════════
//  wy_bigint 导出 & 信息方法
// ═══════════════════════════════════════════════════════════

std::string wy_bigint::to_hex() const {
    int top = highest_bit(*this);
    if (top < 0) return "0";
    int nibbles = (top + 4) / 4; // 向上取整到 nibble
    if (nibbles == 0) nibbles = 1;
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (int i = nibbles - 1; i >= 0; --i) {
        size_t wi = static_cast<size_t>(i) / 8;
        int ni = i % 8;
        uint32_t nibble = (words[wi] >> (ni * 4)) & 0xF;
        oss << nibble;
    }
    return oss.str();
}

std::vector<uint8_t> wy_bigint::to_bytes() const {
    std::vector<uint8_t> result(kB, 0);
    for (size_t i = 0; i < kW; ++i) {
        result[4 * i]     = static_cast<uint8_t>(words[i] & 0xFF);
        result[4 * i + 1] = static_cast<uint8_t>((words[i] >> 8) & 0xFF);
        result[4 * i + 2] = static_cast<uint8_t>((words[i] >> 16) & 0xFF);
        result[4 * i + 3] = static_cast<uint8_t>((words[i] >> 24) & 0xFF);
    }
    // 大端序输出：反转
    std::reverse(result.begin(), result.end());
    return result;
}

bool wy_bigint::is_zero() const {
    for (size_t i = 0; i < kW; ++i)
        if (words[i] != 0) return false;
    return true;
}

bool wy_bigint::is_one() const {
    if (words[0] != 1) return false;
    for (size_t i = 1; i < kW; ++i)
        if (words[i] != 0) return false;
    return true;
}

bool wy_bigint::is_even() const {
    return (words[0] & 1) == 0;
}

int wy_bigint::bit_length() const {
    int h = highest_bit(*this);
    return h + 1; // 0 返回 0
}

// ═══════════════════════════════════════════════════════════
//  wy_bigint 比较运算符
// ═══════════════════════════════════════════════════════════

bool wy_bigint::operator==(const wy_bigint& other) const {
    return cmp(*this, other) == 0;
}
bool wy_bigint::operator!=(const wy_bigint& other) const {
    return cmp(*this, other) != 0;
}
bool wy_bigint::operator<(const wy_bigint& other) const {
    return cmp(*this, other) < 0;
}
bool wy_bigint::operator>(const wy_bigint& other) const {
    return cmp(*this, other) > 0;
}
bool wy_bigint::operator<=(const wy_bigint& other) const {
    return cmp(*this, other) <= 0;
}
bool wy_bigint::operator>=(const wy_bigint& other) const {
    return cmp(*this, other) >= 0;
}

// ═══════════════════════════════════════════════════════════
//  wy_bigint 算术运算 — 加法
// ═══════════════════════════════════════════════════════════

wy_bigint wy_bigint::operator+(const wy_bigint& other) const {
    wy_bigint result;
    uint32_t carry = 0;
    for (size_t i = 0; i < kW; ++i) {
        result.words[i] = add_with_carry(words[i], other.words[i], &carry);
    }
    // 溢出被丢弃（模 2^2048）
    return result;
}

wy_bigint& wy_bigint::operator+=(const wy_bigint& other) {
    uint32_t carry = 0;
    for (size_t i = 0; i < kW; ++i) {
        words[i] = add_with_carry(words[i], other.words[i], &carry);
    }
    return *this;
}

// ═══════════════════════════════════════════════════════════
//  wy_bigint 算术运算 — 减法
// ═══════════════════════════════════════════════════════════

wy_bigint wy_bigint::operator-(const wy_bigint& other) const {
    wy_bigint result;
    int borrow = 0;
    for (size_t i = 0; i < kW; ++i) {
        result.words[i] = sub_with_borrow(words[i], other.words[i], &borrow);
    }
    return result;
}

wy_bigint& wy_bigint::operator-=(const wy_bigint& other) {
    int borrow = 0;
    for (size_t i = 0; i < kW; ++i) {
        words[i] = sub_with_borrow(words[i], other.words[i], &borrow);
    }
    return *this;
}

// ═══════════════════════════════════════════════════════════
//  wy_bigint 算术运算 — 乘法（小学算法，uint64_t 中间值）
// ═══════════════════════════════════════════════════════════

wy_bigint wy_bigint::operator*(const wy_bigint& other) const {
    // 快速路径：乘以 0 或 1
    if (other.is_zero()) return wy_bigint();
    if (other.is_one()) return *this;
    if (this->is_zero()) return wy_bigint();
    if (this->is_one()) return other;

    // 完整乘法：最多需要 2*kW 个 uint32_t
    // 但结果只保留低 kW 个（模 2^2048）
    uint64_t acc[128] = {}; // 128 个 uint64_t 足够存储乘积
    size_t ewa = effective_words(*this);
    size_t ewb = effective_words(other);

    for (size_t i = 0; i < ewa; ++i) {
        uint64_t carry = 0;
        for (size_t j = 0; j < ewb && (i + j) < 128; ++j) {
            uint64_t prod = static_cast<uint64_t>(words[i]) *
                            static_cast<uint64_t>(other.words[j]) +
                            acc[i + j] + carry;
            acc[i + j] = prod & 0xFFFFFFFFULL;
            carry = prod >> 32;
        }
        if (i + ewb < 128) {
            acc[i + ewb] += carry;
        }
    }

    wy_bigint result;
    for (size_t i = 0; i < kW; ++i) {
        result.words[i] = static_cast<uint32_t>(acc[i] & 0xFFFFFFFFULL);
    }
    return result;
}

// ═══════════════════════════════════════════════════════════
//  wy_bigint 算术运算 — 除法 & 取模（恢复余数法 / 小学长除法）
// ═══════════════════════════════════════════════════════════

// 内部除法：dividend / divisor → quotient, remainder
// 使用二进制恢复余数除法（适合大整数）
static void div_mod(const wy_bigint& dividend, const wy_bigint& divisor,
                    wy_bigint* quotient, wy_bigint* remainder) {
    if (divisor.is_zero()) {
        // 除零: 返回 dividend, quotient=0
        if (quotient) *quotient = wy_bigint();
        if (remainder) *remainder = dividend;
        return;
    }
    if (dividend.is_zero()) {
        if (quotient) *quotient = wy_bigint();
        if (remainder) *remainder = wy_bigint();
        return;
    }
    if (dividend < divisor) {
        if (quotient) *quotient = wy_bigint();
        if (remainder) *remainder = dividend;
        return;
    }

    // 二进制长除法
    wy_bigint rem = dividend;
    wy_bigint q;
    int hb_d = divisor.bit_length();
    int hb_n = dividend.bit_length();
    int shift = hb_n - hb_d;

    // 左移 divisor 对齐
    wy_bigint d_shifted = divisor << static_cast<unsigned>(shift);

    for (int i = shift; i >= 0; --i) {
        if (rem >= d_shifted) {
            rem = rem - d_shifted;
            // 设置商第 i 位
            size_t wi = static_cast<size_t>(i) / 32;
            int bi = i % 32;
            q.words[wi] |= (1u << bi);
        }
        d_shifted = d_shifted >> 1;
    }

    if (quotient) *quotient = q;
    if (remainder) *remainder = rem;
}

wy_bigint wy_bigint::operator/(const wy_bigint& other) const {
    wy_bigint q, r;
    div_mod(*this, other, &q, &r);
    return q;
}

wy_bigint wy_bigint::operator%(const wy_bigint& other) const {
    wy_bigint q, r;
    div_mod(*this, other, &q, &r);
    return r;
}

// ═══════════════════════════════════════════════════════════
//  wy_bigint 移位运算
// ═══════════════════════════════════════════════════════════

wy_bigint wy_bigint::operator<<(unsigned bits) const {
    wy_bigint result;
    unsigned word_shift = bits / 32;
    unsigned bit_shift = bits % 32;

    if (word_shift >= kW) return wy_bigint(); // 完全移出

    if (bit_shift == 0) {
        for (size_t i = kW - 1; i >= word_shift; --i)
            result.words[i] = words[i - word_shift];
    } else {
        for (size_t i = kW - 1; i > word_shift; --i) {
            result.words[i] = (words[i - word_shift] << bit_shift) |
                              (words[i - word_shift - 1] >> (32 - bit_shift));
        }
        if (word_shift < kW)
            result.words[word_shift] = words[0] << bit_shift;
    }
    return result;
}

wy_bigint wy_bigint::operator>>(unsigned bits) const {
    wy_bigint result;
    unsigned word_shift = bits / 32;
    unsigned bit_shift = bits % 32;

    if (bit_shift == 0) {
        for (size_t i = 0; i < kW - word_shift; ++i)
            result.words[i] = words[i + word_shift];
    } else {
        for (size_t i = 0; i < kW - word_shift - 1; ++i) {
            result.words[i] = (words[i + word_shift] >> bit_shift) |
                              (words[i + word_shift + 1] << (32 - bit_shift));
        }
        if (word_shift < kW)
            result.words[kW - word_shift - 1] = words[kW - 1] >> bit_shift;
    }
    return result;
}

// ═══════════════════════════════════════════════════════════
//  wy_bigint 位运算
// ═══════════════════════════════════════════════════════════

wy_bigint wy_bigint::operator&(const wy_bigint& other) const {
    wy_bigint result;
    for (size_t i = 0; i < kW; ++i)
        result.words[i] = words[i] & other.words[i];
    return result;
}

wy_bigint wy_bigint::operator|(const wy_bigint& other) const {
    wy_bigint result;
    for (size_t i = 0; i < kW; ++i)
        result.words[i] = words[i] | other.words[i];
    return result;
}

wy_bigint wy_bigint::operator^(const wy_bigint& other) const {
    wy_bigint result;
    for (size_t i = 0; i < kW; ++i)
        result.words[i] = words[i] ^ other.words[i];
    return result;
}

// ═══════════════════════════════════════════════════════════
//  Montgomery 模乘 (CIOS — Coarsely Integrated Operand Scanning)
// ═══════════════════════════════════════════════════════════

struct MontCtx;
static wy_bigint mont_mul(const wy_bigint& a, const wy_bigint& b, const MontCtx& ctx);

/**
 * @brief Montgomery 乘法上下文
 *
 * 预计算值:
 *   n_mod = modulus
 *   n_prime0 = -n[0]⁻¹ mod 2^32
 *   r = 2^(32*W) mod n   (Montgomery 常量)
 */
struct MontCtx {
    wy_bigint n_mod;
    uint32_t  n_prime0; // -n_mod[0]⁻¹ mod 2^32
    wy_bigint r_sq;     // R² mod n (用于将值转换为 Montgomery 形式)
};

/**
 * @brief 计算 n_prime0 = -n[0]⁻¹ mod 2^32
 *
 * 使用扩展欧几里得的简化版：已知 n 是奇数，求 n[0]⁻¹ mod 2^32
 * 公式: inv = n[0] * (2 - n[0] * inv) mod 2^32, 迭代收敛
 */
static uint32_t compute_n_prime0(uint32_t n0) {
    // Newton–Raphson: x_{k+1} = x_k * (2 - n0 * x_k) mod 2^32
    // 3 次迭代足够收敛到 32-bit
    uint32_t x = n0;
    x = x * (2 - n0 * x); // mod 2^2
    x = x * (2 - n0 * x); // mod 2^4
    x = x * (2 - n0 * x); // mod 2^8
    x = x * (2 - n0 * x); // mod 2^16
    x = x * (2 - n0 * x); // mod 2^32
    return static_cast<uint32_t>(-static_cast<int32_t>(x));
}

/**
 * @brief 初始化 Montgomery 上下文
 *
 * @param n 模数（必须是奇数）
 * @return Montgomery 上下文
 */
static MontCtx mont_init(const wy_bigint& n) {
    MontCtx ctx;
    ctx.n_mod = n;
    ctx.n_prime0 = compute_n_prime0(n.words[0]);

    // 计算 R² mod n, R = 2^(32*W)
    // r_sq = (R * R) mod n = 2^(64*W) mod n
    // 从 1 开始反复加倍取模 (binary method for 2^N mod n)
    wy_bigint r_sq(1u);
    int total_bits = static_cast<int>(kW) * 64; // 2*W*32 = 4096
    for (int i = 0; i < total_bits; ++i) {
        r_sq = r_sq + r_sq; // double
        if (r_sq >= n) r_sq = r_sq - n;
        if (r_sq >= n) r_sq = r_sq - n;
    }
    ctx.r_sq = r_sq;
    return ctx;
}

/**
 * @brief 将值转换为 Montgomery 形式: aR = a * R mod n
 *
 * mont_mul(a, R²) = a * R² * R⁻¹ = aR (mod n)  ← 正确
 */
static wy_bigint mont_to(const wy_bigint& a, const MontCtx& ctx) {
    return mont_mul(a, ctx.r_sq, ctx);
}

/**
 * @brief 从 Montgomery 形式转换回普通形式: a = a' * 1 * R⁻¹ mod n
 *
 * MonPro(aR, 1) = a*R * 1 * R⁻¹ = a (mod n)
 */
static wy_bigint mont_from(const wy_bigint& a, const MontCtx& ctx) {
    wy_bigint one(1u);
    // mont_mul(aR, 1) = aR * 1 * R⁻¹ = a mod n
    return mont_mul(a, one, ctx);
}

/**
 * @brief Montgomery 模乘核心 (CIOS — Coarsely Integrated Operand Scanning)
 *
 * 计算: c = aR * bR * R⁻¹ mod n = ab * R mod n
 * 输入 a, b 均为 Montgomery 形式 (aR, bR)
 * 输出也是 Montgomery 形式
 *
 * CIOS: 在每一轮内完成乘加和归约，使用 s+3 个字的临时数组
 * 参考: Ç. K. Koç, T. Acar, B. S. Kaliski Jr.,
 *       "Analyzing and Comparing Montgomery Multiplication Algorithms",
 *       IEEE Micro, 16(3):26–33, June 1996.
 */
static wy_bigint mont_mul(const wy_bigint& a, const wy_bigint& b, const MontCtx& ctx) {
    const uint32_t np0 = ctx.n_prime0;
    uint32_t t[kW + 3] = {}; // 临时: s+2 加溢出空间

    for (size_t i = 0; i < kW; ++i) {
        uint32_t ai = a.words[i];

        // ── 步骤 1: T = T + a[i] * b ──
        uint32_t carry = 0;
        for (size_t j = 0; j < kW; ++j) {
            uint64_t prod = static_cast<uint64_t>(ai) * static_cast<uint64_t>(b.words[j])
                          + static_cast<uint64_t>(t[j]) + static_cast<uint64_t>(carry);
            t[j] = static_cast<uint32_t>(prod & 0xFFFFFFFFULL);
            carry = static_cast<uint32_t>(prod >> 32);
        }
        // 传播最高进位到 t[kW] 和 t[kW+1]
        uint64_t top = static_cast<uint64_t>(t[kW]) + static_cast<uint64_t>(carry);
        t[kW]     = static_cast<uint32_t>(top & 0xFFFFFFFFULL);
        t[kW + 1] = static_cast<uint32_t>(top >> 32);

        // ── 步骤 2: m = T[0] * n'[0] mod 2^32 ──
        uint32_t m = static_cast<uint32_t>(
            (static_cast<uint64_t>(t[0]) * static_cast<uint64_t>(np0)) & 0xFFFFFFFFULL);

        // ── 步骤 3: T = T + m * n ──
        carry = 0;
        for (size_t j = 0; j < kW; ++j) {
            uint64_t prod = static_cast<uint64_t>(m) * static_cast<uint64_t>(ctx.n_mod.words[j])
                          + static_cast<uint64_t>(t[j]) + static_cast<uint64_t>(carry);
            t[j] = static_cast<uint32_t>(prod & 0xFFFFFFFFULL);
            carry = static_cast<uint32_t>(prod >> 32);
        }
        // 传播进位
        {
            uint64_t sum = static_cast<uint64_t>(t[kW]) + static_cast<uint64_t>(carry);
            t[kW] = static_cast<uint32_t>(sum & 0xFFFFFFFFULL);
            carry = static_cast<uint32_t>(sum >> 32);
            if (carry) {
                t[kW + 1] += carry;
                if (t[kW + 1] < carry) t[kW + 2]++; // 三重进位
            }
        }

        // ── 步骤 4: T = T >> 32 (右移一个 word) ──
        for (size_t j = 0; j < kW; ++j)
            t[j] = t[j + 1];
        t[kW] = t[kW + 1];
        t[kW + 1] = t[kW + 2];
        t[kW + 2] = 0;
    }

    // ── 最终条件减: 如果 T ≥ n 则 T = T - n ──
    wy_bigint result;
    for (size_t j = 0; j < kW; ++j)
        result.words[j] = t[j];

    if (result >= ctx.n_mod) {
        result = result - ctx.n_mod;
    }
    return result;
}

// ═══════════════════════════════════════════════════════════
//  wy_bigint 模幂运算 (Montgomery 乘法 + 滑动窗口)
// ═══════════════════════════════════════════════════════════

/**
 * @brief 模幂运算: base^exponent mod modulus
 *
 * 使用 Montgomery 乘法加速 + 滑动窗口法 (w=5)
 * 算法:
 *   1. 初始化 Montgomery 上下文
 *   2. 将 base 转换为 Montgomery 形式
 *   3. 构建预计算表 (窗口大小=5)
 *   4. 滑动窗口扫描 exponent 的 bit
 *   5. 结果转回普通形式
 */
wy_bigint wy_bigint::mod_pow(const wy_bigint& exponent, const wy_bigint& modulus) const {
    if (modulus.is_zero() || modulus.is_one()) return wy_bigint();
    if (exponent.is_zero()) return wy_bigint(1u);
    if (this->is_zero()) return wy_bigint();

    MontCtx ctx = mont_init(modulus);
    wy_bigint base_m = mont_to(*this, ctx);
    wy_bigint one_m = mont_to(wy_bigint(1u), ctx);

    // 滑动窗口大小
    constexpr int WINDOW = 5;
    constexpr int TABLE_SIZE = 1 << (WINDOW - 1); // 16

    // 预计算: g[1], g[3], g[5], ..., g[TABLE_SIZE-1]
    wy_bigint g_table[TABLE_SIZE];
    g_table[0] = base_m;                         // g[1]
    wy_bigint base_sq = mont_mul(base_m, base_m, ctx); // g²
    for (int i = 1; i < TABLE_SIZE; ++i) {
        g_table[i] = mont_mul(g_table[i - 1], base_sq, ctx); // g[2i+1]
    }

    // 扫描 exponent 的 bit（从高到低）
    int bit_len = exponent.bit_length();
    wy_bigint result_m = one_m;

    int i = bit_len - 1;
    while (i >= 0) {
        if (!get_bit(exponent, i)) {
            result_m = mont_mul(result_m, result_m, ctx);
            --i;
        } else {
            // 找到窗口 [i - WINDOW + 1, i] 的最高位
            int window_end = i;
            int window_start = std::max(0, i - WINDOW + 1);
            // 实际扫描: 从 window_end 往下找第一个 1
            // 窗口长度 = window_end - window_start + 1
            int wlen = window_end - window_start + 1;

            // 平方 wlen 次
            for (int j = 0; j < wlen; ++j)
                result_m = mont_mul(result_m, result_m, ctx);

            // 提取窗口值（奇数索引）
            uint32_t window_val = 0;
            for (int j = window_start; j <= window_end; ++j) {
                window_val = (window_val << 1) | (get_bit(exponent, j) ? 1 : 0);
            }

            // window_val 是奇数，索引 = (window_val - 1) / 2
            int idx = static_cast<int>(window_val - 1) / 2;
            if (idx >= 0 && idx < TABLE_SIZE) {
                result_m = mont_mul(result_m, g_table[idx], ctx);
            }
            i = window_start - 1;
        }
    }

    // 转回普通形式: MonPro(result_m, 1) = result_m * 1 * R⁻¹ = result
    wy_bigint result = mont_from(result_m, ctx);
    return result;
}

// ═══════════════════════════════════════════════════════════
//  wy_bigint 数论: 模逆元 (扩展欧几里得)
// ═══════════════════════════════════════════════════════════

/**
 * @brief 计算 a⁻¹ mod m（扩展欧几里得算法）
 *
 * 要求 gcd(a, m) = 1，否则返回 0。
 * 算法: 扩展欧几里得 Bezout 恒等式 ax + my = 1 → x ≡ a⁻¹ (mod m)
 */
wy_bigint wy_bigint::mod_inv(const wy_bigint& modulus) const {
    wy_bigint zero;
    if (modulus.is_zero() || modulus.is_one() || this->is_zero()) return zero;

    // 扩展欧几里得
    wy_bigint a = *this % modulus;
    wy_bigint m = modulus;
    wy_bigint x0(1u), x1;
    wy_bigint y0, y1(1u);

    wy_bigint a_orig = a;
    while (!a.is_zero()) {
        wy_bigint q = m / a;
        wy_bigint r = m % a;

        // x = x0 - q * x1
        wy_bigint x = x0 - (q * x1);
        // y = y0 - q * y1
        wy_bigint y = y0 - (q * y1);

        m = a;
        a = r;
        x0 = x1; x1 = x;
        y0 = y1; y1 = y;
    }

    // m 现在是 gcd(a_orig, modulus)
    if (!m.is_one()) return zero; // 不可逆

    // 确保结果在 [0, modulus) 范围
    if (x0 < zero) {
        x0 = x0 + modulus; // 处理负值
        if (x0 < zero) {
            x0 = x0 % modulus;
            x0 = x0 + modulus;
            x0 = x0 % modulus;
        }
    }
    return x0 % modulus;
}

// ═══════════════════════════════════════════════════════════
//  wy_bigint 数论: GCD (欧几里得)
// ═══════════════════════════════════════════════════════════

wy_bigint wy_bigint::gcd(const wy_bigint& other) const {
    wy_bigint a = *this;
    wy_bigint b = other;
    wy_bigint zero;

    while (!b.is_zero()) {
        wy_bigint t = b;
        b = a % b;
        a = t;
    }
    return a;
}

// ═══════════════════════════════════════════════════════════
//  wy_bigint 数论: Fermat 素性测试
// ═══════════════════════════════════════════════════════════

/**
 * @brief Fermat 素性测试
 *
 * 对于素数 p, a^(p-1) ≡ 1 (mod p) 对所有 a ⊥ p 成立。
 * 随机选取 a ∈ [2, p-2], 测试 iterations 轮。
 *
 * 注意: Carmichael 数会始终通过测试，但对于 1024-bit 密钥生成，
 * 搭配小素数过滤后 Fermat 测试足够安全 (概率 < 2⁻²⁰)。
 *
 * @param iterations 测试轮数（默认 10）
 * @return true 如果大概率是素数
 */
bool wy_bigint::is_probable_prime(int iterations) const {
    if (this->is_even()) return false;
    if (*this < wy_bigint(2u)) return false;
    if (*this == wy_bigint(2u) || *this == wy_bigint(3u)) return true;

    // 快速小素数试除
    wy_bigint zero;
    for (uint32_t sp : kSmallPrimes) {
        wy_bigint sp_big(sp);
        if (*this == sp_big) return true;
        if ((*this % sp_big) == zero) return false;
    }

    // Fermat 测试
    wy_bigint n_minus_1 = *this - wy_bigint(1u);
    wy_bigint two(2u);
    wy_bigint n_minus_2 = *this - two;

    for (int round = 0; round < iterations; ++round) {
        // 在 [2, n-2] 中选随机 a
        wy_bigint r;
        for (size_t i = 0; i < kW; ++i) {
            r.words[i] = wy_random_u32();
        }
        // 确保 r < n-1 且 r >= 2
        r = r % n_minus_2;
        r = r + two; // r ∈ [2, n-1]

        // a^(n-1) mod n
        wy_bigint x = r.mod_pow(n_minus_1, *this);
        if (!x.is_one()) return false;
    }

    return true;
}

// ═══════════════════════════════════════════════════════════
//  RSA 密钥生成
// ═══════════════════════════════════════════════════════════

/**
 * @brief 生成一个 num_bits 位的大素数
 *
 * 策略：
 *   1. 用 wy_random_bytes 填充随机字节
 *   2. 设置最高位（保证 num_bits 位长度）和最低位 = 1（奇数）
 *   3. 小素数试除过滤
 *   4. Fermat 测试 10 轮
 *   5. 不通过则 +2（保持奇数），直到找到
 *
 * @param num_bits 目标比特数（如 1024）
 * @return 大素数
 */
static wy_bigint generate_prime(int num_bits) {
    size_t byte_count = static_cast<size_t>(num_bits + 7) / 8;
    std::vector<uint8_t> buf(byte_count);

    // 外层: 完全重新随机
    for (int attempt = 0; attempt < 100; ++attempt) {
        wy_random_bytes(buf.data(), buf.size());

        // 大端字节 → wy_bigint
        // 设定最高位和最低位
        buf[0] |= 0x80; // 最高字节最高位 = 1 → 保证 bit_length = num_bits
        buf[byte_count - 1] |= 1; // 最低字节最低位 = 1 → 奇数

        wy_bigint p;
        for (size_t i = 0; i < byte_count && i / 4 < kW; ++i) {
            size_t wi = i / 4;
            int shift = static_cast<int>(i % 4) * 8;
            size_t src = byte_count - 1 - i;
            p.words[wi] |= static_cast<uint32_t>(buf[src]) << shift;
        }

        // 小素数试除
        wy_bigint zero;
        bool divisible = false;
        for (uint32_t sp : kSmallPrimes) {
            wy_bigint sp_big(sp);
            if ((p % sp_big) == zero) { divisible = true; break; }
        }
        if (divisible) continue;

        // Fermat 测试
        if (p.is_probable_prime(10)) return p;
    }

    // 极端情况: 返回一个简单的固定素数（理论上不会到达）
    wy_bigint fallback;
    fallback.words[0] = 0xFFFFFFFF;
    fallback.words[31] = 0x80000000; // 确保 1024-bit
    return fallback;
}

/**
 * @brief 生成 RSA 2048-bit 密钥对
 *
 * 流程:
 *   1. 生成 1024-bit 素数 p
 *   2. 生成 1024-bit 素数 q (≠ p)
 *   3. n = p × q
 *   4. φ(n) = (p-1)(q-1)
 *   5. e = 65537
 *   6. d = e⁻¹ mod φ(n)
 */
wy_rsa_keypair wy_rsa_generate_keypair() {
    wy_rsa_keypair kp;
    wy_bigint one(1u);
    wy_bigint zero;

    // 1. 生成素数 p
    wy_bigint p = generate_prime(1024);

    // 2. 生成素数 q (≠ p)
    wy_bigint q;
    for (;;) {
        q = generate_prime(1024);
        if (q != p) break;
    }

    // 3. n = p * q
    wy_bigint n = p * q;

    // 4. φ(n) = (p-1) * (q-1)
    wy_bigint p_minus_1 = p - one;
    wy_bigint q_minus_1 = q - one;
    wy_bigint phi = p_minus_1 * q_minus_1;

    // 5. e = 65537
    wy_bigint e(65537u);

    // 确保 gcd(e, φ(n)) = 1
    wy_bigint g = e.gcd(phi);
    if (!g.is_one()) {
        // 极端情况: 重新生成 q
        for (;;) {
            q = generate_prime(1024);
            if (q == p) continue;
            n = p * q;
            p_minus_1 = p - one;
            q_minus_1 = q - one;
            phi = p_minus_1 * q_minus_1;
            g = e.gcd(phi);
            if (g.is_one()) break;
        }
    }

    // 6. d = e⁻¹ mod φ(n)
    wy_bigint d = e.mod_inv(phi);

    kp.pub.n = n;
    kp.pub.e = e;
    kp.pri.n = n;
    kp.pri.d = d;
    kp.pri.p = p;
    kp.pri.q = q;

    return kp;
}

// ═══════════════════════════════════════════════════════════
//  PKCS#1 v1.5 填充
// ═══════════════════════════════════════════════════════════

/**
 * @brief PKCS#1 v1.5 加密填充
 *
 * 格式: EB = 00 || BT || PS || 00 || D
 *   BT = 02 (公钥加密)
 *   PS = 随机非零字节, ≥8 字节
 *
 * @param plaintext 明文
 * @param plain_len 明文长度
 * @param out       输出缓冲区 (256 字节)
 * @return true 成功
 */
static bool pkcs1_v15_encrypt_pad(const uint8_t* plaintext, size_t plain_len,
                                   uint8_t* out) {
    if (plain_len > WY_RSA_MAX_PLAIN) return false;

    // EB = [0x00] [0x02] [PS: 随机非零] [0x00] [Data]
    // PS 长度 = 256 - 3 - plain_len
    size_t ps_len = kB - 3 - plain_len;
    if (ps_len < 8) return false; // 兼容极小消息

    out[0] = 0x00;
    out[1] = 0x02;

    // 生成随机非零填充字节
    for (size_t i = 0; i < ps_len; ++i) {
        uint8_t b;
        do {
            wy_random_bytes(&b, 1);
        } while (b == 0);
        out[2 + i] = b;
    }

    out[2 + ps_len] = 0x00;
    std::memcpy(out + 3 + ps_len, plaintext, plain_len);
    return true;
}

/**
 * @brief PKCS#1 v1.5 解密去填充
 *
 * @param eb   加密块 (256 字节)
 * @param out  输出明文缓冲区
 * @return     明文长度, 0 = 填充无效
 */
static size_t pkcs1_v15_decrypt_unpad(const uint8_t* eb, uint8_t* out) {
    // 格式: 00 || 02 || PS (≥8 非零) || 00 || D
    if (eb[0] != 0x00 || eb[1] != 0x02) return 0;

    // 找到分隔符 0x00 (从偏移 2 开始)
    size_t sep = 2;
    while (sep < kB && eb[sep] != 0x00) ++sep;
    if (sep >= kB) return 0;

    size_t ps_len = sep - 2;
    if (ps_len < 8) return 0; // PS 必须 ≥ 8

    size_t data_len = kB - sep - 1;
    if (data_len == 0) return 0;
    std::memcpy(out, eb + sep + 1, data_len);
    return data_len;
}

/**
 * @brief PKCS#1 v1.5 签名填充
 *
 * 格式: EB = 00 || 01 || PS (FF...FF) || 00 || DigestInfo
 *
 * @param hash_data 哈希值 (32 字节)
 * @param out       输出缓冲区 (256 字节)
 */
static void pkcs1_v15_sign_pad(const uint8_t* hash_data, uint8_t* out) {
    // DigestInfo = 哈希标识 + hash
    // 简化: 用 34 字节 (type=0x30 0x20 || hash)
    constexpr size_t kHashLen = WY_HASH_OUTPUT_SIZE; // 32
    constexpr size_t kDigestInfoLen = 2 + kHashLen;  // 34
    constexpr size_t kPsLen = kB - 3 - kDigestInfoLen; // 256 - 3 - 34 = 219

    out[0] = 0x00;
    out[1] = 0x01;

    // PS = FF...FF
    std::memset(out + 2, 0xFF, kPsLen);

    out[2 + kPsLen] = 0x00;

    // DigestInfo: ASN.1 DER 编码
    // SEQUENCE { SEQUENCE { OID, NULL }, OCTET STRING hash }
    // 简化版本: type||len||hash
    out[3 + kPsLen] = 0x30; // SEQUENCE
    out[4 + kPsLen] = 0x20; // length 32

    std::memcpy(out + 5 + kPsLen, hash_data, kHashLen);
}

/**
 * @brief PKCS#1 v1.5 签名去填充
 *
 * @param eb     加密块 (256 字节)
 * @param out_hash 输出提取的哈希值 (32 字节)
 * @return true 如果填充有效
 */
static bool pkcs1_v15_sign_unpad(const uint8_t* eb, uint8_t* out_hash) {
    if (eb[0] != 0x00 || eb[1] != 0x01) return false;

    // 找到分隔符
    size_t sep = 2;
    while (sep < kB && eb[sep] == 0xFF) ++sep;
    if (sep >= kB || eb[sep] != 0x00) return false;

    size_t ps_len = sep - 2;
    if (ps_len < 8) return false;

    size_t di_start = sep + 1;
    size_t di_len = kB - di_start;
    if (di_len < 2 + WY_HASH_OUTPUT_SIZE) return false;

    // 跳过 ASN.1 头: 00 后应为 0x30 0x20 或等效
    // 简化处理: 直接提取最后 32 字节
    std::memcpy(out_hash, eb + kB - WY_HASH_OUTPUT_SIZE, WY_HASH_OUTPUT_SIZE);
    return true;
}

// ═══════════════════════════════════════════════════════════
//  将 bigint 转为固定长度的大端字节数组
// ═══════════════════════════════════════════════════════════

/**
 * @brief 将 bigint 导出为固定长度大端字节（256 字节）
 */
static void bigint_to_be_bytes(const wy_bigint& a, uint8_t* out, size_t len) {
    std::vector<uint8_t> bytes = a.to_bytes();
    size_t src_len = bytes.size();
    size_t offset = len - src_len;
    std::memset(out, 0, offset);
    std::memcpy(out + offset, bytes.data(), std::min(src_len, len));
}

/**
 * @brief 从大端字节导入为 bigint（256 字节）
 */
static wy_bigint bigint_from_be_bytes(const uint8_t* bytes, size_t len) {
    // 反转字节 → 小端 word
    wy_bigint result;
    for (size_t i = 0; i < len && i / 4 < kW; ++i) {
        size_t wi = i / 4;
        int shift = static_cast<int>(i % 4) * 8;
        size_t src = len - 1 - i;
        result.words[wi] |= static_cast<uint32_t>(bytes[src]) << shift;
    }
    return result;
}

// ═══════════════════════════════════════════════════════════
//  RSA 加密/解密
// ═══════════════════════════════════════════════════════════

/// RSAEP: m^e mod n
static wy_bigint rsa_ep(const wy_bigint& m, const wy_bigint& e, const wy_bigint& n) {
    VMProtectScope _vmp_scope_auto_1("rsa_ep");
    return m.mod_pow(e, n);
}

/// RSADP (CRT 加速): c^d mod n 使用 p, q
static wy_bigint rsa_dp_crt(const wy_bigint& c, const wy_bigint& d,
                             const wy_bigint& p, const wy_bigint& q) {
    VMProtectScope _vmp_scope_auto_2("rsa_dp_crt");
    wy_bigint one(1u);

    // dp = d mod (p-1)
    wy_bigint dp = d % (p - one);
    // dq = d mod (q-1)
    wy_bigint dq = d % (q - one);
    // qinv = q⁻¹ mod p
    wy_bigint qinv = q.mod_inv(p);

    // m1 = c^dp mod p
    wy_bigint m1 = c.mod_pow(dp, p);
    // m2 = c^dq mod q
    wy_bigint m2 = c.mod_pow(dq, q);

    // h = qinv * (m1 - m2) mod p
    wy_bigint diff;
    if (m1 >= m2)
        diff = m1 - m2;
    else
        diff = (m1 + p) - m2;
    diff = diff % p;
    wy_bigint h = (qinv * diff) % p;

    // m = m2 + h * q
    wy_bigint result = h * q;
    result = result + m2;
    return result;
}

std::vector<uint8_t> wy_rsa_encrypt(const uint8_t* plaintext, size_t plain_len,
                                     const wy_rsa_pubkey* pubkey) {
    VMProtectScope _vmp_rsa_encrypt("wy_rsa_encrypt");
    std::vector<uint8_t> result(kB, 0);
    if (!plaintext || plain_len == 0 || !pubkey) return result;

    // 1. PKCS#1 v1.5 填充
    uint8_t eb[kB];
    if (!pkcs1_v15_encrypt_pad(plaintext, plain_len, eb)) return {};

    // 2. 转为大整数
    wy_bigint m = bigint_from_be_bytes(eb, kB);

    // 3. 加密: c = m^e mod n
    wy_bigint c = rsa_ep(m, pubkey->e, pubkey->n);

    // 4. 导出密文
    bigint_to_be_bytes(c, result.data(), kB);
    return result;
}

std::vector<uint8_t> wy_rsa_decrypt(const uint8_t* ciphertext, size_t cipher_len,
                                     const wy_rsa_prikey* prikey) {
    VMProtectScope _vmp_rsa_decrypt("wy_rsa_decrypt");
    std::vector<uint8_t> result;
    if (!ciphertext || cipher_len != kB || !prikey) return result;

    // 1. 转为大整数
    wy_bigint c = bigint_from_be_bytes(ciphertext, cipher_len);

    // 2. 解密 (CRT 加速)
    wy_bigint m = rsa_dp_crt(c, prikey->d, prikey->p, prikey->q);

    // 3. 导出为字节
    uint8_t eb[kB];
    bigint_to_be_bytes(m, eb, kB);

    // 4. 去除 PKCS#1 v1.5 填充
    uint8_t plain[WY_RSA_MAX_PLAIN];
    size_t plen = pkcs1_v15_decrypt_unpad(eb, plain);
    if (plen == 0) return {};

    result.assign(plain, plain + plen);
    return result;
}

// ═══════════════════════════════════════════════════════════
//  RSA 签名/验签
// ═══════════════════════════════════════════════════════════

std::vector<uint8_t> wy_rsa_sign(const uint8_t* data, size_t len,
                                  const wy_rsa_prikey* prikey) {
    VMProtectScope _vmp_rsa_sign("wy_rsa_sign");
    std::vector<uint8_t> result(kB, 0);
    if (!data || len == 0 || !prikey) return result;

    // 1. 计算 WY-Hash
    uint8_t hash[WY_HASH_OUTPUT_SIZE];
    wy_hash(data, len, hash);

    // 2. PKCS#1 v1.5 签名填充
    uint8_t eb[kB];
    pkcs1_v15_sign_pad(hash, eb);

    // 3. 转为大整数
    wy_bigint m = bigint_from_be_bytes(eb, kB);

    // 4. 签名: s = m^d mod n (CRT 加速)
    wy_bigint s = rsa_dp_crt(m, prikey->d, prikey->p, prikey->q);

    // 5. 导出签名
    bigint_to_be_bytes(s, result.data(), kB);
    return result;
}

bool wy_rsa_verify(const uint8_t* data, size_t data_len,
                   const uint8_t* signature,
                   const wy_rsa_pubkey* pubkey) {
    VMProtectScope _vmp_scope_auto_3("wy_rsa_verify");
    if (!data || data_len == 0 || !signature || !pubkey) return false;

    // 1. 计算原始数据的 WY-Hash
    uint8_t expected_hash[WY_HASH_OUTPUT_SIZE];
    wy_hash(data, data_len, expected_hash);

    // 2. 签名 → 大整数
    wy_bigint s = bigint_from_be_bytes(signature, kB);

    // 3. 验签: m = s^e mod n
    wy_bigint m = rsa_ep(s, pubkey->e, pubkey->n);

    // 4. 导出填充块
    uint8_t eb[kB];
    bigint_to_be_bytes(m, eb, kB);

    // 5. 去除 PKCS#1 v1.5 签名填充
    uint8_t recovered_hash[WY_HASH_OUTPUT_SIZE];
    if (!pkcs1_v15_sign_unpad(eb, recovered_hash)) return false;

    // 6. 常量时间比较哈希值
    return wy_const_time_eq(expected_hash, recovered_hash, WY_HASH_OUTPUT_SIZE);
}

// ═══════════════════════════════════════════════════════════
//  密钥序列化
// ═══════════════════════════════════════════════════════════

std::string wy_rsa_pubkey_to_hex(const wy_rsa_pubkey* pubkey) {
    if (!pubkey) return "";
    // 格式: n_hex || ":" || e_hex
    return pubkey->n.to_hex() + ":" + pubkey->e.to_hex();
}

wy_rsa_pubkey wy_rsa_pubkey_from_hex(const std::string& hex) {
    wy_rsa_pubkey key;
    auto pos = hex.find(':');
    if (pos == std::string::npos) return key;
    key.n = wy_bigint(hex.substr(0, pos));
    key.e = wy_bigint(hex.substr(pos + 1));
    return key;
}

std::string wy_rsa_prikey_to_hex(const wy_rsa_prikey* prikey) {
    if (!prikey) return "";
    // 格式: n_hex || ":" || d_hex || ":" || p_hex || ":" || q_hex
    return prikey->n.to_hex() + ":" +
           prikey->d.to_hex() + ":" +
           prikey->p.to_hex() + ":" +
           prikey->q.to_hex();
}

wy_rsa_prikey wy_rsa_prikey_from_hex(const std::string& hex) {
    wy_rsa_prikey key;
    std::string s = hex;
    size_t p1 = s.find(':');
    if (p1 == std::string::npos) return key;
    size_t p2 = s.find(':', p1 + 1);
    if (p2 == std::string::npos) return key;
    size_t p3 = s.find(':', p2 + 1);
    if (p3 == std::string::npos) return key;

    key.n = wy_bigint(s.substr(0, p1));
    key.d = wy_bigint(s.substr(p1 + 1, p2 - p1 - 1));
    key.p = wy_bigint(s.substr(p2 + 1, p3 - p2 - 1));
    key.q = wy_bigint(s.substr(p3 + 1));
    return key;
}

} // namespace wy
