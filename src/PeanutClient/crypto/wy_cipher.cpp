// ============================================================
// WY-Cipher 实现 — 自研对称加密算法
// 256-bit 块 · Feistel 网络 32 轮 · 自定义 S-Box / P-Box
// 纯 C++ · 零外部依赖
// ============================================================

#include "wy_cipher.h"
#include "wy_random.h"
#include "wy_hash.h"
#include "../vmprotect_markers.h"

#include <cstring>
#include <algorithm>

namespace wy {

// ═══════════════════════════════════════════════════════════
//  基础 S-Box — 256 字节非线性替换表
//  基于乘法逆元 + 仿射变换构造 (AES 风格)
// ═══════════════════════════════════════════════════════════
static const uint8_t g_base_sbox[256] = {
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
};

// 逆 S-Box
static const uint8_t g_base_inv_sbox[256] = {
    0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
    0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
    0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
    0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
    0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
    0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
    0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
    0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
    0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
    0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
    0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
    0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
    0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
    0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
    0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D
};

// ═══════════════════════════════════════════════════════════
//  P-Box — 位排列 (256-bit → 256-bit)
//  每个字节的每个比特被安排到不同位置, 增强扩散
// ═══════════════════════════════════════════════════════════

// 正向 P-Box: perm[i] = 输出位 i 来自输入位 perm[i]
static const int g_pbox[256] = {
    191, 127, 63,  255, 159, 95,  31,  223,
    175, 111, 47,  239, 143, 79,  15,  207,
    183, 119, 55,  247, 151, 87,  23,  215,
    167, 103, 39,  231, 135, 71,  7,   199,
    187, 123, 59,  251, 155, 91,  27,  219,
    171, 107, 43,  235, 139, 75,  11,  203,
    179, 115, 51,  243, 147, 83,  19,  211,
    163, 99,  35,  227, 131, 67,  3,   195,
    189, 125, 61,  253, 157, 93,  29,  221,
    173, 109, 45,  237, 141, 77,  13,  205,
    181, 117, 53,  245, 149, 85,  21,  213,
    165, 101, 37,  229, 133, 69,  5,   197,
    185, 121, 57,  249, 153, 89,  25,  217,
    169, 105, 41,  233, 137, 73,  9,   201,
    177, 113, 49,  241, 145, 81,  17,  209,
    161, 97,  33,  225, 129, 65,  1,   193,
    190, 126, 62,  254, 158, 94,  30,  222,
    174, 110, 46,  238, 142, 78,  14,  206,
    182, 118, 54,  246, 150, 86,  22,  214,
    166, 102, 38,  230, 134, 70,  6,   198,
    186, 122, 58,  250, 154, 90,  26,  218,
    170, 106, 42,  234, 138, 74,  10,  202,
    178, 114, 50,  242, 146, 82,  18,  210,
    162, 98,  34,  226, 130, 66,  2,   194,
    188, 124, 60,  252, 156, 92,  28,  220,
    172, 108, 44,  236, 140, 76,  12,  204,
    180, 116, 52,  244, 148, 84,  20,  212,
    164, 100, 36,  228, 132, 68,  4,   196,
    184, 120, 56,  248, 152, 88,  24,  216,
    168, 104, 40,  232, 136, 72,  8,   200,
    176, 112, 48,  240, 144, 80,  16,  208,
    160, 96,  32,  224, 128, 64,  0,   192
};

// ═══════════════════════════════════════════════════════════
//  辅助函数
// ═══════════════════════════════════════════════════════════

static inline uint32_t rotr32(uint32_t x, unsigned n) {
    return (x >> n) | (x << (32 - n));
}

static inline uint32_t rotl32(uint32_t x, unsigned n) {
    return (x << n) | (x >> (32 - n));
}

// 将 8 字节读为 uint64_t (小端)
static inline uint64_t read_le64(const uint8_t* p) {
    return (static_cast<uint64_t>(p[0]))       |
           (static_cast<uint64_t>(p[1]) << 8)  |
           (static_cast<uint64_t>(p[2]) << 16) |
           (static_cast<uint64_t>(p[3]) << 24) |
           (static_cast<uint64_t>(p[4]) << 32) |
           (static_cast<uint64_t>(p[5]) << 40) |
           (static_cast<uint64_t>(p[6]) << 48) |
           (static_cast<uint64_t>(p[7]) << 56);
}

// 将 uint64_t 写为 8 字节 (小端)
static inline void write_le64(uint8_t* p, uint64_t v) {
    p[0] = static_cast<uint8_t>(v);
    p[1] = static_cast<uint8_t>(v >> 8);
    p[2] = static_cast<uint8_t>(v >> 16);
    p[3] = static_cast<uint8_t>(v >> 24);
    p[4] = static_cast<uint8_t>(v >> 32);
    p[5] = static_cast<uint8_t>(v >> 40);
    p[6] = static_cast<uint8_t>(v >> 48);
    p[7] = static_cast<uint8_t>(v >> 56);
}

// 应用 P-Box 到 32 字节块
static void apply_pbox(const int* pbox, const uint8_t* src, uint8_t* dst) {
    for (int i = 0; i < 256; ++i) {
        int src_bit = pbox[i];
        int src_byte = src_bit / 8;
        int src_bit_in_byte = src_bit % 8;
        int dst_byte = i / 8;
        int dst_bit_in_byte = i % 8;
        uint8_t bit_val = (src[src_byte] >> src_bit_in_byte) & 1;
        if (bit_val)
            dst[dst_byte] |= (1 << dst_bit_in_byte);
        else
            dst[dst_byte] &= ~(1 << dst_bit_in_byte);
    }
    std::memcpy(const_cast<uint8_t*>(src), dst, 32);
}

// ═══════════════════════════════════════════════════════════
//  密钥扩展
// ═══════════════════════════════════════════════════════════

void wy_cipher_key_schedule(const uint8_t* raw_key, wy_cipher_key* out_key) {
    VMProtectScope _vmp_scope_auto_1("wy_cipher_key_schedule");
    // 1. 用原始密钥初始化基础 S-Box 的扰动版本
    for (int i = 0; i < 256; ++i) {
        out_key->sbox[i] = g_base_sbox[i] ^ raw_key[i % 32] ^ raw_key[(i * 7 + 13) % 32];
    }

    // 2. 派生 32 轮密钥, 每轮 8 个 32-bit 字
    uint8_t seed[64];
    std::memcpy(seed, raw_key, 32);

    // 对密钥做自引用哈希链式派生
    for (int r = 0; r < WY_CIPHER_ROUNDS; ++r) {
        // 种子 = WY-Hash(种子 || 轮号)
        seed[32] = static_cast<uint8_t>(r);
        seed[33] = static_cast<uint8_t>(r >> 8);
        uint8_t hash[WY_HASH_OUTPUT_SIZE];
        wy_hash(seed, 34, hash);

        for (int i = 0; i < 8; ++i) {
            out_key->round_keys[r][i] =
                (static_cast<uint32_t>(hash[i * 4])     << 24) |
                (static_cast<uint32_t>(hash[i * 4 + 1]) << 16) |
                (static_cast<uint32_t>(hash[i * 4 + 2]) << 8)  |
                (static_cast<uint32_t>(hash[i * 4 + 3]));
        }

        // 用 hash 更新种子用于下一轮
        std::memcpy(seed, hash, 32);
    }

    // 安全清零
    std::memset(seed, 0, sizeof(seed));
}

// ═══════════════════════════════════════════════════════════
//  Feistel 轮函数 F — 核心非线性变换
// ═══════════════════════════════════════════════════════════

static void feistel_round_function(const wy_cipher_key* key, int round,
                                    const uint8_t* half_block, uint8_t* output) {
    // 输入: 16 字节 (左半或右半)
    // 输出: 16 字节

    // 第一步: S-Box 替换 (展开到 16 字节后逐字节替换)
    uint8_t temp[16];
    for (int i = 0; i < 16; ++i)
        temp[i] = key->sbox[half_block[i]];

    // 第二步: 与轮子密钥混合 (8 个 32-bit 字, 每 4 字节异或一个)
    for (int i = 0; i < 4; ++i) {
        uint32_t rk = key->round_keys[round][i];
        temp[i * 4]     ^= static_cast<uint8_t>(rk);
        temp[i * 4 + 1] ^= static_cast<uint8_t>(rk >> 8);
        temp[i * 4 + 2] ^= static_cast<uint8_t>(rk >> 16);
        temp[i * 4 + 3] ^= static_cast<uint8_t>(rk >> 24);
    }

    // 第三步: 线性扩散 (MDS 风格矩阵乘法 over GF(2^8))
    for (int col = 0; col < 4; ++col) {
        uint8_t a = temp[col * 4];
        uint8_t b = temp[col * 4 + 1];
        uint8_t c = temp[col * 4 + 2];
        uint8_t d = temp[col * 4 + 3];

        // 简化 MDS: 循环移位 + 异或
        temp[col * 4]     = a ^ rotl32(d, 3) ^ rotl32(b, 7);
        temp[col * 4 + 1] = b ^ rotl32(a, 5) ^ rotl32(c, 11);
        temp[col * 4 + 2] = c ^ rotl32(b, 13) ^ rotl32(d, 17);
        temp[col * 4 + 3] = d ^ rotl32(c, 19) ^ rotl32(a, 23);
    }

    // 第四步: 再次 S-Box
    for (int i = 0; i < 16; ++i)
        output[i] = key->sbox[temp[i]];
}

static void feistel_round(const wy_cipher_key* key, int round,
                           const uint8_t* left_in, const uint8_t* right_in,
                           uint8_t* left_out, uint8_t* right_out) {
    // F 函数作用于右半
    uint8_t f_out[16];
    feistel_round_function(key, round, right_in, f_out);

    // left_out = right_in
    // right_out = left_in XOR F(right_in)
    std::memcpy(left_out, right_in, 16);
    for (int i = 0; i < 16; ++i)
        right_out[i] = left_in[i] ^ f_out[i];
}

// ═══════════════════════════════════════════════════════════
//  块加密 / 解密
// ═══════════════════════════════════════════════════════════

void wy_cipher_encrypt_block(const wy_cipher_key* key, uint8_t* block) {
    VMProtectScope _vmp_scope_auto_2("wy_cipher_encrypt_block");
    // 1. 初始白化: 异或轮密钥 0
    for (int i = 0; i < 8; ++i) {
        uint32_t rk = key->round_keys[0][i];
        block[i * 4]     ^= static_cast<uint8_t>(rk);
        block[i * 4 + 1] ^= static_cast<uint8_t>(rk >> 8);
        block[i * 4 + 2] ^= static_cast<uint8_t>(rk >> 16);
        block[i * 4 + 3] ^= static_cast<uint8_t>(rk >> 24);
    }

    // 2. 32 轮 Feistel
    uint8_t left[16], right[16];
    std::memcpy(left, block, 16);
    std::memcpy(right, block + 16, 16);

    for (int r = 0; r < WY_CIPHER_ROUNDS; ++r) {
        uint8_t new_left[16], new_right[16];
        feistel_round(key, r, left, right, new_left, new_right);
        std::memcpy(left, new_left, 16);
        std::memcpy(right, new_right, 16);

        // 每 4 轮穿插一次 P-Box 扩散
        if (r % 4 == 3) {
            uint8_t combined[32], pbox_out[32] = {};
            std::memcpy(combined, left, 16);
            std::memcpy(combined + 16, right, 16);
            apply_pbox(g_pbox, combined, pbox_out);
            std::memcpy(left, pbox_out, 16);
            std::memcpy(right, pbox_out + 16, 16);
        }
    }

    // 3. 最终白化: 异或轮密钥 31
    std::memcpy(block, left, 16);
    std::memcpy(block + 16, right, 16);
    for (int i = 0; i < 8; ++i) {
        uint32_t rk = key->round_keys[WY_CIPHER_ROUNDS - 1][i];
        block[i * 4]     ^= static_cast<uint8_t>(rk);
        block[i * 4 + 1] ^= static_cast<uint8_t>(rk >> 8);
        block[i * 4 + 2] ^= static_cast<uint8_t>(rk >> 16);
        block[i * 4 + 3] ^= static_cast<uint8_t>(rk >> 24);
    }
}

void wy_cipher_decrypt_block(const wy_cipher_key* key, uint8_t* block) {
    VMProtectScope _vmp_scope_auto_3("wy_cipher_decrypt_block");
    // 解密: 逆向操作
    // 1. 逆向最终白化
    for (int i = 0; i < 8; ++i) {
        uint32_t rk = key->round_keys[WY_CIPHER_ROUNDS - 1][i];
        block[i * 4]     ^= static_cast<uint8_t>(rk);
        block[i * 4 + 1] ^= static_cast<uint8_t>(rk >> 8);
        block[i * 4 + 2] ^= static_cast<uint8_t>(rk >> 16);
        block[i * 4 + 3] ^= static_cast<uint8_t>(rk >> 24);
    }

    uint8_t left[16], right[16];
    std::memcpy(left, block, 16);
    std::memcpy(right, block + 16, 16);

    // 2. 逆向 32 轮 Feistel (倒序)
    for (int r = WY_CIPHER_ROUNDS - 1; r >= 0; --r) {
        // 逆向 P-Box (每 4 轮)
        if (r % 4 == 3) {
            uint8_t combined[32], pbox_out[32] = {};
            std::memcpy(combined, left, 16);
            std::memcpy(combined + 16, right, 16);
            // 逆向 P-Box: 排列表的逆
            int inv_pbox[256];
            for (int i = 0; i < 256; ++i)
                inv_pbox[g_pbox[i]] = i;
            apply_pbox(inv_pbox, combined, pbox_out);
            std::memcpy(left, pbox_out, 16);
            std::memcpy(right, pbox_out + 16, 16);
        }

        // Feistel 逆: 交换左右
        uint8_t new_left[16], new_right[16];
        // 加密: L'=R, R'=L⊕F(R)
        // 解密: R=L', L=R'⊕F(L')
        std::memcpy(new_right, left, 16); // R = L'
        uint8_t f_out[16];
        feistel_round_function(key, r, left, f_out); // F(L')
        for (int i = 0; i < 16; ++i)
            new_left[i] = right[i] ^ f_out[i]; // L = R' ⊕ F(L')

        std::memcpy(left, new_left, 16);
        std::memcpy(right, new_right, 16);
    }

    // 3. 逆向初始白化
    std::memcpy(block, left, 16);
    std::memcpy(block + 16, right, 16);
    for (int i = 0; i < 8; ++i) {
        uint32_t rk = key->round_keys[0][i];
        block[i * 4]     ^= static_cast<uint8_t>(rk);
        block[i * 4 + 1] ^= static_cast<uint8_t>(rk >> 8);
        block[i * 4 + 2] ^= static_cast<uint8_t>(rk >> 16);
        block[i * 4 + 3] ^= static_cast<uint8_t>(rk >> 24);
    }
}

// ═══════════════════════════════════════════════════════════
//  CBC 模式
// ═══════════════════════════════════════════════════════════

// 将 16 字节 IV 扩展为 32 字节块 IV
// IV_block = WY-Hash(IV)[0:32] 异或 原始密钥（从密钥表还原）
static void expand_iv(const uint8_t* iv, const wy_cipher_key* key, uint8_t* block_iv) {
    uint8_t hash[WY_HASH_OUTPUT_SIZE];
    wy_hash(iv, 16, hash);
    // 用轮密钥 0 异或哈希结果产生块 IV
    for (int i = 0; i < 8; ++i) {
        uint32_t rk = key->round_keys[0][i];
        hash[i * 4]     ^= static_cast<uint8_t>(rk);
        hash[i * 4 + 1] ^= static_cast<uint8_t>(rk >> 8);
        hash[i * 4 + 2] ^= static_cast<uint8_t>(rk >> 16);
        hash[i * 4 + 3] ^= static_cast<uint8_t>(rk >> 24);
    }
    std::memcpy(block_iv, hash, WY_CIPHER_BLOCK_SIZE);
}

std::vector<uint8_t> wy_cbc_encrypt(const wy_cipher_key* key,
                                     const uint8_t* iv, const uint8_t* data, size_t len) {
    VMProtectScope _vmp_cbc_enc("wy_cbc_encrypt");
    if (!data || len == 0) return {};

    // PKCS7-like 填充: 至少一个完整的 32 字节块
    size_t padded_len = ((len / WY_CIPHER_BLOCK_SIZE) + 1) * WY_CIPHER_BLOCK_SIZE;
    size_t pad_val = padded_len - len;
    std::vector<uint8_t> padded(padded_len);
    std::memcpy(padded.data(), data, len);
    // PKCS7: 所有填充字节 = 填充长度
    std::memset(padded.data() + len, static_cast<int>(pad_val), pad_val);

    // 生成块 IV
    uint8_t block_iv[WY_CIPHER_BLOCK_SIZE];
    expand_iv(iv, key, block_iv);

    std::vector<uint8_t> result(padded_len);
    uint8_t prev[WY_CIPHER_BLOCK_SIZE];
    std::memcpy(prev, block_iv, WY_CIPHER_BLOCK_SIZE);

    for (size_t i = 0; i < padded_len; i += WY_CIPHER_BLOCK_SIZE) {
        // XOR with previous ciphertext
        for (size_t j = 0; j < WY_CIPHER_BLOCK_SIZE; ++j)
            result[i + j] = padded[i + j] ^ prev[j];

        // Encrypt
        wy_cipher_encrypt_block(key, result.data() + i);

        // Update prev for next block
        std::memcpy(prev, result.data() + i, WY_CIPHER_BLOCK_SIZE);
    }

    return result;
}

std::vector<uint8_t> wy_cbc_decrypt(const wy_cipher_key* key,
                                     const uint8_t* iv, const uint8_t* data, size_t len) {
    VMProtectScope _vmp_cbc_dec("wy_cbc_decrypt");
    if (!data || len == 0 || len % WY_CIPHER_BLOCK_SIZE != 0) return {};

    uint8_t block_iv[WY_CIPHER_BLOCK_SIZE];
    expand_iv(iv, key, block_iv);

    std::vector<uint8_t> result(len);
    uint8_t prev[WY_CIPHER_BLOCK_SIZE];
    std::memcpy(prev, block_iv, WY_CIPHER_BLOCK_SIZE);

    for (size_t i = 0; i < len; i += WY_CIPHER_BLOCK_SIZE) {
        // Save current ciphertext for next iteration
        uint8_t curr_cipher[WY_CIPHER_BLOCK_SIZE];
        std::memcpy(curr_cipher, data + i, WY_CIPHER_BLOCK_SIZE);

        // Decrypt
        std::memcpy(result.data() + i, data + i, WY_CIPHER_BLOCK_SIZE);
        wy_cipher_decrypt_block(key, result.data() + i);

        // XOR with previous ciphertext
        for (size_t j = 0; j < WY_CIPHER_BLOCK_SIZE; ++j)
            result[i + j] ^= prev[j];

        std::memcpy(prev, curr_cipher, WY_CIPHER_BLOCK_SIZE);
    }

    // 去除 PKCS7 填充
    uint8_t pad_val = result.back();
    if (pad_val > 0 && pad_val <= WY_CIPHER_BLOCK_SIZE) {
        bool valid = true;
        for (size_t i = len - pad_val; i < len; ++i) {
            if (result[i] != pad_val) { valid = false; break; }
        }
        if (valid) result.resize(len - pad_val);
    }

    return result;
}

std::string wy_cipher_generate_key_hex() {
    uint8_t key[WY_CIPHER_KEY_SIZE];
    wy_random_bytes(key, sizeof(key));
    return wy_hash_to_hex(key);
}

} // namespace wy
