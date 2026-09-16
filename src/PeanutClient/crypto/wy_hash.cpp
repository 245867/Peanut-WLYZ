// ============================================================
// WY-Hash 实现 — 自研 256-bit 密码学哈希
// 自定义 Merkle-Damgård + 80轮压缩函数
// 纯 C++ · 零外部依赖
// ============================================================

#include "wy_hash.h"
#include "wy_random.h"
#include "../vmprotect_markers.h"

#include <cstring>
#include <algorithm>
#include <sstream>
#include <iomanip>

namespace wy {

// ═══════════════════════════════════════════════════════════
//  自定义常量
// ═══════════════════════════════════════════════════════════
// 初始向量 (IV) — 8 个 32-bit 字，取自圆周率 π 小数位
// π = 3.1415926535... → 取小数部分每8位十六进制
static const uint32_t g_hash_iv[8] = {
    0x243F6A88, 0x85A308D3, 0x13198A2E, 0x03707344,
    0xA4093822, 0x299F31D0, 0x082EFA98, 0xEC4E6C89
};

// 80轮常量 — 取自自然对数的底 e 的小数位
// e = 2.7182818284... → 每4个十六进制数字取一个32-bit字
static const uint32_t g_round_constants[80] = {
    0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5,
    0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
    0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3,
    0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
    0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC,
    0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
    0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7,
    0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
    0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13,
    0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
    0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3,
    0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
    0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5,
    0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
    0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208,
    0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2,
    0xD153FF50, 0xE2CD6E0F, 0xF2BCE984, 0xFB8FA0A3,
    0x06F0CEB2, 0x1A3F9D6E, 0x2C3E7B52, 0x4B3C0F84,
    0x5ED8AA4A, 0x6B2C15D1, 0x7C4F8A6D, 0x8D7B1C3A,
    0x9E4F7C29, 0xAFDA1A05, 0xBE1B892F, 0xCD4E66F1
};

// ═══════════════════════════════════════════════════════════
//  压缩函数 — 80 轮
// ═══════════════════════════════════════════════════════════

// 右旋
static inline uint32_t rotr32(uint32_t x, unsigned n) {
    return (x >> n) | (x << (32 - n));
}

// 消息扩展: 从 16 个 32-bit 字扩展到 80 个
static void expand_message(const uint32_t* w16, uint32_t* w80) {
    for (int i = 0; i < 16; ++i) w80[i] = w16[i];
    for (int i = 16; i < 80; ++i) {
        uint32_t s0 = rotr32(w80[i - 15], 7) ^ rotr32(w80[i - 15], 18) ^ (w80[i - 15] >> 3);
        uint32_t s1 = rotr32(w80[i - 2], 17) ^ rotr32(w80[i - 2], 19) ^ (w80[i - 2] >> 10);
        w80[i] = w80[i - 16] + s0 + w80[i - 7] + s1;
    }
}

// 压缩函数: 80轮变换
static void compress(uint32_t* state, const uint32_t* w80) {
    uint32_t a = state[0], b = state[1], c = state[2], d = state[3];
    uint32_t e = state[4], f = state[5], g = state[6], h = state[7];

    for (int i = 0; i < 80; ++i) {
        // 选择函数: Ch(e, f, g) = (e & f) ^ (~e & g)
        uint32_t ch = (e & f) ^ (~e & g);

        // 多数函数: Maj(a, b, c) = (a & b) ^ (a & c) ^ (b & c)
        uint32_t maj = (a & b) ^ (a & c) ^ (b & c);

        // Σ0 = rotr(a,2) ^ rotr(a,13) ^ rotr(a,22)
        uint32_t sigma0 = rotr32(a, 2) ^ rotr32(a, 13) ^ rotr32(a, 22);

        // Σ1 = rotr(e,6) ^ rotr(e,11) ^ rotr(e,25)
        uint32_t sigma1 = rotr32(e, 6) ^ rotr32(e, 11) ^ rotr32(e, 25);

        // 核心变换
        uint32_t t1 = h + sigma1 + ch + g_round_constants[i] + w80[i];
        uint32_t t2 = sigma0 + maj;

        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;

        // 额外扩散层: 每 8 轮做一次 shuffle
        if (i % 8 == 7) {
            uint32_t tmp = a;
            a = (a & 0x00FF00FF) | ((b & 0x00FF00FF) << 8);
            b = (b & 0xFF00FF00) | ((tmp & 0xFF00FF00) >> 8);
            tmp = c;
            c = ((c >> 16) & 0xFFFF) | ((d << 16) & 0xFFFF0000);
            d = ((d >> 16) & 0xFFFF) | ((tmp << 16) & 0xFFFF0000);
        }
    }

    state[0] += a; state[1] += b; state[2] += c; state[3] += d;
    state[4] += e; state[5] += f; state[6] += g; state[7] += h;
}

// ═══════════════════════════════════════════════════════════
//  公开接口
// ═══════════════════════════════════════════════════════════

void wy_hash_init(wy_hash_ctx* ctx) {
    for (size_t i = 0; i < WY_HASH_STATE_SIZE; ++i)
        ctx->state[i] = g_hash_iv[i];
    ctx->total_bytes = 0;
    ctx->buf_used = 0;
    std::memset(ctx->buffer, 0, WY_HASH_BLOCK_SIZE);
}

static void process_block(wy_hash_ctx* ctx, const uint8_t* block) {
    uint32_t w16[16];
    for (int i = 0; i < 16; ++i) {
        w16[i] = (static_cast<uint32_t>(block[i * 4])     << 24) |
                 (static_cast<uint32_t>(block[i * 4 + 1]) << 16) |
                 (static_cast<uint32_t>(block[i * 4 + 2]) << 8)  |
                 (static_cast<uint32_t>(block[i * 4 + 3]));
    }
    uint32_t w80[80];
    expand_message(w16, w80);
    compress(ctx->state, w80);
}

void wy_hash_update(wy_hash_ctx* ctx, const uint8_t* data, size_t len) {
    VMProtectScope _vmp_scope_auto_1("wy_hash_update");
    ctx->total_bytes += len;

    if (ctx->buf_used > 0) {
        size_t fill = std::min(WY_HASH_BLOCK_SIZE - ctx->buf_used, len);
        std::memcpy(ctx->buffer + ctx->buf_used, data, fill);
        ctx->buf_used += fill;
        if (ctx->buf_used < WY_HASH_BLOCK_SIZE) return;
        process_block(ctx, ctx->buffer);
        ctx->buf_used = 0;
        data += fill;
        len -= fill;
    }

    while (len >= WY_HASH_BLOCK_SIZE) {
        process_block(ctx, data);
        data += WY_HASH_BLOCK_SIZE;
        len -= WY_HASH_BLOCK_SIZE;
    }

    if (len > 0) {
        std::memcpy(ctx->buffer, data, len);
        ctx->buf_used = len;
    }
}

void wy_hash_final(wy_hash_ctx* ctx, uint8_t* digest) {
    VMProtectScope _vmp_scope_auto_2("wy_hash_final");
    uint64_t total_bits = ctx->total_bytes * 8;

    // 填充: 1 比特 + 0 填满 + 64-bit 长度
    size_t pad_offset = ctx->buf_used;
    ctx->buffer[pad_offset++] = 0x80; // 追加 bit '1'

    // 如果剩余空间放不下 8 字节长度，再处理一个块
    if (pad_offset > WY_HASH_BLOCK_SIZE - 8) {
        std::memset(ctx->buffer + pad_offset, 0, WY_HASH_BLOCK_SIZE - pad_offset);
        process_block(ctx, ctx->buffer);
        pad_offset = 0;
    }
    std::memset(ctx->buffer + pad_offset, 0, WY_HASH_BLOCK_SIZE - pad_offset - 8);

    // 大端写入长度
    for (int i = 0; i < 8; ++i)
        ctx->buffer[WY_HASH_BLOCK_SIZE - 8 + i] = static_cast<uint8_t>(total_bits >> (56 - i * 8));

    process_block(ctx, ctx->buffer);

    // 输出状态字（大端）
    for (size_t i = 0; i < WY_HASH_STATE_SIZE; ++i) {
        digest[i * 4]     = static_cast<uint8_t>(ctx->state[i] >> 24);
        digest[i * 4 + 1] = static_cast<uint8_t>(ctx->state[i] >> 16);
        digest[i * 4 + 2] = static_cast<uint8_t>(ctx->state[i] >> 8);
        digest[i * 4 + 3] = static_cast<uint8_t>(ctx->state[i]);
    }
}

// ═══════════════════════════════════════════════════════════
//  HMAC-WY256
// ═══════════════════════════════════════════════════════════

static const size_t HMAC_BLOCK = 64;

void wy_hmac(const uint8_t* key, size_t key_len,
             const uint8_t* data, size_t len,
             uint8_t* mac) {
    VMProtectScope _vmp_scope_auto_3("wy_hmac");
    uint8_t block_key[HMAC_BLOCK] = {};

    // 如果密钥大于块大小，先哈希
    if (key_len > HMAC_BLOCK) {
        wy_hash(key, key_len, block_key);
    } else {
        std::memcpy(block_key, key, key_len);
    }

    // i_key_pad = key ⊕ 0x36, o_key_pad = key ⊕ 0x5C
    uint8_t i_pad[HMAC_BLOCK], o_pad[HMAC_BLOCK];
    for (size_t i = 0; i < HMAC_BLOCK; ++i) {
        i_pad[i] = block_key[i] ^ 0x36;
        o_pad[i] = block_key[i] ^ 0x5C;
    }

    // inner = H(i_key_pad || message)
    uint8_t inner_hash[WY_HASH_OUTPUT_SIZE];
    wy_hash_ctx ctx;
    wy_hash_init(&ctx);
    wy_hash_update(&ctx, i_pad, HMAC_BLOCK);
    wy_hash_update(&ctx, data, len);
    wy_hash_final(&ctx, inner_hash);

    // MAC = H(o_key_pad || inner)
    wy_hash_init(&ctx);
    wy_hash_update(&ctx, o_pad, HMAC_BLOCK);
    wy_hash_update(&ctx, inner_hash, WY_HASH_OUTPUT_SIZE);
    wy_hash_final(&ctx, mac);

    // 安全清零
    std::memset(block_key, 0, sizeof(block_key));
    std::memset(i_pad, 0, sizeof(i_pad));
    std::memset(o_pad, 0, sizeof(o_pad));
    std::memset(inner_hash, 0, sizeof(inner_hash));
}

// ═══════════════════════════════════════════════════════════
//  HKDF
// ═══════════════════════════════════════════════════════════

void wy_hkdf_expand(const uint8_t* prk, size_t prk_len,
                    const uint8_t* info, size_t info_len,
                    uint8_t* out, size_t out_len) {
    size_t blocks = (out_len + WY_HASH_OUTPUT_SIZE - 1) / WY_HASH_OUTPUT_SIZE;
    uint8_t prev[WY_HASH_OUTPUT_SIZE] = {};
    size_t prev_len = 0;

    for (size_t i = 0; i < blocks; ++i) {
        // T(i) = HMAC(prk, T(i-1) || info || byte(i+1))
        uint8_t* block = (i < blocks - 1 || out_len % WY_HASH_OUTPUT_SIZE == 0)
                          ? out + i * WY_HASH_OUTPUT_SIZE
                          : out + i * WY_HASH_OUTPUT_SIZE;

        wy_hash_ctx ctx;
        wy_hash_init(&ctx);
        if (prev_len > 0) wy_hash_update(&ctx, prev, prev_len);
        if (info_len > 0) wy_hash_update(&ctx, info, info_len);
        uint8_t counter = static_cast<uint8_t>(i + 1);
        wy_hash_update(&ctx, &counter, 1);
        uint8_t temp[WY_HASH_OUTPUT_SIZE];
        wy_hash_final(&ctx, temp);

        // 对 temp 做 HMAC
        wy_hmac(prk, prk_len, temp, WY_HASH_OUTPUT_SIZE, block);
        std::memcpy(prev, block, WY_HASH_OUTPUT_SIZE);
        prev_len = WY_HASH_OUTPUT_SIZE;
    }
}

void wy_hkdf(const uint8_t* ikm, size_t ikm_len,
             const uint8_t* salt, size_t salt_len,
             const uint8_t* info, size_t info_len,
             uint8_t* out, size_t out_len) {
    VMProtectScope _vmp_scope_auto_4("wy_hkdf");
    // Extract: PRK = HMAC(salt, ikm)
    uint8_t prk[WY_HASH_OUTPUT_SIZE];
    uint8_t default_salt[WY_HASH_OUTPUT_SIZE] = {};
    if (!salt) { salt = default_salt; salt_len = WY_HASH_OUTPUT_SIZE; }
    wy_hmac(salt, salt_len, ikm, ikm_len, prk);

    // Expand
    wy_hkdf_expand(prk, WY_HASH_OUTPUT_SIZE, info, info_len, out, out_len);

    std::memset(prk, 0, sizeof(prk));
}

// ═══════════════════════════════════════════════════════════
//  工具函数
// ═══════════════════════════════════════════════════════════

std::string wy_hash_to_hex(const uint8_t* digest) {
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (size_t i = 0; i < WY_HASH_OUTPUT_SIZE; ++i)
        oss << std::setw(2) << static_cast<unsigned>(digest[i]);
    return oss.str();
}

bool wy_const_time_eq(const uint8_t* a, const uint8_t* b, size_t len) {
    uint8_t diff = 0;
    for (size_t i = 0; i < len; ++i)
        diff |= (a[i] ^ b[i]);
    return diff == 0;
}

} // namespace wy
