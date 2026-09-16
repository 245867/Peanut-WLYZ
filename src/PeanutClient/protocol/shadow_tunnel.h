// ============================================================
// PeanutSecure Protocol (PSP) v2.0 — 自研加密协议
// 使用 WY-RSA + WY-Cipher + WY-Hash 三层加密
// 全部使用项目自研算法
// ============================================================

#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include <array>
#include <ctime>

#include "../crypto/wy_rsa.h"

namespace peanut {
namespace psp {

// ── 帧格式常量 ─────────────────────────────────────────────
constexpr uint8_t  PSP_MAGIC0          = 0x57;       // 'W'
constexpr uint8_t  PSP_MAGIC1          = 0x59;       // 'Y'
constexpr uint8_t  PSP_VERSION         = 0x02;       // v2.0 (纯自研算法)
constexpr size_t   PSP_HEADER_SIZE     = 14;         // 帧头字节数
constexpr size_t   PSP_RSA_BLOCK       = 256;        // RSA-2048 密文块
constexpr size_t   PSP_CIPHER_BLOCK    = 32;         // WY-Cipher 块大小
constexpr size_t   PSP_HASH_SIZE       = 32;         // WY-Hash 256 输出
constexpr size_t   PSP_IV_SIZE         = 16;         // CBC IV
constexpr size_t   PSP_KEY_SIZE        = 32;         // 256-bit 密钥
constexpr size_t   PSP_SESSION_ID_SIZE = 16;         // 会话随机ID
constexpr size_t   PSP_MAX_PADDING     = 127;        // PKCS7 最大填充

// ── 帧类型 ─────────────────────────────────────────────────
enum class FrameType : uint8_t {
    DATA            = 0x01,   // 正常数据帧 (已加密)
    HANDSHAKE_INIT  = 0x02,   // 握手初始化 (客户端→服务端, 含RSA加密的会话密钥)
    HANDSHAKE_RESP  = 0x03,   // 握手响应 (服务端→客户端)
    HANDSHAKE_ACK   = 0x04,   // 握手确认
    FRAME_ERROR     = 0xFF    // 错误帧
};

// ── 错误码 ─────────────────────────────────────────────────
enum class ErrorCode : uint8_t {
    OK              = 0x00,
    ERR_MAGIC       = 0x01,
    ERR_VERSION     = 0x02,
    ERR_SEQ         = 0x03,
    ERR_HMAC        = 0x04,   // HMAC 校验失败
    ERR_SESSION     = 0x05,
    ERR_INTERNAL    = 0x06,
    ERR_DECRYPT_WY  = 0x07,   // WY-Cipher 解密失败
    ERR_DECRYPT_RSA = 0x08,   // RSA 解密失败
    ERR_NETWORK     = 0x09
};

// ── 会话状态 ───────────────────────────────────────────────
enum class SessionState : uint8_t {
    IDLE        = 0x00,
    HANDSHAKING = 0x01,
    ACTIVE      = 0x02,
    CLOSED      = 0x03
};

// ── PSP v2.0 帧头 ──────────────────────────────────────────
#pragma pack(push, 1)
struct PspHeader {
    uint8_t  magic0;          // 0x57
    uint8_t  magic1;          // 0x59
    uint8_t  version;         // 0x02 (v2.0自研算法)
    uint8_t  type;            // FrameType
    uint32_t seq_number;      // 序列号 (LE, 单调递增)
    uint16_t payload_len;     // 加密负载长度 (LE)
    uint16_t checksum;        // CRC16 of header[0:12]
    uint16_t padding;         // 保留对齐
};
#pragma pack(pop)

static_assert(sizeof(PspHeader) == PSP_HEADER_SIZE, "PspHeader size mismatch");

// ── PSP 帧 (完整) ──────────────────────────────────────────
// 布局:
//   [PspHeader 14B]
//   [Encrypted Session Key 256B]    ← WY-RSA 加密的 WY-Cipher 会话密钥
//   [IV 16B]                        ← CBC 初始向量
//   [Ciphertext NB]                 ← WY-Cipher CBC 密文
//   [HMAC 32B]                      ← WY-HMAC(会话密钥, 帧头||密钥块||IV||密文)

constexpr size_t PSP_MIN_FRAME = PSP_HEADER_SIZE + PSP_RSA_BLOCK + PSP_IV_SIZE + PSP_HASH_SIZE;
// = 14 + 256 + 16 + 32 = 318 bytes 最小帧

struct PspFrame {
    PspHeader               header;
    std::vector<uint8_t>    rsa_key_block;   // RSA 加密的会话密钥 (256B)
    std::array<uint8_t, PSP_IV_SIZE> iv;    // CBC IV
    std::vector<uint8_t>    ciphertext;      // WY-Cipher 密文
    std::array<uint8_t, PSP_HASH_SIZE> hmac; // WY-HMAC
};

// ── 解码结果 ───────────────────────────────────────────────
struct DecodeResult {
    bool                success     = false;
    ErrorCode           error_code  = ErrorCode::OK;
    std::vector<uint8_t> inner_payload;   // 解密后的业务数据
    uint32_t            seq_number  = 0;
    FrameType           frame_type  = FrameType::DATA;
};

// ── 会话 ───────────────────────────────────────────────────
struct PspSession {
    std::array<uint8_t, PSP_SESSION_ID_SIZE> session_id;
    std::array<uint8_t, PSP_KEY_SIZE>        session_key;  // WY-Cipher 会话密钥
    uint32_t                                 last_seq = 0;
    std::time_t                              created_at = 0;
    std::time_t                              last_active = 0;
    SessionState                             state = SessionState::IDLE;
};

// ═══════════════════════════════════════════════════════════
//  Encoder (发送端 — 客户端)
// ═══════════════════════════════════════════════════════════
class Encoder {
public:
    Encoder();
    ~Encoder();

    // 设置 RSA 公钥 (服务端公钥, hex字符串, 512字符n + 8字符e)
    void set_rsa_pubkey_hex(const std::string& key_hex);
    void set_rsa_pubkey_raw(const uint8_t* n, const uint8_t* e);

    // 设置 WY-Cipher 预共享密钥 (用于派生会话密钥的种子)
    void set_psk_hex(const std::string& key_hex);

    // 会话ID
    const std::array<uint8_t, PSP_SESSION_ID_SIZE>& session_id() const;

    // 构建握手初始化帧:
    //   1. 生成随机会话密钥 (256-bit)
    //   2. 用服务端 RSA 公钥加密会话密钥
    //   3. 帧载荷: [SessionID 16B] + [WY-HMAC证明]
    //   返回完整帧字节
    std::vector<uint8_t> build_handshake_init();

    // 包装业务数据:
    //   1. WY-Cipher CBC 加密业务数据 (用会话密钥)
    //   2. WY-HMAC 认证
    //   3. RSA 密钥块 (已缓存, 握手时加密的会话密钥)
    //   返回完整帧字节
    std::vector<uint8_t> wrap(const std::vector<uint8_t>& inner_payload);

    // 确认会话
    void confirm_session();

    uint32_t current_seq() const { return seq_; }

private:
    std::array<uint8_t, PSP_SESSION_ID_SIZE> sid_;
    std::array<uint8_t, PSP_KEY_SIZE>        session_key_;   // WY-Cipher 会话密钥
    std::vector<uint8_t>                     rsa_key_block_; // RSA加密的会话密钥 (缓存)
    wy::wy_rsa_pubkey                        rsa_pubkey_{};
    std::string                              psk_hex_;
    uint32_t                                 seq_ = 0;
    bool                                     session_confirmed_ = false;
    bool                                     have_rsa_pubkey_ = false;
};

// ═══════════════════════════════════════════════════════════
//  Decoder (接收端 — 客户端解密服务端响应)
// ═══════════════════════════════════════════════════════════
class Decoder {
public:
    Decoder();
    ~Decoder();

    // 设置 RSA 私钥 (客户端私钥, hex)
    void set_rsa_prikey_hex(const std::string& key_hex);

    // 设置预共享密钥种子
    void set_psk_hex(const std::string& key_hex);

    // 加载会话 (握手成功后)
    void load_session(const PspSession& session);

    // 解码 PSP 帧 → 提取内层业务数据
    DecodeResult decode(const uint8_t* data, size_t len);

private:
    std::array<uint8_t, PSP_KEY_SIZE> session_key_;
    uint32_t                          last_seq_ = 0;
    bool                              have_session_ = false;
    bool                              have_rsa_prikey_ = false;
};

// ── CRC16 (CCITT) ──────────────────────────────────────────
inline uint16_t crc16_ccitt(const uint8_t* data, size_t len) {
    uint16_t crc = 0xFFFF;
    for (size_t i = 0; i < len; ++i) {
        crc ^= static_cast<uint16_t>(data[i]) << 8;
        for (int j = 0; j < 8; ++j)
            crc = (crc & 0x8000) ? ((crc << 1) ^ 0x1021) : (crc << 1);
    }
    return crc;
}

inline uint16_t header_checksum(const PspHeader& hdr) {
    // First 10 bytes only (exclude checksum + padding)
    return crc16_ccitt(reinterpret_cast<const uint8_t*>(&hdr), 10);
}

} // namespace psp
} // namespace peanut
