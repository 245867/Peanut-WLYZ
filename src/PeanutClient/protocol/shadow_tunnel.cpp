// ============================================================
// PeanutSecure Protocol (PSP) v2.0 — 自研加密协议实现
// 使用 WY-RSA + WY-Cipher + WY-Hash 三层加密
// 全部使用项目自研算法
// ============================================================

#include "shadow_tunnel.h"

// 自研加密库
#include "../crypto/wy_cipher.h"
#include "../vmprotect_markers.h"
#include "../crypto/wy_rsa.h"
#include "../crypto/wy_hash.h"
#include "../crypto/wy_random.h"
#include "../vmprotect_markers.h"

#include <cstring>
#include <algorithm>

namespace peanut {
namespace psp {

// ═══════════════════════════════════════════════════════════
//  内部: 帧序列化/反序列化
// ═══════════════════════════════════════════════════════════

// 布局:
//   [PspHeader 14B] [rsa_key 256B] [IV 16B] [ciphertext NB] [HMAC 32B]

static std::vector<uint8_t> serialize_frame(const PspFrame& frame) {
    // 计算总长度
    size_t total = PSP_HEADER_SIZE + frame.rsa_key_block.size()
                   + PSP_IV_SIZE + frame.ciphertext.size() + PSP_HASH_SIZE;

    std::vector<uint8_t> buf(total);
    size_t off = 0;

    // 1. 帧头
    std::memcpy(buf.data() + off, &frame.header, PSP_HEADER_SIZE);
    off += PSP_HEADER_SIZE;

    // 2. RSA 密钥块
    std::memcpy(buf.data() + off, frame.rsa_key_block.data(), frame.rsa_key_block.size());
    off += frame.rsa_key_block.size();

    // 3. IV
    std::memcpy(buf.data() + off, frame.iv.data(), PSP_IV_SIZE);
    off += PSP_IV_SIZE;

    // 4. 密文
    std::memcpy(buf.data() + off, frame.ciphertext.data(), frame.ciphertext.size());
    off += frame.ciphertext.size();

    // 5. HMAC
    std::memcpy(buf.data() + off, frame.hmac.data(), PSP_HASH_SIZE);

    return buf;
}

static bool deserialize_frame(const uint8_t* data, size_t len, PspFrame& frame) {
    if (len < PSP_MIN_FRAME) return false;

    size_t off = 0;

    // 1. 帧头
    std::memcpy(&frame.header, data + off, PSP_HEADER_SIZE);
    off += PSP_HEADER_SIZE;

    // 校验 magic
    if (frame.header.magic0 != PSP_MAGIC0 || frame.header.magic1 != PSP_MAGIC1)
        return false;

    // 2. RSA 密钥块 (固定 256B)
    frame.rsa_key_block.resize(PSP_RSA_BLOCK);
    std::memcpy(frame.rsa_key_block.data(), data + off, PSP_RSA_BLOCK);
    off += PSP_RSA_BLOCK;

    // 3. IV (固定 16B)
    std::memcpy(frame.iv.data(), data + off, PSP_IV_SIZE);
    off += PSP_IV_SIZE;

    // 4. 密文 (剩余 - HMAC大小)
    size_t ct_len = frame.header.payload_len;
    if (off + ct_len + PSP_HASH_SIZE > len) return false;

    frame.ciphertext.resize(ct_len);
    std::memcpy(frame.ciphertext.data(), data + off, ct_len);
    off += ct_len;

    // 5. HMAC
    std::memcpy(frame.hmac.data(), data + off, PSP_HASH_SIZE);

    return true;
}

// ═══════════════════════════════════════════════════════════
//  Encoder
// ═══════════════════════════════════════════════════════════

Encoder::Encoder() {
    // 生成随机会话ID
    wy::wy_random_bytes(sid_.data(), PSP_SESSION_ID_SIZE);
}

Encoder::~Encoder() {
    // 安全擦除密钥
    std::memset(session_key_.data(), 0, PSP_KEY_SIZE);
    std::memset(sid_.data(), 0, PSP_SESSION_ID_SIZE);
}

void Encoder::set_psk_hex(const std::string& key_hex) {
    psk_hex_ = key_hex;
}

void Encoder::set_rsa_pubkey_hex(const std::string& key_hex) {
    rsa_pubkey_ = wy::wy_rsa_pubkey_from_hex(key_hex);
    have_rsa_pubkey_ = !rsa_pubkey_.n.is_zero();
}

void Encoder::set_rsa_pubkey_raw(const uint8_t* /*n*/, const uint8_t* /*e*/) {
    // 保留接口；优先使用 set_rsa_pubkey_hex
}

const std::array<uint8_t, PSP_SESSION_ID_SIZE>& Encoder::session_id() const {
    return sid_;
}

std::vector<uint8_t> Encoder::build_handshake_init() {
    VMProtectScope _vmp_scope_auto_1("build_handshake_init");
    // 1. 生成随机 256-bit 会话密钥
    wy::wy_random_bytes(session_key_.data(), PSP_KEY_SIZE);

    // 2. 用服务端 RSA 公钥加密会话密钥 → 256B 块
    std::vector<uint8_t> rsa_block(PSP_RSA_BLOCK, 0);
    if (have_rsa_pubkey_) {
        auto enc = wy::wy_rsa_encrypt(session_key_.data(), PSP_KEY_SIZE, &rsa_pubkey_);
        if (enc.size() == PSP_RSA_BLOCK)
            rsa_block = std::move(enc);
    } else {
        // 无公钥时不能安全握手；仍填随机以免崩溃，服务端应拒绝
        wy::wy_random_bytes(rsa_block.data(), PSP_RSA_BLOCK);
    }
    rsa_key_block_ = rsa_block;

    // 3. 载荷 = [SessionID 16B] + [prove 32B]
    std::vector<uint8_t> payload(PSP_SESSION_ID_SIZE + PSP_HASH_SIZE);
    std::memcpy(payload.data(), sid_.data(), PSP_SESSION_ID_SIZE);

    const char* prove_str = "PSP-HANDSHAKE-V2";
    wy::wy_hmac(session_key_.data(), PSP_KEY_SIZE,
                reinterpret_cast<const uint8_t*>(prove_str),
                std::strlen(prove_str),
                payload.data() + PSP_SESSION_ID_SIZE);

    uint8_t iv[PSP_IV_SIZE];
    wy::wy_random_bytes(iv, PSP_IV_SIZE);

    wy::wy_cipher_key cipher_key;
    wy::wy_cipher_key_schedule(session_key_.data(), &cipher_key);
    auto ct = wy::wy_cbc_encrypt(&cipher_key, iv, payload.data(), payload.size());

    PspFrame frame;
    frame.header.magic0      = PSP_MAGIC0;
    frame.header.magic1      = PSP_MAGIC1;
    frame.header.version     = PSP_VERSION;
    frame.header.type        = static_cast<uint8_t>(FrameType::HANDSHAKE_INIT);
    frame.header.seq_number  = 0;
    frame.header.payload_len = static_cast<uint16_t>(ct.size());
    frame.header.checksum    = 0;
    frame.header.padding     = 0;
    frame.header.checksum    = header_checksum(frame.header);

    frame.rsa_key_block = rsa_block;
    std::memcpy(frame.iv.data(), iv, PSP_IV_SIZE);
    frame.ciphertext = ct;

    std::vector<uint8_t> mac_input;
    mac_input.insert(mac_input.end(),
                     reinterpret_cast<const uint8_t*>(&frame.header),
                     reinterpret_cast<const uint8_t*>(&frame.header) + PSP_HEADER_SIZE);
    mac_input.insert(mac_input.end(), frame.rsa_key_block.begin(), frame.rsa_key_block.end());
    mac_input.insert(mac_input.end(), frame.iv.begin(), frame.iv.end());
    mac_input.insert(mac_input.end(), frame.ciphertext.begin(), frame.ciphertext.end());

    wy::wy_hmac(session_key_.data(), PSP_KEY_SIZE,
                mac_input.data(), mac_input.size(),
                frame.hmac.data());

    std::memset(iv, 0, sizeof(iv));
    return serialize_frame(frame);
}

std::vector<uint8_t> Encoder::wrap(const std::vector<uint8_t>& inner_payload) {
    VMProtectScope _vmp_scope_auto_2("wrap");
    ++seq_;

    // 1. WY-Cipher CBC 加密业务数据
    uint8_t iv[PSP_IV_SIZE];
    wy::wy_random_bytes(iv, PSP_IV_SIZE);

    wy::wy_cipher_key cipher_key;
    wy::wy_cipher_key_schedule(session_key_.data(), &cipher_key);

    auto ct = wy::wy_cbc_encrypt(&cipher_key, iv,
                                  inner_payload.data(), inner_payload.size());

    // 2. 构建帧
    PspFrame frame;
    frame.header.magic0      = PSP_MAGIC0;
    frame.header.magic1      = PSP_MAGIC1;
    frame.header.version     = PSP_VERSION;
    frame.header.type        = static_cast<uint8_t>(FrameType::DATA);
    frame.header.seq_number  = seq_;
    frame.header.payload_len = static_cast<uint16_t>(ct.size());
    frame.header.checksum    = 0;
    frame.header.padding     = 0;

    frame.header.checksum = header_checksum(frame.header);

    // RSA 密钥块: 使用缓存的 RSA 加密会话密钥 (握手时已生成)
    frame.rsa_key_block = rsa_key_block_;
    if (frame.rsa_key_block.size() != PSP_RSA_BLOCK) {
        // 未缓存则填充随机 (上层应在握手时填充)
        frame.rsa_key_block.resize(PSP_RSA_BLOCK);
        wy::wy_random_bytes(frame.rsa_key_block.data(), PSP_RSA_BLOCK);
    }

    std::memcpy(frame.iv.data(), iv, PSP_IV_SIZE);
    frame.ciphertext = ct;

    // 3. HMAC
    std::vector<uint8_t> mac_input;
    mac_input.insert(mac_input.end(),
                     reinterpret_cast<const uint8_t*>(&frame.header),
                     reinterpret_cast<const uint8_t*>(&frame.header) + PSP_HEADER_SIZE);
    mac_input.insert(mac_input.end(), frame.rsa_key_block.begin(), frame.rsa_key_block.end());
    mac_input.insert(mac_input.end(), frame.iv.begin(), frame.iv.end());
    mac_input.insert(mac_input.end(), frame.ciphertext.begin(), frame.ciphertext.end());

    wy::wy_hmac(session_key_.data(), PSP_KEY_SIZE,
                mac_input.data(), mac_input.size(),
                frame.hmac.data());

    std::memset(iv, 0, sizeof(iv));

    return serialize_frame(frame);
}

void Encoder::confirm_session() {
    session_confirmed_ = true;
}

// ═══════════════════════════════════════════════════════════
//  Decoder
// ═══════════════════════════════════════════════════════════

Decoder::Decoder() {}
Decoder::~Decoder() {
    std::memset(session_key_.data(), 0, PSP_KEY_SIZE);
}

void Decoder::set_psk_hex(const std::string& /*key_hex*/) {
    // TODO: 存储 PSK
}

void Decoder::set_rsa_prikey_hex(const std::string& /*key_hex*/) {
    have_rsa_prikey_ = true;
    // TODO: 存储 RSA 私钥
}

void Decoder::load_session(const PspSession& session) {
    std::memcpy(session_key_.data(), session.session_key.data(), PSP_KEY_SIZE);
    last_seq_ = session.last_seq;
    have_session_ = true;
}

DecodeResult Decoder::decode(const uint8_t* data, size_t len) {
    VMProtectScope _vmp_scope_auto_3("decode");
    DecodeResult result;

    // 长度检查
    if (len < PSP_MIN_FRAME) {
        result.error_code = ErrorCode::ERR_INTERNAL;
        return result;
    }

    // 反序列化
    PspFrame frame;
    if (!deserialize_frame(data, len, frame)) {
        result.error_code = ErrorCode::ERR_MAGIC;
        return result;
    }

    // 版本检查
    if (frame.header.version != PSP_VERSION) {
        result.error_code = ErrorCode::ERR_VERSION;
        return result;
    }

    // CRC 校验
    uint16_t computed_crc = header_checksum(frame.header);
    if (computed_crc != frame.header.checksum) {
        result.error_code = ErrorCode::ERR_INTERNAL;
        return result;
    }

    // 序列号检查 (防重放)
    if (frame.header.type != static_cast<uint8_t>(FrameType::HANDSHAKE_RESP)) {
        if (frame.header.seq_number <= last_seq_) {
            result.error_code = ErrorCode::ERR_SEQ;
            return result;
        }
    }

    // 序列号跳跃窗口 (允许跳跃 ≤100)
    if (frame.header.seq_number > last_seq_ + 100 && last_seq_ > 0) {
        result.error_code = ErrorCode::ERR_SEQ;
        return result;
    }

    // HMAC 验证
    std::vector<uint8_t> mac_input;
    mac_input.insert(mac_input.end(),
                     reinterpret_cast<const uint8_t*>(&frame.header),
                     reinterpret_cast<const uint8_t*>(&frame.header) + PSP_HEADER_SIZE);
    mac_input.insert(mac_input.end(), frame.rsa_key_block.begin(), frame.rsa_key_block.end());
    mac_input.insert(mac_input.end(), frame.iv.begin(), frame.iv.end());
    mac_input.insert(mac_input.end(), frame.ciphertext.begin(), frame.ciphertext.end());

    uint8_t computed_hmac[PSP_HASH_SIZE];
    wy::wy_hmac(session_key_.data(), PSP_KEY_SIZE,
                mac_input.data(), mac_input.size(),
                computed_hmac);

    if (!wy::wy_const_time_eq(computed_hmac, frame.hmac.data(), PSP_HASH_SIZE)) {
        result.error_code = ErrorCode::ERR_HMAC;
        std::memset(computed_hmac, 0, sizeof(computed_hmac));
        return result;
    }
    std::memset(computed_hmac, 0, sizeof(computed_hmac));

    // WY-Cipher 解密
    wy::wy_cipher_key cipher_key;
    wy::wy_cipher_key_schedule(session_key_.data(), &cipher_key);

    auto pt = wy::wy_cbc_decrypt(&cipher_key, frame.iv.data(),
                                  frame.ciphertext.data(), frame.ciphertext.size());

    // 更新序列号
    if (frame.header.seq_number > last_seq_)
        last_seq_ = frame.header.seq_number;

    result.success = true;
    result.error_code = ErrorCode::OK;
    result.inner_payload = pt;
    result.seq_number = frame.header.seq_number;
    result.frame_type = static_cast<FrameType>(frame.header.type);

    return result;
}

} // namespace psp
} // namespace peanut
