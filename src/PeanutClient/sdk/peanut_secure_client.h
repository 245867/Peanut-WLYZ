// ============================================================
// PeanutSecure Client SDK — 使用自研 WY 加密库
// v2.0 纯自研算法
// ============================================================

#pragma once

#include <string>
#include <vector>
#include <functional>
#include <memory>
#include <atomic>
#include <mutex>

#include "../protocol/shadow_tunnel.h"
#include "../crypto/wy_cipher.h"
#include "../crypto/wy_hash.h"
#include "../crypto/wy_rsa.h"
#include "../crypto/wy_random.h"
#include "../api/client_api.h"
#include "nlohmann/json.hpp"

namespace peanut {
namespace sdk {

// ── 传输模式 ───────────────────────────────────────────────
enum class TransportMode {
    HTTP = 0,
    TCP  = 1
};

// ── 连接状态 ───────────────────────────────────────────────
enum class ConnectionState {
    DISCONNECTED = 0,
    CONNECTING   = 1,
    HANDSHAKING  = 2,
    CONNECTED    = 3,
    CONN_ERROR   = 4
};

struct UpdatePolicy {
    bool force_update = false;
    bool build_revoked = false;
    std::string latest_version;
    std::string minimum_version;
    std::string target_file;
    std::string target_sha256;
    std::string package_id;
    std::string package_sha256;
    long long package_size = 0;
    unsigned long long manifest_version = 0;
};

struct SessionPolicy {
    bool multi_open_enabled = false;
    int max_online_per_card = 1;
};

// ── 日志回调 ───────────────────────────────────────────────
using LogCallback = std::function<void(const std::string&, int level)>;
using StateCallback = std::function<void(ConnectionState state)>;

// ── PeanutSecure客户端SDK ─────────────────────────────────
class PeanutSecureClient {
public:
    PeanutSecureClient();
    ~PeanutSecureClient();

    void SetServer(const std::string& host, int port);
    void SetTransportMode(TransportMode mode);
    void SetCredentials(const std::string& hmac_key, const std::string& cipher_key_hex);
    void SetPSPKey(const std::string& psp_key_hex);
    // 服务端 RSA 公钥 hex (n:e)，握手加密会话密钥用；也可从 keys/server_pubkey.hex 加载
    void SetServerRsaPubkeyHex(const std::string& pubkey_hex);
    bool LoadKeysFromDir(const std::string& key_dir);
    void SetCallbacks(LogCallback log_cb, StateCallback state_cb = nullptr);

    bool Connect();
    void Disconnect();
    bool IsConnected() const;
    ConnectionState GetState() const;

    bool FetchConfigInfo(std::string& announcement, std::string& version);
    bool FetchSessionPolicy(SessionPolicy& out_policy,
                            std::string* out_error = nullptr);
    bool FetchUpdatePolicy(const std::string& product_id,
                           const std::string& client_version,
                           const std::string& build_hash,
                           UpdatePolicy& out_policy,
                           std::string* out_error = nullptr);
    bool Activate(const std::string& cardkey, const std::string& machinecode,
                  std::string& out_token, std::string* out_error = nullptr);
    bool FetchPluginList(const std::string& token,
                         std::vector<CloudPluginInfo>& out_plugins,
                         std::string* out_error = nullptr);
    bool CallPlugin(const std::string& token,
                    const std::string& plugin_name,
                    const std::string& input,
                    std::string& out_result,
                    std::string* out_error = nullptr);
    bool SendHeartbeat(const std::string& token,
                      std::string& out_card_status, int& out_usage_minutes,
                      long long& out_remaining_seconds);
    bool Logout(const std::string& token);
    bool DeactivateCard(const std::string& token, const std::string& cardkey);
    bool DownloadUpdatePackage(const std::string& package_id,
                               std::vector<uint8_t>& out_data,
                               std::string* out_error = nullptr);

    bool TCPSend(const std::vector<uint8_t>& data);
    bool TCPReceive(std::vector<uint8_t>& out_data, int timeout_ms = 5000);

    const std::string& GetSessionID() const { return session_id_; }
    uint32_t GetSessionSeq() const { return session_seq_; }
    const std::string& GetServerHost() const { return host_; }
    int GetServerPort() const { return port_; }
    long long GetLastActivationRemainingSeconds() const { return last_activation_remaining_seconds_; }
    const std::string& GetLastServerError() const { return last_server_error_; }

private:
    bool SendRequest(const std::string& path, const std::string& encrypted_body,
                    std::string& out_response);
    bool DecryptResponse(const std::string& body, std::string& out_json);
    bool VerifySignedResponse(const std::string& json_str,
                             nlohmann::ordered_json& out_resp);

    bool PSPHandshake();
    std::vector<uint8_t> PSPWrapAndEncode(const std::vector<uint8_t>& inner);
    bool PSPUnwrapAndDecode(const std::string& body,
                          std::vector<uint8_t>& out_inner);

    void Log(int level, const std::string& msg);

    // 配置
    std::string host_;
    int port_ = 9001;
    TransportMode transport_mode_ = TransportMode::TCP;

    // 密钥
    std::string hmac_key_;
    std::string cipher_key_hex_;   // WY-Cipher 预共享密钥
    std::string psp_key_hex_;
    std::string rsa_pubkey_hex_;   // 服务端公钥 n:e

    // PSP
    std::unique_ptr<peanut::psp::Encoder> psp_encoder_;
    std::string session_id_;
    uint32_t session_seq_ = 0;

    // 状态
    std::atomic<ConnectionState> state_{ConnectionState::DISCONNECTED};
    std::string last_server_error_;
    mutable std::mutex mutex_;

    // 传输
    uintptr_t tcp_socket_ = static_cast<uintptr_t>(~0ULL);
    bool tcp_connected_ = false;
    long long last_activation_remaining_seconds_ = 0;

    // 回调
    LogCallback log_cb_;
    StateCallback state_cb_;
};

// ── 密钥生成 ───────────────────────────────────────────────
std::string GenerateWYCipherKeyHex();
std::string GeneratePSPKeyHex();

} // namespace sdk
} // namespace peanut
