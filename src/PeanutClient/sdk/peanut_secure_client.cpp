// ============================================================
// PeanutSecure Client SDK — 实现
// v2.0 纯自研 WY 加密
// ============================================================

#include "peanut_secure_client.h"

#include "../api/client_api.h"
#include "../crypto/key_files.h"
#include "../util/util.h"
#include "../vmprotect_markers.h"
#include "../sdk/anti_debug.h"

#include <httplib.h>
#include <sstream>
#include <iomanip>
#include <ctime>
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")

namespace peanut {
namespace sdk {

static std::string LocalizeServerMessage(const std::string& message) {
    if (message == "card unavailable or bound" || message == "device binding rejected") return "该卡密已绑定其他电脑，请先在服务端解绑";
    if (message == "card not found") return "卡密不存在，请检查输入是否正确";
    if (message == "invalid session" || message == "server rejected session") return "登录会话无效或已过期，请重新登录";
    if (message == "expired") return "授权已经过期，请重新登录";
    if (message == "plugin not found") return "云函数不存在或未启用";
    if (message == "plugin exec fail") return "云函数执行失败";
    if (message == "bad signature") return "请求签名校验失败";
    if (message == "bad request") return "请求格式错误";
    return message.empty() ? "服务端拒绝了本次请求" : message;
}

// ── 辅助函数 ───────────────────────────────────────────────

static std::string random_hex(int bytes) {
    uint8_t buf[64];
    wy::wy_random_bytes(buf, bytes);
    std::stringstream ss;
    ss << std::hex << std::uppercase << std::setfill('0');
    for (int i = 0; i < bytes; ++i)
        ss << std::setw(2) << static_cast<int>(buf[i]);
    return ss.str();
}

static std::string sha256_hex(const std::string& data) {
    uint8_t hash[wy::WY_HASH_OUTPUT_SIZE];
    wy::wy_hash(reinterpret_cast<const uint8_t*>(data.data()), data.size(), hash);
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (size_t i = 0; i < wy::WY_HASH_OUTPUT_SIZE; ++i)
        ss << std::setw(2) << static_cast<int>(hash[i]);
    return ss.str();
}

// ── 密钥生成 ───────────────────────────────────────────────

std::string GenerateWYCipherKeyHex() {
    return wy::wy_cipher_generate_key_hex();
}

std::string GeneratePSPKeyHex() {
    return random_hex(32);
}

// ═══════════════════════════════════════════════════════════
//  PeanutSecureClient 实现
// ═══════════════════════════════════════════════════════════

PeanutSecureClient::PeanutSecureClient() {
    psp_encoder_ = std::make_unique<peanut::psp::Encoder>();
}

PeanutSecureClient::~PeanutSecureClient() {
    Disconnect();
}

void PeanutSecureClient::SetServer(const std::string& host, int port) {
    host_ = host;
    port_ = port;
}

void PeanutSecureClient::SetTransportMode(TransportMode mode) {
    transport_mode_ = mode;
}

void PeanutSecureClient::SetCredentials(const std::string& hmac_key,
                                         const std::string& cipher_key_hex) {
    hmac_key_ = hmac_key;
    cipher_key_hex_ = cipher_key_hex;
}

void PeanutSecureClient::SetPSPKey(const std::string& psp_key_hex) {
    psp_key_hex_ = psp_key_hex;
    if (psp_encoder_)
        psp_encoder_->set_psk_hex(psp_key_hex);
}

void PeanutSecureClient::SetServerRsaPubkeyHex(const std::string& pubkey_hex) {
    rsa_pubkey_hex_ = pubkey_hex;
    if (psp_encoder_)
        psp_encoder_->set_rsa_pubkey_hex(pubkey_hex);
}

bool PeanutSecureClient::LoadKeysFromDir(const std::string& key_dir) {
    wy::wy_rsa_pubkey pub;
    if (!peanut::keys::LoadServerPubkey(key_dir, pub)) {
        Log(3, "加载 server_pubkey.hex 失败: " + key_dir);
        return false;
    }
    SetServerRsaPubkeyHex(wy::wy_rsa_pubkey_to_hex(&pub));

    std::string cipher, hmac, psp;
    if (!peanut::keys::LoadCipherKeyHex(key_dir, cipher) ||
        !peanut::keys::LoadHmacKey(key_dir, hmac)) {
        Log(3, "加载 cipher/hmac 密钥失败");
        return false;
    }
    SetCredentials(hmac, cipher);
    if (peanut::keys::LoadPspKeyHex(key_dir, psp))
        SetPSPKey(psp);
    Log(1, "已从本地密钥目录加载: " + key_dir);
    return true;
}

void PeanutSecureClient::SetCallbacks(LogCallback log_cb, StateCallback state_cb) {
    log_cb_ = log_cb;
    state_cb_ = state_cb;
}

bool PeanutSecureClient::Connect() {
    if (!security::antidebug::QuickCheck()) { Log(3, "anti-debug check failed"); return false; }
    VMProtectScope _vmp_scope_Connect("Connect");
    state_ = ConnectionState::CONNECTING;

    // TCP 模式
    if (transport_mode_ == TransportMode::TCP) {
        Log(1, "TCP连接: " + host_ + ":" + std::to_string(port_));
        WSADATA wd{}; if (WSAStartup(MAKEWORD(2,2), &wd) != 0) return false;
        addrinfo hints{}, *ai=nullptr; hints.ai_family=AF_INET; hints.ai_socktype=SOCK_STREAM; hints.ai_protocol=IPPROTO_TCP;
        if (getaddrinfo(host_.c_str(), std::to_string(port_).c_str(), &hints, &ai) != 0) return false;
        SOCKET s=socket(ai->ai_family,ai->ai_socktype,ai->ai_protocol);
        bool ok=s!=INVALID_SOCKET && connect(s,ai->ai_addr,(int)ai->ai_addrlen)==0; freeaddrinfo(ai);
        if(!ok){if(s!=INVALID_SOCKET)closesocket(s);return false;}
        tcp_socket_=static_cast<uintptr_t>(s); tcp_connected_=true;
    }

    // PSP 握手
    Log(0, "开始PSP握手...");
    state_ = ConnectionState::HANDSHAKING;

    if (!PSPHandshake()) {
        Log(3, "PSP握手失败");
        state_ = ConnectionState::CONN_ERROR;
        return false;
    }

    Log(1, "PSP握手成功 — 会话已建立");
    state_ = ConnectionState::CONNECTED;

    if (state_cb_) state_cb_(ConnectionState::CONNECTED);
    return true;
}

void PeanutSecureClient::Disconnect() {
    if(tcp_connected_){SOCKET s=static_cast<SOCKET>(tcp_socket_);shutdown(s,SD_BOTH);closesocket(s);tcp_socket_=static_cast<uintptr_t>(INVALID_SOCKET);WSACleanup();}
    state_ = ConnectionState::DISCONNECTED;
    tcp_connected_ = false;
}

bool PeanutSecureClient::IsConnected() const {
    return state_ == ConnectionState::CONNECTED;
}

ConnectionState PeanutSecureClient::GetState() const {
    return state_;
}

// ── PSP 握手 ───────────────────────────────────────────────

bool PeanutSecureClient::PSPHandshake() {
    VMProtectScope _vmp_scope_PSPHandshake("PSPHandshake");
    try {
        if (rsa_pubkey_hex_.empty()) {
            Log(3, "PSP握手失败: 未设置服务端 RSA 公钥 (keys/server_pubkey.hex)");
            return false;
        }
        psp_encoder_->set_rsa_pubkey_hex(rsa_pubkey_hex_);

        auto init_frame = psp_encoder_->build_handshake_init();
        session_id_ = std::string(
            reinterpret_cast<const char*>(psp_encoder_->session_id().data()),
            peanut::psp::PSP_SESSION_ID_SIZE);

        std::string b64 = Base64Encode(init_frame);
        if (transport_mode_ == TransportMode::TCP) {
            std::string response;
            if (!SendRequest("/psp_handshake", b64, response) || response != "ok") return false;
            psp_encoder_->confirm_session(); return true;
        }
        std::string body = "data=" + httplib::detail::encode_url(b64);

        httplib::Client cli(host_, port_);
        cli.set_connection_timeout(5, 0);
        cli.set_read_timeout(120, 0);  // RSA 解密较慢，给足时间

        auto res = cli.Post("/psp_handshake", body, "application/x-www-form-urlencoded");
        if (!res || res->status != 200) {
            std::string detail = !res ? "无连接" : ("HTTP " + std::to_string(res->status));
            if (res && !res->body.empty()) detail += " " + res->body;
            Log(3, "PSP握手失败: " + detail);
            return false;
        }

        Log(1, "PSP握手: 服务端响应 OK");
        psp_encoder_->confirm_session();
        return true;
    } catch (const std::exception& e) {
        Log(3, std::string("PSP握手异常: ") + e.what());
        return false;
    }
}

// ── 加密/解密 ──────────────────────────────────────────────

std::vector<uint8_t> PeanutSecureClient::PSPWrapAndEncode(
    const std::vector<uint8_t>& inner) {
    return psp_encoder_->wrap(inner);
}

bool PeanutSecureClient::PSPUnwrapAndDecode(const std::string& body,
                                              std::vector<uint8_t>& out_inner) {
    // 解码 Base64
    auto raw = Base64Decode(body);

    // PSP 解码
    peanut::psp::Decoder decoder;
    decoder.set_psk_hex(psp_key_hex_);

    auto result = decoder.decode(raw.data(), raw.size());
    if (!result.success) {
        Log(3, "PSP解码失败: " + std::to_string(static_cast<int>(result.error_code)));
        return false;
    }

    out_inner = result.inner_payload;
    session_seq_ = result.seq_number;
    return true;
}

// ── 请求/响应 ──────────────────────────────────────────────

bool PeanutSecureClient::SendRequest(const std::string& path,
                                      const std::string& encrypted_body,
                                      std::string& out_response) {
    if (transport_mode_ == TransportMode::TCP) {
        nlohmann::ordered_json frame={{"path",path},{"data",encrypted_body}};
        std::string wire=frame.dump(); uint32_t n=htonl(static_cast<uint32_t>(wire.size()));
        auto send_all=[&](const char* p,size_t left){while(left){int x=send(static_cast<SOCKET>(tcp_socket_),p,(int)left,0);if(x<=0)return false;p+=x;left-=x;}return true;};
        auto recv_all=[&](char* p,size_t left){while(left){int x=recv(static_cast<SOCKET>(tcp_socket_),p,(int)left,0);if(x<=0)return false;p+=x;left-=x;}return true;};
        if(!send_all(reinterpret_cast<const char*>(&n),4)||!send_all(wire.data(),wire.size()))return false;
        uint32_t rn=0;if(!recv_all(reinterpret_cast<char*>(&rn),4))return false;rn=ntohl(rn);
        if(rn==0||rn>64*1024*1024)return false;out_response.resize(rn);return recv_all(out_response.data(),rn);
    }
    httplib::Client cli(host_, port_);
    cli.set_connection_timeout(10, 0);
    cli.set_read_timeout(10, 0);

    std::string full_path = path + "?data=" + httplib::detail::encode_url(encrypted_body);

    auto res = cli.Get(full_path.c_str());
    if (!res) {
        Log(3, std::string("请求失败: ") + std::to_string(static_cast<int>(res.error())));
        return false;
    }
    if (res->status != 200) {
        Log(3, "HTTP错误: " + std::to_string(res->status));
        return false;
    }

    out_response = res->body;
    return true;
}

bool PeanutSecureClient::DecryptResponse(const std::string& body,
                                           std::string& out_json) {
    out_json = DecryptServerResponseRaw(body, cipher_key_hex_);
    return !out_json.empty();
}

bool PeanutSecureClient::VerifySignedResponse(const std::string& json_str,
                                                nlohmann::ordered_json& out_resp) {
    try {
        out_resp = nlohmann::ordered_json::parse(json_str);
        if (!out_resp.contains("signature")) return false;

        std::string sig = out_resp["signature"].get<std::string>();
        out_resp.erase("signature");
        return VerifySignature(out_resp.dump(), hmac_key_, sig);
    } catch (...) {
        return false;
    }
}

// ── API ────────────────────────────────────────────────────

bool PeanutSecureClient::FetchConfigInfo(std::string& announcement,
                                           std::string& version) {
    try {
        JsonType req = {{"nonce", GenerateRandomNonce()}, {"timestamp", std::time(nullptr)}};
        req["signature"] = MakeSignature(req, hmac_key_);
        std::string enc = EncryptAndEncodeRequest(req, cipher_key_hex_);

        std::string body;
        if (!SendRequest("/config_info", enc, body)) return false;

        std::string json;
        if (!DecryptResponse(body, json)) return false;

        JsonType resp;
        if (!VerifySignedResponse(json, resp)) return false;

        if (resp.contains("announcement"))
            announcement = resp["announcement"].get<std::string>();
        if (resp.contains("version"))
            version = resp["version"].get<std::string>();
        return true;
    } catch (const std::exception& e) {
        Log(3, std::string("FetchConfigInfo: ") + e.what());
        return false;
    }
}

bool PeanutSecureClient::FetchSessionPolicy(SessionPolicy& out_policy,
                                             std::string* out_error) {
    VMProtectScope scope("FetchSessionPolicy");
    try {
        JsonType req = {{"nonce", GenerateRandomNonce()}, {"timestamp", std::time(nullptr)}};
        req["signature"] = MakeSignature(req, hmac_key_);
        std::string body, plain;
        JsonType resp;
        if (!SendRequest("/config_info", EncryptAndEncodeRequest(req, cipher_key_hex_), body) ||
            !DecryptResponse(body, plain) || !VerifySignedResponse(plain, resp) ||
            resp.value("status", "error") != "success") {
            if (out_error) *out_error = "无法取得服务端会话策略";
            return false;
        }
        out_policy.multi_open_enabled = resp.value("multi_open_enabled", false);
        out_policy.max_online_per_card = (std::max)(1, resp.value("max_online_per_card", 1));
        if (!out_policy.multi_open_enabled) out_policy.max_online_per_card = 1;
        return true;
    } catch (const std::exception& e) {
        if (out_error) *out_error = e.what();
        return false;
    }
}

bool PeanutSecureClient::FetchUpdatePolicy(const std::string& product_id,
                                             const std::string& client_version,
                                             const std::string& build_hash,
                                             UpdatePolicy& out_policy,
                                             std::string* out_error) {
    try {
        JsonType req = {{"product_id", product_id}, {"client_version", client_version},
                        {"build_hash", build_hash}, {"nonce", GenerateRandomNonce()},
                        {"timestamp", std::time(nullptr)}};
        req["signature"] = MakeSignature(req, hmac_key_);
        std::string body;
        if (!SendRequest("/update_policy", EncryptAndEncodeRequest(req, cipher_key_hex_), body)) {
            if (out_error) *out_error = "update policy request failed";
            return false;
        }
        std::string plain;
        JsonType resp;
        if (!DecryptResponse(body, plain) || !VerifySignedResponse(plain, resp)) {
            if (out_error) *out_error = "invalid update policy response";
            return false;
        }
        out_policy.force_update = resp.value("force_update", false);
        out_policy.build_revoked = resp.value("build_revoked", false);
        out_policy.latest_version = resp.value("latest_version", "");
        out_policy.minimum_version = resp.value("minimum_version", "");
        out_policy.target_file = resp.value("target_file", "");
        out_policy.target_sha256 = resp.value("target_sha256", "");
        out_policy.package_id = resp.value("package_id", "");
        out_policy.package_sha256 = resp.value("package_sha256", "");
        out_policy.package_size = resp.value("package_size", 0LL);
        out_policy.manifest_version = resp.value("manifest_version", 0ULL);
        return true;
    } catch (const std::exception& e) {
        if (out_error) *out_error = e.what();
        return false;
    }
}

bool PeanutSecureClient::Activate(const std::string& cardkey,
                                    const std::string& machinecode,
                                    std::string& out_token,
                                    std::string* out_error) {
    if (!security::antidebug::QuickCheck()) { if (out_error) *out_error = "anti-debug check failed"; return false; }
    VMProtectScope _vmp_scope_Activate("Activate");
    try {
        JsonType req = {{"cardkey", cardkey}, {"machinecode", machinecode},
                        {"nonce", GenerateRandomNonce()}, {"timestamp", std::time(nullptr)}};
        req["signature"] = MakeSignature(req, hmac_key_);
        std::string enc = EncryptAndEncodeRequest(req, cipher_key_hex_);

        std::string body;
        if (!SendRequest("/auth_activate", enc, body)) return false;

        std::string json;
        if (!DecryptResponse(body, json)) return false;

        JsonType resp;
        if (!VerifySignedResponse(json, resp)) return false;

        if (resp.contains("token"))
            out_token = resp["token"].get<std::string>();
        last_activation_remaining_seconds_ = resp.value("remaining_seconds", 0LL);
        bool ok = resp.contains("status") && resp["status"] == "success";
        if (!ok && out_error && resp.contains("message"))
            *out_error = LocalizeServerMessage(resp["message"].get<std::string>());
        return ok;
    } catch (const std::exception& e) {
        Log(3, std::string("Activate: ") + e.what());
        if (out_error) *out_error = e.what();
        return false;
    }
}

bool PeanutSecureClient::FetchPluginList(const std::string& token,
                                          std::vector<CloudPluginInfo>& out_plugins,
                                          std::string* out_error) {
    if (!security::antidebug::QuickCheck()) { if (out_error) *out_error = "anti-debug check failed"; return false; }
    VMProtectScope _vmp_scope_FetchPluginList("FetchPluginList");
    try {
        JsonType req={{"token",token},{"nonce",GenerateRandomNonce()},{"timestamp",std::time(nullptr)}}; req["signature"]=MakeSignature(req,hmac_key_);
        std::string body,plain; JsonType resp; if(!SendRequest("/plugin_list",EncryptAndEncodeRequest(req,cipher_key_hex_),body)||!DecryptResponse(body,plain)||!VerifySignedResponse(plain,resp)||resp.value("status","error")!="success")return false;
        out_plugins.clear(); for(const auto& p:resp["plugins"]){CloudPluginInfo i;i.name=p.value("name","");i.description=p.value("description","");i.version=p.value("version","");i.menu_text=p.value("menu_text","");i.enabled=p.value("enabled",false);out_plugins.push_back(i);} return true;
    } catch(const std::exception& e){if(out_error)*out_error=e.what();return false;}
}

bool PeanutSecureClient::CallPlugin(const std::string& token,
                                     const std::string& plugin_name,
                                     const std::string& input,
                                     std::string& out_result,
                                     std::string* out_error) {
    if (!security::antidebug::QuickCheck()) { if (out_error) *out_error = "anti-debug check failed"; return false; }
    VMProtectScope _vmp_scope_CallPlugin("CallPlugin");
    try {
        std::string nonce=GenerateRandomNonce(); JsonType req={{"token",token},{"plugin_name",plugin_name},{"input",input},{"nonce",nonce},{"timestamp",std::time(nullptr)}}; req["signature"]=MakeSignature(req,hmac_key_);
        std::string body,plain;JsonType resp;if(!SendRequest("/plugin_exec",EncryptAndEncodeRequest(req,cipher_key_hex_),body)||!DecryptResponse(body,plain)||!VerifySignedResponse(plain,resp)||resp.value("status","error")!="success"||resp.value("request_nonce","")!=nonce){if(out_error)*out_error=LocalizeServerMessage(resp.value("message","云函数响应无效"));return false;}out_result=resp.value("result","");return !out_result.empty();
    }catch(const std::exception&e){if(out_error)*out_error=e.what();return false;}
}

bool PeanutSecureClient::SendHeartbeat(const std::string& token,
                                         std::string& out_card_status,
                                         int& out_usage_minutes,
                                         long long& out_remaining_seconds) {
    if (!security::antidebug::QuickCheck()) return false;
    VMProtectScope _vmp_scope_SendHeartbeat("SendHeartbeat");
    last_server_error_.clear();
    try {
        std::string request_nonce=GenerateRandomNonce();
        JsonType req = {{"token", token},
                        {"nonce", request_nonce}, {"timestamp", std::time(nullptr)}};
        req["signature"] = MakeSignature(req, hmac_key_);
        std::string enc = EncryptAndEncodeRequest(req, cipher_key_hex_);

        std::string body;
        if (!SendRequest("/auth_heartbeat", enc, body)) return false;

        std::string json;
        if (!DecryptResponse(body, json)) return false;

        JsonType resp;
        if (!VerifySignedResponse(json, resp)) return false;
        if (resp.value("status", "error") != "success") {
            last_server_error_ = LocalizeServerMessage(resp.value("message", "server rejected session"));
            Log(3, "心跳被服务端拒绝: " + last_server_error_);
            return false;
        }
        if(resp.value("request_nonce","")!=request_nonce)return false;

        if (resp.contains("card_status"))
            out_card_status = resp["card_status"].get<std::string>();
        if (resp.contains("usage_minutes"))
            out_usage_minutes = resp["usage_minutes"].get<int>();
        if (resp.contains("remaining_seconds"))
            out_remaining_seconds = resp["remaining_seconds"].get<long long>();
        return true;
    } catch (const std::exception& e) {
        last_server_error_.clear(); // 传输异常按断网容错处理，而不是立即判服务端撤销
        Log(3, std::string("SendHeartbeat: ") + e.what());
        return false;
    }
}

bool PeanutSecureClient::Logout(const std::string& token) {
    VMProtectScope _vmp_scope_Logout("Logout");
    CallLogout(host_, port_, cipher_key_hex_, hmac_key_, token, 1);
    return true;
}

bool PeanutSecureClient::DeactivateCard(const std::string& token,
                                          const std::string& cardkey) {
    VMProtectScope _vmp_scope_DeactivateCard("DeactivateCard");
    try {
        JsonType req = {{"token", token}, {"cardkey", cardkey},
                        {"nonce", GenerateRandomNonce()}, {"timestamp", std::time(nullptr)}};
        req["signature"] = MakeSignature(req, hmac_key_);
        std::string enc = EncryptAndEncodeRequest(req, cipher_key_hex_);

        std::string body;
        if (!SendRequest("/deactivate", enc, body)) return false;

        std::string json;
        if (!DecryptResponse(body, json)) return false;

        JsonType resp;
        if (!VerifySignedResponse(json, resp)) return false;

        return resp.contains("status") && resp["status"] == "success";
    } catch (const std::exception& e) {
        Log(3, std::string("DeactivateCard: ") + e.what());
        return false;
    }
}

bool PeanutSecureClient::DownloadUpdatePackage(const std::string& package_id, std::vector<uint8_t>& out_data, std::string* out_error) {
    if (transport_mode_ != TransportMode::TCP) { if(out_error)*out_error="自动更新只允许使用TCP协议"; return false; }
    JsonType req={{"package_id",package_id},{"nonce",GenerateRandomNonce()},{"timestamp",std::time(nullptr)}};req["signature"]=MakeSignature(req,hmac_key_);
    std::string body,plain;JsonType resp;if(!SendRequest("/update_download",EncryptAndEncodeRequest(req,cipher_key_hex_),body)||!DecryptResponse(body,plain)||!VerifySignedResponse(plain,resp)||resp.value("status","error")!="success"){if(out_error)*out_error="服务端拒绝下载自动更新包";return false;}
    out_data=Base64Decode(resp.value("package_data",""));return !out_data.empty();
}

bool PeanutSecureClient::TCPSend(const std::vector<uint8_t>& data) {
    if(!tcp_connected_)return false;size_t off=0;while(off<data.size()){int n=send(static_cast<SOCKET>(tcp_socket_),reinterpret_cast<const char*>(data.data()+off),(int)(data.size()-off),0);if(n<=0)return false;off+=n;}return true;
}

bool PeanutSecureClient::TCPReceive(std::vector<uint8_t>& out_data, int timeout_ms) {
    if(!tcp_connected_)return false;fd_set f;FD_ZERO(&f);FD_SET(static_cast<SOCKET>(tcp_socket_),&f);timeval tv{timeout_ms/1000,(timeout_ms%1000)*1000};if(select(0,&f,nullptr,nullptr,&tv)<=0)return false;uint8_t buf[65536];int n=recv(static_cast<SOCKET>(tcp_socket_),reinterpret_cast<char*>(buf),sizeof(buf),0);if(n<=0)return false;out_data.assign(buf,buf+n);return true;
}

void PeanutSecureClient::Log(int level, const std::string& msg) {
    if (log_cb_) log_cb_(msg, level);
}

} // namespace sdk
} // namespace peanut
