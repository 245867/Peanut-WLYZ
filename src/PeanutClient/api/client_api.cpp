// client_api.cpp — 业务 API 层（使用自研 WY 加密库）
#include "client_api.h"
#include "../crypto/wy_cipher.h"
#include "../crypto/wy_hash.h"
#include "../crypto/wy_random.h"
#include "../crypto/wy_rsa.h"
#include "util.h"
#include "../vmprotect_markers.h"
#include <httplib.h>
#include <iostream>
#include <sstream>
#include <iomanip>
#include <nlohmann/json.hpp>
#include <ctime>
#include <random>
#include <atomic>
#include <chrono>
#include <cstdlib>
#include <vector>

using JsonType = nlohmann::ordered_json;

// ── 内部: hex ↔ 字节 ───────────────────────────────────────
static std::vector<unsigned char> hex_to_bytes(const std::string& hex) {
    std::vector<unsigned char> bytes;
    for (size_t i = 0; i + 1 < hex.size(); i += 2) {
        unsigned char byte = static_cast<unsigned char>(
            strtol(hex.substr(i, 2).c_str(), nullptr, 16));
        bytes.push_back(byte);
    }
    return bytes;
}

static std::string bytes_to_hex(const unsigned char* data, size_t len) {
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (size_t i = 0; i < len; ++i)
        ss << std::setw(2) << static_cast<int>(data[i]);
    return ss.str();
}

static std::string bytes_to_hex(const std::vector<unsigned char>& data) {
    return bytes_to_hex(data.data(), data.size());
}

// ── 加密/解密 (使用自研 WY-Cipher) ──────────────────────────
static std::string wy_aes_encrypt(const std::string& plaintext, const std::string& key_hex) {
    auto key_bytes = hex_to_bytes(key_hex);
    if (key_bytes.size() < wy::WY_CIPHER_KEY_SIZE) return "";

    wy::wy_cipher_key cipher_key;
    wy::wy_cipher_key_schedule(key_bytes.data(), &cipher_key);

    uint8_t iv[16];
    wy::wy_random_bytes(iv, sizeof(iv));

    std::vector<uint8_t> ct = wy::wy_cbc_encrypt(
        &cipher_key, iv,
        reinterpret_cast<const uint8_t*>(plaintext.data()), plaintext.size());

    // 格式: [IV 16B] + [密文]
    std::vector<uint8_t> result;
    result.insert(result.end(), iv, iv + 16);
    result.insert(result.end(), ct.begin(), ct.end());

    return Base64Encode(result);
}

static std::string wy_aes_decrypt(const std::string& b64_cipher, const std::string& key_hex) {
    auto raw = Base64Decode(b64_cipher);
    if (raw.size() < 16 + wy::WY_CIPHER_BLOCK_SIZE) return "";

    auto key_bytes = hex_to_bytes(key_hex);
    if (key_bytes.size() < wy::WY_CIPHER_KEY_SIZE) return "";

    wy::wy_cipher_key cipher_key;
    wy::wy_cipher_key_schedule(key_bytes.data(), &cipher_key);

    std::vector<uint8_t> pt = wy::wy_cbc_decrypt(
        &cipher_key, raw.data(), raw.data() + 16, raw.size() - 16);

    return std::string(pt.begin(), pt.end());
}

// ── HMAC (使用自研 WY-HMAC) ─────────────────────────────────
static std::string wy_hmac_sha256(const std::string& data, const std::string& key) {
    uint8_t hmac_out[wy::WY_HASH_OUTPUT_SIZE];
    wy::wy_hmac(
        reinterpret_cast<const uint8_t*>(key.data()), key.size(),
        reinterpret_cast<const uint8_t*>(data.data()), data.size(),
        hmac_out);
    return bytes_to_hex(hmac_out, wy::WY_HASH_OUTPUT_SIZE);
}

// ── API 层公共函数 ─────────────────────────────────────────
std::string DecryptServerResponse(const std::string& base64_data, const std::string& aes_key_hex) {
    VMProtectScope _vmp_scope_auto_1("DecryptServerResponse");
    return wy_aes_decrypt(base64_data, aes_key_hex);
}

bool VerifySignature(const std::string& json_str, const std::string& hmac_key, const std::string& signature) {
    VMProtectScope _vmp_scope_auto_2("VerifySignature");
    std::string calc_sig = wy_hmac_sha256(json_str, hmac_key);
    return calc_sig == signature;
}

std::string EncryptAndEncodeRequest(const JsonType& req_json, const std::string& aes_key_hex) {
    VMProtectScope _vmp_scope_auto_3("EncryptAndEncodeRequest");
    std::string json_str = req_json.dump();
    return wy_aes_encrypt(json_str, aes_key_hex);
}

std::string DecryptServerResponseRaw(const std::string& body, const std::string& aes_key_hex) {
    VMProtectScope _vmp_scope_auto_4("DecryptServerResponseRaw");
    return DecryptServerResponse(body, aes_key_hex);
}

std::string MakeSignature(const JsonType& req_json, const std::string& hmac_key) {
    VMProtectScope _vmp_scope_auto_5("MakeSignature");
    JsonType tmp = req_json;
    tmp.erase("signature");
    return wy_hmac_sha256(tmp.dump(), hmac_key);
}

// ── 业务接口 ───────────────────────────────────────────────

void FetchServerConfigInfo(const std::string& host, int port,
                           const std::string& aes_key_hex, const std::string& hmac_key) {
    VMProtectScope _vmp_scope_auto_6("FetchServerConfigInfo");
    httplib::Client cli(host, port);
    std::string nonce = GenerateRandomNonce();
    long long timestamp = static_cast<long long>(std::time(nullptr));
    JsonType req_json = {{"nonce", nonce}, {"timestamp", timestamp}};
    req_json["signature"] = MakeSignature(req_json, hmac_key);
    std::string encrypted_body = EncryptAndEncodeRequest(req_json, aes_key_hex);
    std::string full_path = "/config_info?data=" + httplib::detail::encode_url(encrypted_body);

    if (auto res = cli.Get(full_path.c_str())) {
        std::cout << "[公告/版本] HTTP " << res->status << std::endl;
        try {
            std::string json_str = DecryptServerResponseRaw(res->body, aes_key_hex);
            std::cout << "[公告/版本] 解密: " << json_str << std::endl;
            JsonType resp = JsonType::parse(json_str);
            if (resp.contains("signature")) {
                std::string sig = resp["signature"].get<std::string>();
                resp.erase("signature");
                if (VerifySignature(resp.dump(), hmac_key, sig)) {
                    std::cout << "[公告/版本] 签名OK" << std::endl;
                    if (resp.contains("status") && resp["status"] == "success") {
                        std::cout << "公告: " << resp["announcement"].get<std::string>() << std::endl;
                        std::cout << "版本: " << resp["version"].get<std::string>() << std::endl;
                    }
                } else {
                    std::cout << "[公告/版本] 签名失败" << std::endl;
                }
            }
        } catch (...) {
            std::cout << "[公告/版本] 解析失败: " << res->body << std::endl;
        }
    } else {
        std::cout << "[公告/版本] 请求失败: " << res.error() << std::endl;
    }
}

void SendHeartbeatRequest(const std::string& host, int port,
                          const std::string& aes_key_hex, const std::string& hmac_key,
                          const std::string& token) {
    VMProtectScope _vmp_scope_auto_7("SendHeartbeatRequest");
    httplib::Client cli(host, port);
    std::string nonce = GenerateRandomNonce();
    long long timestamp = static_cast<long long>(std::time(nullptr));
    JsonType req_json = {{"token", token}, {"nonce", nonce}, {"timestamp", timestamp}};
    req_json["signature"] = MakeSignature(req_json, hmac_key);
    std::string encrypted_body = EncryptAndEncodeRequest(req_json, aes_key_hex);
    std::string full_path = "/auth_heartbeat?data=" + httplib::detail::encode_url(encrypted_body);

    if (auto res = cli.Get(full_path.c_str())) {
        std::cout << "[心跳] HTTP " << res->status << std::endl;
        std::string json_str = DecryptServerResponseRaw(res->body, aes_key_hex);
        std::cout << "[心跳] 解密: " << json_str << std::endl;
        JsonType resp = JsonType::parse(json_str);
        if (resp.contains("signature")) {
            std::string sig = resp["signature"].get<std::string>();
            resp.erase("signature");
            if (VerifySignature(resp.dump(), hmac_key, sig)) {
                std::cout << "[心跳] 签名OK" << std::endl;
                if (resp.contains("status"))
                    std::cout << "[心跳] 状态: " << resp["status"].get<std::string>() << std::endl;
                if (resp.contains("card_status"))
                    std::cout << "[心跳] 卡密: " << resp["card_status"].get<std::string>() << std::endl;
                if (resp.contains("usage_minutes"))
                    std::cout << "[心跳] 时长: " << resp["usage_minutes"].get<int>() << " 分" << std::endl;
                if (resp.contains("remaining_seconds"))
                    std::cout << "[心跳] 剩余: " << resp["remaining_seconds"].get<long long>() << " 秒" << std::endl;
            } else {
                std::cout << "[心跳] 签名失败" << std::endl;
            }
        }
    } else {
        std::cout << "[心跳] 请求失败: " << res.error() << std::endl;
    }
}

bool FetchPluginList(const std::string& host, int port,
                     const std::string& aes_key_hex, const std::string& hmac_key,
                     const std::string& token,
                     std::vector<CloudPluginInfo>& out_plugins,
                     std::string* out_error) {
    VMProtectScope _vmp_scope_auto_8("FetchPluginList");
    out_plugins.clear();
    try {
        httplib::Client cli(host, port);
        cli.set_connection_timeout(2, 0);
        cli.set_read_timeout(3, 0);
        std::string nonce = GenerateRandomNonce(24);
        long long timestamp = static_cast<long long>(std::time(nullptr));
        JsonType req_json = {{"token", token},
                             {"nonce", nonce},
                             {"timestamp", timestamp}};
        req_json["signature"] = MakeSignature(req_json, hmac_key);
        std::string encrypted_body = EncryptAndEncodeRequest(req_json, aes_key_hex);
        std::string full_path = "/plugin_list?data=" +
                                httplib::detail::encode_url(encrypted_body);

        auto res = cli.Get(full_path.c_str());
        if (!res) {
            if (out_error) *out_error = "plugin_list 请求失败（服务端可能未实现）";
            return false;
        }
        if (res->status != 200) {
            if (out_error)
                *out_error = "plugin_list HTTP " + std::to_string(res->status);
            return false;
        }

        std::string json_str = DecryptServerResponseRaw(res->body, aes_key_hex);
        JsonType resp = JsonType::parse(json_str);
        if (resp.contains("signature")) {
            std::string sig = resp["signature"].get<std::string>();
            resp.erase("signature");
            if (!VerifySignature(resp.dump(), hmac_key, sig)) {
                if (out_error) *out_error = "plugin_list 签名校验失败";
                return false;
            }
        }
        if (!resp.contains("status") || resp["status"] != "success") {
            if (out_error) *out_error = "plugin_list 返回非 success";
            return false;
        }
        if (!resp.contains("plugins") || !resp["plugins"].is_array()) {
            return true; // 空清单也算成功
        }
        for (const auto& item : resp["plugins"]) {
            CloudPluginInfo info;
            if (item.contains("name"))
                info.name = item["name"].get<std::string>();
            if (item.contains("description"))
                info.description = item["description"].get<std::string>();
            if (item.contains("version"))
                info.version = item["version"].get<std::string>();
            if (item.contains("menu_text"))
                info.menu_text = item["menu_text"].get<std::string>();
            if (item.contains("enabled"))
                info.enabled = item["enabled"].get<bool>();
            if (!info.name.empty())
                out_plugins.push_back(std::move(info));
        }
        return true;
    } catch (const std::exception& e) {
        if (out_error) *out_error = std::string("plugin_list 异常: ") + e.what();
        return false;
    }
}

bool CallPluginExec(const std::string& host, int port,
                    const std::string& aes_key_hex, const std::string& hmac_key,
                    const std::string& token,
                    const std::string& plugin_name,
                    const std::string& input,
                    std::string& out_result,
                    int crypto_type,
                    std::string* out_error) {
    VMProtectScope _vmp_scope_auto_9("CallPluginExec");
    out_result.clear();
    try {
        httplib::Client cli(host, port);
        cli.set_connection_timeout(3, 0);
        cli.set_read_timeout(30, 0);
        std::string nonce = GenerateRandomNonce(24);
        long long timestamp = static_cast<long long>(std::time(nullptr));
        JsonType req_json = {{"plugin_name", plugin_name},
                             {"input", input},
                             {"token", token},
                             {"nonce", nonce},
                             {"timestamp", timestamp}};
        req_json["signature"] = MakeSignature(req_json, hmac_key);
        std::string encrypted_body = EncryptAndEncodeRequest(req_json, aes_key_hex);
        std::string full_path = "/plugin_exec?data=" +
                                httplib::detail::encode_url(encrypted_body) +
                                "&type=" + std::to_string(crypto_type);

        auto res = cli.Get(full_path.c_str());
        if (!res) {
            if (out_error) *out_error = "plugin_exec 请求失败";
            return false;
        }
        std::string json_str = DecryptServerResponseRaw(res->body, aes_key_hex);
        JsonType resp = JsonType::parse(json_str);
        if (resp.contains("signature")) {
            std::string sig = resp["signature"].get<std::string>();
            resp.erase("signature");
            if (!VerifySignature(resp.dump(), hmac_key, sig)) {
                if (out_error) *out_error = "plugin_exec 签名校验失败";
                return false;
            }
        }
        if (resp.contains("status") && resp["status"] == "success") {
            if (resp.contains("plugin_result")) {
                out_result = resp["plugin_result"].get<std::string>();
                return true;
            }
            if (resp.contains("result")) {
                out_result = resp["result"].get<std::string>();
                return true;
            }
        }
        if (out_error) *out_error = "plugin_exec 失败: " + json_str;
        return false;
    } catch (const std::exception& e) {
        if (out_error) *out_error = std::string("plugin_exec 异常: ") + e.what();
        return false;
    }
}

void CallLogout(const std::string& host, int port,
                const std::string& aes_key_hex, const std::string& hmac_key,
                const std::string& token, int crypto_type) {
    VMProtectScope _vmp_scope_auto_10("CallLogout");
    httplib::Client cli(host, port);
    std::string nonce = GenerateRandomNonce(24);
    long long timestamp = static_cast<long long>(std::time(nullptr));
    JsonType req_json = {{"token", token}, {"nonce", nonce}, {"timestamp", timestamp}};
    req_json["signature"] = MakeSignature(req_json, hmac_key);
    std::string encrypted_body = EncryptAndEncodeRequest(req_json, aes_key_hex);
    std::string full_path = "/logout?data=" + httplib::detail::encode_url(encrypted_body) +
                            "&type=" + std::to_string(crypto_type);

    if (auto res = cli.Get(full_path.c_str())) {
        std::cout << "[下线] HTTP " << res->status << std::endl;
        std::string json_str = DecryptServerResponseRaw(res->body, aes_key_hex);
        std::cout << "[下线] 解密: " << json_str << std::endl;
        JsonType resp = JsonType::parse(json_str);
        if (resp.contains("signature")) {
            std::string sig = resp["signature"].get<std::string>();
            resp.erase("signature");
            if (VerifySignature(resp.dump(), hmac_key, sig)) {
                if (resp.contains("status") && resp["status"] == "success")
                    std::cout << "下线成功" << std::endl;
                else
                    std::cout << "下线失败: " << json_str << std::endl;
            }
        }
    } else {
        std::cout << "[下线] 请求失败: " << res.error() << std::endl;
    }
}
