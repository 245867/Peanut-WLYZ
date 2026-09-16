// ============================================================
// 本地密钥文件 — 公钥 / 私钥 / 业务密钥
// ============================================================
#pragma once

#include "wy_rsa.h"
#include <string>

namespace peanut {
namespace keys {

constexpr const char* kDefaultKeyDir = "keys";

constexpr const char* kServerPubkeyFile  = "server_pubkey.hex";
constexpr const char* kServerPrivkeyFile = "server_privkey.hex";
constexpr const char* kCipherKeyFile     = "cipher_key.hex";
constexpr const char* kHmacKeyFile       = "hmac_key.txt";
constexpr const char* kPspKeyFile        = "psp_key.hex";

bool WriteTextFile(const std::string& path, const std::string& content);
bool ReadTextFile(const std::string& path, std::string& out);

bool SaveServerPubkey(const std::string& dir, const wy::wy_rsa_pubkey& pub);
bool SaveServerPrivkey(const std::string& dir, const wy::wy_rsa_prikey& pri);
bool LoadServerPubkey(const std::string& dir, wy::wy_rsa_pubkey& out);
bool LoadServerPrivkey(const std::string& dir, wy::wy_rsa_prikey& out);

bool SaveCipherKeyHex(const std::string& dir, const std::string& hex);
bool LoadCipherKeyHex(const std::string& dir, std::string& out);
bool SaveHmacKey(const std::string& dir, const std::string& key);
bool LoadHmacKey(const std::string& dir, std::string& out);
bool SavePspKeyHex(const std::string& dir, const std::string& hex);
bool LoadPspKeyHex(const std::string& dir, std::string& out);

bool GenerateAndSaveKeypair(const std::string& dir, std::string* err = nullptr);
bool EnsureBusinessKeys(const std::string& dir);

} // namespace keys
} // namespace peanut
