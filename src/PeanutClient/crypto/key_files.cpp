#include "key_files.h"
#include "wy_cipher.h"
#include "wy_random.h"
#include "../vmprotect_markers.h"

#include <fstream>
#include <sstream>
#include <iomanip>
#include <filesystem>
#include <cstring>
#include <vector>

namespace fs = std::filesystem;

namespace peanut {
namespace keys {

static std::string Join(const std::string& dir, const char* name) {
    fs::path p = fs::path(dir) / name;
    return p.string();
}

bool WriteTextFile(const std::string& path, const std::string& content) {
    VMProtectScope _vmp_scope_auto_1("WriteTextFile");
    try {
        fs::path p(path);
        if (p.has_parent_path())
            fs::create_directories(p.parent_path());
        std::ofstream ofs(path, std::ios::binary | std::ios::trunc);
        if (!ofs) return false;
        ofs << content;
        return static_cast<bool>(ofs);
    } catch (...) {
        return false;
    }
}

bool ReadTextFile(const std::string& path, std::string& out) {
    VMProtectScope _vmp_scope_auto_2("ReadTextFile");
    try {
        std::ifstream ifs(path, std::ios::binary);
        if (!ifs) return false;
        std::ostringstream ss;
        ss << ifs.rdbuf();
        out = ss.str();
        while (!out.empty() && (out.back() == '\n' || out.back() == '\r' ||
                                out.back() == ' ' || out.back() == '\t'))
            out.pop_back();
        return !out.empty();
    } catch (...) {
        return false;
    }
}

bool SaveServerPubkey(const std::string& dir, const wy::wy_rsa_pubkey& pub) {
    VMProtectScope _vmp_scope_auto_3("SaveServerPubkey");
    return WriteTextFile(Join(dir, kServerPubkeyFile), wy::wy_rsa_pubkey_to_hex(&pub));
}

bool SaveServerPrivkey(const std::string& dir, const wy::wy_rsa_prikey& pri) {
    VMProtectScope _vmp_scope_auto_4("SaveServerPrivkey");
    return WriteTextFile(Join(dir, kServerPrivkeyFile), wy::wy_rsa_prikey_to_hex(&pri));
}

bool LoadServerPubkey(const std::string& dir, wy::wy_rsa_pubkey& out) {
    VMProtectScope _vmp_scope_auto_5("LoadServerPubkey");
    std::string hex;
    if (!ReadTextFile(Join(dir, kServerPubkeyFile), hex)) return false;
    out = wy::wy_rsa_pubkey_from_hex(hex);
    return !out.n.is_zero();
}

bool LoadServerPrivkey(const std::string& dir, wy::wy_rsa_prikey& out) {
    VMProtectScope _vmp_scope_auto_6("LoadServerPrivkey");
    std::string hex;
    if (!ReadTextFile(Join(dir, kServerPrivkeyFile), hex)) return false;
    out = wy::wy_rsa_prikey_from_hex(hex);
    return !out.n.is_zero();
}

bool SaveCipherKeyHex(const std::string& dir, const std::string& hex) {
    VMProtectScope _vmp_scope_auto_7("SaveCipherKeyHex");
    return WriteTextFile(Join(dir, kCipherKeyFile), hex);
}
bool LoadCipherKeyHex(const std::string& dir, std::string& out) {
    VMProtectScope _vmp_scope_auto_8("LoadCipherKeyHex");
    return ReadTextFile(Join(dir, kCipherKeyFile), out);
}
bool SaveHmacKey(const std::string& dir, const std::string& key) {
    VMProtectScope _vmp_scope_auto_9("SaveHmacKey");
    return WriteTextFile(Join(dir, kHmacKeyFile), key);
}
bool LoadHmacKey(const std::string& dir, std::string& out) {
    VMProtectScope _vmp_scope_auto_10("LoadHmacKey");
    return ReadTextFile(Join(dir, kHmacKeyFile), out);
}
bool SavePspKeyHex(const std::string& dir, const std::string& hex) {
    VMProtectScope _vmp_scope_auto_11("SavePspKeyHex");
    return WriteTextFile(Join(dir, kPspKeyFile), hex);
}
bool LoadPspKeyHex(const std::string& dir, std::string& out) {
    VMProtectScope _vmp_scope_auto_12("LoadPspKeyHex");
    return ReadTextFile(Join(dir, kPspKeyFile), out);
}

static std::string RandomHex(size_t nbytes) {
    std::vector<uint8_t> buf(nbytes);
    wy::wy_random_bytes(buf.data(), nbytes);
    std::ostringstream ss;
    ss << std::hex << std::uppercase << std::setfill('0');
    for (size_t i = 0; i < nbytes; ++i)
        ss << std::setw(2) << static_cast<int>(buf[i]);
    return ss.str();
}

bool GenerateAndSaveKeypair(const std::string& dir, std::string* err) {
    VMProtectScope _vmp_scope_auto_13("GenerateAndSaveKeypair");
    try {
        fs::create_directories(dir);
        auto kp = wy::wy_rsa_generate_keypair();
        if (!SaveServerPubkey(dir, kp.pub) || !SaveServerPrivkey(dir, kp.pri)) {
            if (err) *err = "write RSA key files failed";
            return false;
        }
        return true;
    } catch (const std::exception& e) {
        if (err) *err = e.what();
        return false;
    }
}

bool EnsureBusinessKeys(const std::string& dir) {
    VMProtectScope _vmp_scope_auto_14("EnsureBusinessKeys");
    fs::create_directories(dir);
    std::string tmp;
    if (!LoadCipherKeyHex(dir, tmp)) {
        if (!SaveCipherKeyHex(dir, wy::wy_cipher_generate_key_hex()))
            return false;
    }
    if (!LoadHmacKey(dir, tmp)) {
        return false;
    }
    if (!LoadPspKeyHex(dir, tmp)) {
        if (!SavePspKeyHex(dir, RandomHex(32)))
            return false;
    }
    return true;
}

} // namespace keys
} // namespace peanut
