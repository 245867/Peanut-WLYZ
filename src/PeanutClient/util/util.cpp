// util.cpp — 纯 C++ 实现，无外部加密依赖
#include "util.h"
#include <random>
#include <sstream>
#include <vector>
#include <cstdint>

// ── Base64 解码 (纯 C++ 实现) ─────────────────────────────
static const char g_base64_chars[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static int base64_index(char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

std::string Base64Encode(const std::vector<unsigned char>& data) {
    std::string result;
    size_t i = 0;
    uint32_t buf = 0;
    int buf_len = 0;

    for (i = 0; i < data.size(); ++i) {
        buf = (buf << 8) | data[i];
        buf_len += 8;
        while (buf_len >= 6) {
            buf_len -= 6;
            result += g_base64_chars[(buf >> buf_len) & 0x3F];
        }
    }
    if (buf_len > 0) {
        buf <<= (6 - buf_len);
        result += g_base64_chars[buf & 0x3F];
    }
    while (result.size() % 4 != 0)
        result += '=';

    return result;
}

std::vector<unsigned char> Base64Decode(const std::string& base64_data) {
    std::vector<unsigned char> result;
    uint32_t buf = 0;
    int buf_len = 0;

    for (char c : base64_data) {
        if (c == '=') break;
        int idx = base64_index(c);
        if (idx < 0) continue;
        buf = (buf << 6) | idx;
        buf_len += 6;
        if (buf_len >= 8) {
            buf_len -= 8;
            result.push_back(static_cast<unsigned char>((buf >> buf_len) & 0xFF));
        }
    }
    return result;
}

// ── 随机 Nonce ─────────────────────────────────────────────
std::string GenerateRandomNonce(size_t length) {
    static const char charset[] =
        "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    static std::random_device rd;
    static std::mt19937 gen(rd());
    static std::uniform_int_distribution<> dis(0, sizeof(charset) - 2);
    std::stringstream ss;
    for (size_t i = 0; i < length; ++i)
        ss << charset[dis(gen)];
    return ss.str();
}
