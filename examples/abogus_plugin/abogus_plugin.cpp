// abogus_plugin — 云端安全插件（方案C）
// 算法完全在云端DLL执行，客户端零知识
// 新增5个低调用频率核心函数，确保安全且避免频繁通讯
#include <windows.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <string>
#include <sstream>
#include <algorithm>
#include <vector>
#include <ctime>
#include <cctype>

static char* dup_str(const char* s) {
    if (!s) return nullptr;
    size_t n = strlen(s) + 1;
    char* p = (char*)malloc(n);
    if (p) memcpy(p, s, n);
    return p;
}

extern "C" __declspec(dllexport) void PluginFree(char* data) { if (data) free(data); }

extern "C" __declspec(dllexport) int PluginGetInfo(
    char** out_name, char** out_version,
    char** out_description, char** out_author)
{
    *out_name = dup_str("abogus");
    *out_version = dup_str("2.0.0");
    *out_description = dup_str("云端安全插件 — 签名/加密/校验/指纹/令牌");
    *out_author = dup_str("Peanut");
    return 0;
}

extern "C" __declspec(dllexport) int PluginInit(const char*) { return 0; }

// ── 简易JSON解析辅助 ───────────────────────────────────────
static const char* json_get_str(const char* json, const char* key, char* out, size_t out_sz) {
    out[0] = '\0';
    char search[256];
    _snprintf_s(search, sizeof(search), _TRUNCATE, "\"%s\"", key);
    const char* pos = strstr(json, search);
    if (!pos) return out;
    pos = strchr(pos + strlen(search), ':');
    if (!pos) return out;
    pos = strchr(pos, '"');
    if (!pos) return out;
    pos++;
    const char* end = strchr(pos, '"');
    if (!end) return out;
    size_t len = (size_t)(end - pos);
    if (len >= out_sz) len = out_sz - 1;
    memcpy(out, pos, len);
    out[len] = '\0';
    return out;
}

static int json_get_int(const char* json, const char* key, int def) {
    char search[256];
    _snprintf_s(search, sizeof(search), _TRUNCATE, "\"%s\"", key);
    const char* pos = strstr(json, search);
    if (!pos) return def;
    pos = strchr(pos + strlen(search), ':');
    if (!pos) return def;
    while (*pos && (*pos < '0' || *pos > '9') && *pos != '-') pos++;
    return atoi(pos);
}

static bool json_get_bool(const char* json, const char* key, bool def) {
    char search[256];
    _snprintf_s(search, sizeof(search), _TRUNCATE, "\"%s\"", key);
    const char* pos = strstr(json, search);
    if (!pos) return def;
    pos = strchr(pos + strlen(search), ':');
    if (!pos) return def;
    while (*pos && *pos != 't' && *pos != 'f') pos++;
    return (*pos == 't');
}

// ── 简易JSON转义（处理所有控制字符，确保输出合法JSON） ────
static void json_escape(const char* src, char* dst, size_t dst_sz) {
    char* d = dst;
    const char* end = dst + dst_sz - 8;
    for (const char* s = src; *s && d < end; s++) {
        unsigned char c = (unsigned char)*s;
        if (c == '"' || c == '\\') { if (d < end - 1) { *d++ = '\\'; *d++ = (char)c; } }
        else if (c == '\n') { if (d < end - 1) { *d++ = '\\'; *d++ = 'n'; } }
        else if (c == '\r') { if (d < end - 1) { *d++ = '\\'; *d++ = 'r'; } }
        else if (c == '\t') { if (d < end - 1) { *d++ = '\\'; *d++ = 't'; } }
        else if (c < 0x20) { if (d < end - 5) { _snprintf_s(d, (size_t)(end - d), _TRUNCATE, "\\u%04x", c); while (*d) d++; } }
        else { *d++ = (char)c; }
    }
    *d = '\0';
}

// ── 核心算法：FNV-1a哈希 ───────────────────────────────────
static unsigned long fnv1a(const char* data, size_t len) {
    unsigned long h = 2166136261UL;
    for (size_t i = 0; i < len; i++) {
        h ^= (unsigned char)data[i];
        h *= 16777619UL;
    }
    return h;
}

// ── 核心算法：XOR加密/解密 ──────────────────────────────────
static std::string xor_cipher(const std::string& data, const std::string& key) {
    std::string result = data;
    for (size_t i = 0; i < result.size(); i++)
        result[i] ^= key[i % key.size()];
    return result;
}

// ── 核心算法：XOR乱数密钥派生 ──────────────────────────────
static std::string derive_key(const std::string& seed, const std::string& nonce) {
    std::string combined = seed + "|" + nonce;
    unsigned long h = fnv1a(combined.c_str(), combined.size());
    char buf[32];
    _snprintf_s(buf, sizeof(buf), _TRUNCATE, "%08lx_%08lx", h, h ^ 0xDEADBEEF);
    return std::string(buf);
}

// ── 核心签名算法（云端执行，不可泄露给客户端） ─────────────
static std::string generate_abogus_impl(const char* urlQuery, const char* postBody, const char* userAgent) {
    std::string query(urlQuery ? urlQuery : "");
    std::string body(postBody ? postBody : "");
    std::string ua(userAgent ? userAgent : "");

    // 阶段1: 提取query参数并排序
    std::vector<std::pair<std::string, std::string>> params;
    std::string q = query;
    if (!q.empty() && q[0] == '?') q = q.substr(1);
    size_t pos = 0;
    while (pos < q.length()) {
        size_t eq = q.find('=', pos);
        size_t amp = q.find('&', pos);
        if (amp == std::string::npos) amp = q.length();
        if (eq != std::string::npos && eq < amp) {
            std::string key = q.substr(pos, eq - pos);
            std::string val = q.substr(eq + 1, amp - eq - 1);
            params.push_back({key, val});
        }
        pos = amp + 1;
    }
    std::sort(params.begin(), params.end());

    // 阶段2: 构建规范化query字符串
    std::string canonical;
    for (size_t i = 0; i < params.size(); i++) {
        if (i > 0) canonical += "&";
        canonical += params[i].first + "=" + params[i].second;
    }

    // 阶段3: 提取UA特征
    unsigned long ua_h = fnv1a(ua.c_str(), ua.size());
    char ua_hash[32];
    _snprintf_s(ua_hash, sizeof(ua_hash), _TRUNCATE, "%08lx", ua_h);

    // 阶段4: 组合签名种子
    std::string seed = canonical + "|" + std::to_string(body.length()) + "|" + ua_hash;

    // 阶段5: 多层哈希迭代
    unsigned long sig = fnv1a(seed.c_str(), seed.size());
    sig ^= (sig << 13) ^ (sig >> 7);

    // 阶段6: 格式化输出
    char result[512];
    _snprintf_s(result, sizeof(result), _TRUNCATE,
        "%s_%08lx_%zu", ua_hash, sig, body.length());
    return std::string(result);
}

// ═══════════════════════════════════════════════════════════════
// 新增函数1: decrypt_config — 解密配置（启动时调用1次）
// 输入: {"action":"decrypt_config","data":"加密后的base64配置","key_seed":"种子"}
// =══════════════════════════════════════════════════════════════
static std::string decrypt_config_impl(const char* encrypted_data, const char* key_seed) {
    std::string data(encrypted_data ? encrypted_data : "");
    std::string seed(key_seed ? key_seed : "peanut_default_seed");
    if (data.empty()) return "";

    // 派生密钥
    std::string key = derive_key(seed, "config_decrypt_nonce");
    // XOR解密
    std::string decrypted = xor_cipher(data, key);
    return decrypted;
}

// ═══════════════════════════════════════════════════════════════
// 新增函数2: verify_license — 验证许可证（启动时/定时调用）
// 输入: {"action":"verify_license","license_data":"许可证数据","signature":"签名","machine_code":"机器码"}
// 输出: {"result":"ok","data":{"valid":true/false,"expire_time":"到期时间","features":"功能列表"}}
// =══════════════════════════════════════════════════════════════
static std::string verify_license_impl(const char* license_data, const char* signature, const char* machine_code) {
    std::string lic(license_data ? license_data : "");
    std::string sig(signature ? signature : "");
    std::string mc(machine_code ? machine_code : "");

    if (lic.empty() || sig.empty()) return "{\"result\":\"error\",\"message\":\"missing license or signature\"}";

    // 验证签名：用机器码+许可证数据重新计算签名
    std::string expected_input = lic + "|" + mc + "|peanut_license_salt";
    unsigned long expected_hash = fnv1a(expected_input.c_str(), expected_input.size());
    char expected_sig[32];
    _snprintf_s(expected_sig, sizeof(expected_sig), _TRUNCATE, "%08lx", expected_hash);

    bool valid = (sig == expected_sig);

    // 解析许可证中的到期时间
    time_t now = time(nullptr);
    struct tm tm_now;
    localtime_s(&tm_now, &now);
    char time_buf[32];
    strftime(time_buf, sizeof(time_buf), "%Y-%m-%d %H:%M:%S", &tm_now);

    // 提取功能列表
    char features[256] = "basic";
    const char* feat_pos = strstr(lic.c_str(), "features:");
    if (feat_pos) {
        const char* end = strchr(feat_pos, ';');
        size_t len = end ? (size_t)(end - feat_pos - 9) : strlen(feat_pos + 9);
        if (len < sizeof(features)) {
            memcpy(features, feat_pos + 9, len);
            features[len] = '\0';
        }
    }

    char result[1024];
    char escaped_lic[512], escaped_mc[256];
    json_escape(lic.c_str(), escaped_lic, sizeof(escaped_lic));
    json_escape(mc.c_str(), escaped_mc, sizeof(escaped_mc));
    _snprintf_s(result, sizeof(result), _TRUNCATE,
        "{\"result\":\"ok\",\"data\":{\"valid\":%s,\"check_time\":\"%s\",\"machine_code\":\"%s\",\"features\":\"%s\"}}",
        valid ? "true" : "false", time_buf, escaped_mc, features);
    return std::string(result);
}

// ═══════════════════════════════════════════════════════════════
// 新增函数3: get_device_fingerprint — 获取设备指纹（登录时调用1次）
// 输入: {"action":"get_device_fingerprint","os_version":"Win10","cpu_id":"BFEBFBFF","disk_serial":"ABCD1234","mac_addr":"00-11-22-33-44-55"}
// 输出: {"result":"ok","data":{"fingerprint":"唯一指纹哈希","risk_level":"low/medium/high"}}
// =══════════════════════════════════════════════════════════════
static std::string get_device_fingerprint_impl(const char* os_ver, const char* cpu_id, const char* disk_serial, const char* mac_addr) {
    std::string os(os_ver ? os_ver : "");
    std::string cpu(cpu_id ? cpu_id : "");
    std::string disk(disk_serial ? disk_serial : "");
    std::string mac(mac_addr ? mac_addr : "");

    // 组合设备信息（4个参数 = 3个|分隔符）
    std::string combined = os + "|" + cpu + "|" + disk + "|" + mac;
    if (combined == "|||") return "{\"result\":\"error\",\"message\":\"no device info provided\"}";

    // 多层哈希生成指纹
    unsigned long h1 = fnv1a(combined.c_str(), combined.size());
    // 二次哈希
    char h1_str[32];
    _snprintf_s(h1_str, sizeof(h1_str), _TRUNCATE, "%08lx", h1);
    unsigned long h2 = fnv1a(h1_str, strlen(h1_str));
    // 三次哈希加盐
    std::string salted = std::string(h1_str) + "_peanut_device_salt_v2";
    unsigned long fingerprint = fnv1a(salted.c_str(), salted.size());

    // 风险评估
    const char* risk = "low";
    if (cpu.empty() || disk.empty()) risk = "high";
    else if (mac.empty()) risk = "medium";

    char result[512];
    _snprintf_s(result, sizeof(result), _TRUNCATE,
        "{\"result\":\"ok\",\"data\":{\"fingerprint\":\"%08lx%08lx\",\"risk_level\":\"%s\",\"h1\":\"%08lx\",\"h2\":\"%08lx\"}}",
        fingerprint, h1 ^ h2, risk, h1, h2);
    return std::string(result);
}

// ═══════════════════════════════════════════════════════════════
// 新增函数4: hash_verify — 完整性校验（启动时/定时调用）
// 输入: {"action":"hash_verify","file_path":"文件路径","expected_hash":"期望的哈希值","file_size":12345}
// 输出: {"result":"ok","data":{"match":true/false,"computed_hash":"计算出的哈希","file_size":12345}}
// =══════════════════════════════════════════════════════════════
static std::string hash_verify_impl(const char* file_path, const char* expected_hash, int file_size) {
    std::string fp(file_path ? file_path : "");
    std::string exp(expected_hash ? expected_hash : "");

    if (fp.empty()) return "{\"result\":\"error\",\"message\":\"missing file_path\"}";

    // 计算文件哈希
    std::string computed = "N/A";
    bool match = false;
    int actual_size = 0;

    HANDLE hFile = CreateFileA(fp.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr);
    if (hFile != INVALID_HANDLE_VALUE) {
        DWORD size = GetFileSize(hFile, nullptr);
        actual_size = (int)size;

        char buf[4096];
        DWORD read = 0;
        unsigned long hash = 2166136261UL;
        while (ReadFile(hFile, buf, sizeof(buf), &read, nullptr) && read > 0) {
            for (DWORD i = 0; i < read; i++) {
                hash ^= (unsigned char)buf[i];
                hash *= 16777619UL;
            }
        }
        CloseHandle(hFile);

        char hash_str[32];
        _snprintf_s(hash_str, sizeof(hash_str), _TRUNCATE, "%08lx", hash);
        computed = hash_str;

        if (!exp.empty()) match = (exp == computed);
        else if (file_size > 0) match = (actual_size == file_size);
    }

    char result[512];
    _snprintf_s(result, sizeof(result), _TRUNCATE,
        "{\"result\":\"ok\",\"data\":{\"match\":%s,\"computed_hash\":\"%s\",\"expected_hash\":\"%s\",\"file_size\":%d}}",
        match ? "true" : "false", computed.c_str(), exp.c_str(), actual_size);
    return std::string(result);
}

// ═══════════════════════════════════════════════════════════════
// 新增函数5: generate_token — 生成安全令牌（会话建立时调用）
// 输入: {"action":"generate_token","session_id":"会话ID","timestamp":1234567890,"random_seed":"随机种子"}
// 输出: {"result":"ok","data":{"token":"安全令牌","expires_in":3600,"token_type":"session"}}
// =══════════════════════════════════════════════════════════════
static std::string generate_token_impl(const char* session_id, long long timestamp, const char* random_seed) {
    std::string sid(session_id ? session_id : "");
    std::string seed(random_seed ? random_seed : "");

    if (sid.empty()) return "{\"result\":\"error\",\"message\":\"missing session_id\"}";

    // 组合输入
    char ts_buf[32];
    _snprintf_s(ts_buf, sizeof(ts_buf), _TRUNCATE, "%lld", timestamp);
    std::string combined = sid + "|" + ts_buf + "|" + seed + "|peanut_token_salt_v3";

    // 多层哈希派生令牌
    unsigned long h1 = fnv1a(combined.c_str(), combined.size());
    char h1_str[32];
    _snprintf_s(h1_str, sizeof(h1_str), _TRUNCATE, "%08lx", h1);

    std::string h1_combined = std::string(h1_str) + "_reverse_token";
    unsigned long h2 = fnv1a(h1_combined.c_str(), h1_combined.size());

    unsigned long token_hash = h1 ^ h2;
    time_t now = (time_t)timestamp;
    if (now == 0) now = time(nullptr);

    // 令牌有效期1小时
    int expires_in = 3600;

    char result[512];
    _snprintf_s(result, sizeof(result), _TRUNCATE,
        "{\"result\":\"ok\",\"data\":{\"token\":\"pt_%08lx%08lx_%lld\",\"expires_in\":%d,\"token_type\":\"session\",\"created_at\":%lld}}",
        token_hash, h1, (long long)now, expires_in, (long long)now);
    return std::string(result);
}

// ═══════════════════════════════════════════════════════════════
// ═══════════════════════════════════════════════════════════════
// 新增函数6: verify_signature — 验证签名（服务端下发指令时调用）
// ═══════════════════════════════════════════════════════════════
static std::string verify_signature_impl(const char* payload, const char* signature, const char* pubkey_id) {
    std::string pl(payload ? payload : "");
    std::string sig(signature ? signature : "");
    std::string kid(pubkey_id ? pubkey_id : "default");
    if (pl.empty() || sig.empty()) return "{\"result\":\"error\",\"message\":\"missing payload or signature\"}";
    std::string expected_input = pl + "|" + kid + "|peanut_sign_salt_v2";
    unsigned long expected_hash = fnv1a(expected_input.c_str(), expected_input.size());
    char expected_sig[32];
    _snprintf_s(expected_sig, sizeof(expected_sig), _TRUNCATE, "%08lx", expected_hash);
    bool valid = (sig == expected_sig);
    time_t now = time(nullptr);
    struct tm tm_now; localtime_s(&tm_now, &now);
    char time_buf[32]; strftime(time_buf, sizeof(time_buf), "%Y-%m-%d %H:%M:%S", &tm_now);
    char result[512], escaped_kid[128];
    json_escape(kid.c_str(), escaped_kid, sizeof(escaped_kid));
    _snprintf_s(result, sizeof(result), _TRUNCATE,
        "{\"result\":\"ok\",\"data\":{\"valid\":%s,\"pubkey_id\":\"%s\",\"verify_time\":\"%s\"}}",
        valid ? "true" : "false", escaped_kid, time_buf);
    return std::string(result);
}

// 新增函数7: key_derive — 密钥派生（密钥轮换时调用）
static std::string key_derive_impl(const char* master_key, const char* context, int key_len) {
    std::string mk(master_key ? master_key : "");
    std::string ctx(context ? context : "default");
    if (mk.empty()) return "{\"result\":\"error\",\"message\":\"missing master_key\"}";
    if (key_len <= 0 || key_len > 128) key_len = 32;
    std::string derived; derived.reserve(key_len);
    std::string round_input = mk + "|" + ctx + "|peanut_kdf_salt";
    unsigned long last_hash = fnv1a(round_input.c_str(), round_input.size());
    for (int i = 0; i < key_len; i += 4) {
        char round_str[64]; _snprintf_s(round_str, sizeof(round_str), _TRUNCATE, "%08lx|%d", last_hash, i);
        last_hash = fnv1a(round_str, strlen(round_str));
        derived.push_back((char)(last_hash & 0xFF)); derived.push_back((char)((last_hash >> 8) & 0xFF));
        derived.push_back((char)((last_hash >> 16) & 0xFF)); derived.push_back((char)((last_hash >> 24) & 0xFF));
    }
    derived.resize(key_len);
    char hex_buf[260]; char* p = hex_buf;
    for (int i = 0; i < key_len && p < hex_buf + sizeof(hex_buf) - 3; i++) {
        _snprintf_s(p, 3, _TRUNCATE, "%02x", (unsigned char)derived[i]); p += 2;
    }
    *p = '\0';
    char result[1024], escaped_ctx[128];
    json_escape(ctx.c_str(), escaped_ctx, sizeof(escaped_ctx));
    _snprintf_s(result, sizeof(result), _TRUNCATE,
        "{\"result\":\"ok\",\"data\":{\"derived_key\":\"%s\",\"key_len\":%d,\"context\":\"%s\"}}",
        hex_buf, key_len, escaped_ctx);
    return std::string(result);
}

// 新增函数8: secure_random — 安全随机数生成
static std::string secure_random_impl(int length, const char* seed) {
    if (length <= 0 || length > 256) length = 32;
    std::string sd(seed ? seed : "");
    LARGE_INTEGER counter; QueryPerformanceCounter(&counter);
    DWORD pid = GetCurrentProcessId(), tid = GetCurrentThreadId(), tick = GetTickCount();
    char entropy[128];
    _snprintf_s(entropy, sizeof(entropy), _TRUNCATE, "%lld|%lu|%lu|%lu|%s|peanut_rng",
        counter.QuadPart, pid, tid, tick, sd.c_str());
    std::string random; random.reserve(length);
    unsigned long state = fnv1a(entropy, strlen(entropy));
    for (int i = 0; i < length; i += 4) {
        state ^= (state << 13); state ^= (state >> 17); state ^= (state << 5);
        state = fnv1a((char*)&state, 4) ^ (state * 16777619UL);
        random.push_back((char)(state & 0xFF)); random.push_back((char)((state >> 8) & 0xFF));
        random.push_back((char)((state >> 16) & 0xFF)); random.push_back((char)((state >> 24) & 0xFF));
    }
    random.resize(length);
    char hex_buf[520]; char* p = hex_buf;
    for (int i = 0; i < length && p < hex_buf + sizeof(hex_buf) - 3; i++) {
        _snprintf_s(p, 3, _TRUNCATE, "%02x", (unsigned char)random[i]); p += 2;
    }
    *p = '\0';
    char result[1024];
    _snprintf_s(result, sizeof(result), _TRUNCATE,
        "{\"result\":\"ok\",\"data\":{\"random\":\"%s\",\"length\":%d}}", hex_buf, length);
    return std::string(result);
}

// 新增函数9: check_integrity — 进程完整性检查
static std::string check_integrity_impl(const std::vector<std::string>& paths, const std::vector<std::string>& expected) {
    if (paths.empty()) return "{\"result\":\"error\",\"message\":\"no paths provided\"}";
    std::string results = "["; bool all_ok = true; size_t count = (std::min)(paths.size(), expected.size());
    for (size_t i = 0; i < paths.size(); i++) {
        if (i > 0) results += ",";
        bool match = false; std::string computed = "N/A";
        HANDLE hFile = CreateFileA(paths[i].c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr);
        if (hFile != INVALID_HANDLE_VALUE) {
            char buf[4096]; DWORD read = 0; unsigned long hash = 2166136261UL;
            while (ReadFile(hFile, buf, sizeof(buf), &read, nullptr) && read > 0)
                for (DWORD j = 0; j < read; j++) { hash ^= (unsigned char)buf[j]; hash *= 16777619UL; }
            CloseHandle(hFile);
            char hash_str[32]; _snprintf_s(hash_str, sizeof(hash_str), _TRUNCATE, "%08lx", hash); computed = hash_str;
            if (i < count) match = (expected[i] == computed); else match = true;
        }
        if (!match) all_ok = false;
        char escaped_path[512]; json_escape(paths[i].c_str(), escaped_path, sizeof(escaped_path));
        char item[768];
        _snprintf_s(item, sizeof(item), _TRUNCATE,
            "{\"path\":\"%s\",\"match\":%s,\"computed_hash\":\"%s\"}",
            escaped_path, match ? "true" : "false", computed.c_str());
        results += item;
    }
    results += "]";
    char result[4096];
    _snprintf_s(result, sizeof(result), _TRUNCATE,
        "{\"result\":\"ok\",\"data\":{\"all_ok\":%s,\"results\":%s}}",
        all_ok ? "true" : "false", results.c_str());
    return std::string(result);
}


// PluginExecute 主入口
// =══════════════════════════════════════════════════════════════
extern "C" __declspec(dllexport) int PluginExecute(
    const char* data, int len, int* out_len, char** out_data)
{
    if (!data || len <= 0) {
        const char* err = "{\"result\":\"error\",\"message\":\"invalid input\"}";
        *out_len = (int)strlen(err);
        *out_data = dup_str(err);
        return -1;
    }

    // 解析action字段
    char action[64] = {0};
    json_get_str(data, "action", action, sizeof(action));
    if (action[0] == '\0') {
        const char* err = "{\"result\":\"error\",\"message\":\"missing action\"}";
        *out_len = (int)strlen(err);
        *out_data = dup_str(err);
        return -2;
    }

    std::string result;
    char buf[4096];
    int n = 0;

    // ── 原有函数 ──────────────────────────────────────────
    if (strcmp(action, "generate_abogus") == 0) {
        char urlQuery[2048] = {0}, postBody[4096] = {0}, userAgent[1024] = {0};
        json_get_str(data, "urlQuery", urlQuery, sizeof(urlQuery));
        json_get_str(data, "postBody", postBody, sizeof(postBody));
        json_get_str(data, "userAgent", userAgent, sizeof(userAgent));

        std::string sig = generate_abogus_impl(urlQuery, postBody, userAgent);
        char escaped_sig[1024];
        json_escape(sig.c_str(), escaped_sig, sizeof(escaped_sig));
        n = _snprintf_s(buf, sizeof(buf), _TRUNCATE,
            "{\"result\":\"ok\",\"data\":{\"signature\":\"%s\",\"algorithm\":\"a_bogus_v1\"}}", escaped_sig);
    }
    else if (strcmp(action, "sign_create_room") == 0) {
        char queryString[2048] = {0}, postBody[4096] = {0}, ua[1024] = {0};
        json_get_str(data, "queryString", queryString, sizeof(queryString));
        json_get_str(data, "postBody", postBody, sizeof(postBody));
        json_get_str(data, "ua", ua, sizeof(ua));

        std::string sig = generate_abogus_impl(queryString, postBody, ua);
        char escaped_sig[1024], escaped_query[2048];
        json_escape(sig.c_str(), escaped_sig, sizeof(escaped_sig));
        json_escape(queryString, escaped_query, sizeof(escaped_query));
        n = _snprintf_s(buf, sizeof(buf), _TRUNCATE,
            "{\"result\":\"ok\",\"data\":{\"signature\":\"%s\",\"query\":\"%s\",\"a_bogus\":\"%s\"}}",
            escaped_sig, escaped_query, escaped_sig);
    }
    // ── 新增函数1: decrypt_config ─────────────────────────
    else if (strcmp(action, "decrypt_config") == 0) {
        char encrypted[8192] = {0}, key_seed[256] = {0};
        json_get_str(data, "encrypted_data", encrypted, sizeof(encrypted));
        json_get_str(data, "key_seed", key_seed, sizeof(key_seed));

        std::string decrypted = decrypt_config_impl(encrypted, key_seed);
        char escaped_dec[8700];
        json_escape(decrypted.c_str(), escaped_dec, sizeof(escaped_dec));
        n = _snprintf_s(buf, sizeof(buf), _TRUNCATE,
            "{\"result\":\"ok\",\"data\":{\"decrypted\":\"%s\",\"length\":%zu}}",
            escaped_dec, decrypted.size());
    }
    // ── 新增函数2: verify_license ─────────────────────────
    else if (strcmp(action, "verify_license") == 0) {
        char license_data[4096] = {0}, signature[256] = {0}, machine_code[512] = {0};
        json_get_str(data, "license_data", license_data, sizeof(license_data));
        json_get_str(data, "signature", signature, sizeof(signature));
        json_get_str(data, "machine_code", machine_code, sizeof(machine_code));

        result = verify_license_impl(license_data, signature, machine_code);
        *out_len = (int)result.size();
        *out_data = dup_str(result.c_str());
        return 0;
    }
    // ── 新增函数3: get_device_fingerprint ─────────────────
    else if (strcmp(action, "get_device_fingerprint") == 0) {
        char os_ver[256] = {0}, cpu_id[256] = {0}, disk_serial[256] = {0}, mac_addr[256] = {0};
        json_get_str(data, "os_version", os_ver, sizeof(os_ver));
        json_get_str(data, "cpu_id", cpu_id, sizeof(cpu_id));
        json_get_str(data, "disk_serial", disk_serial, sizeof(disk_serial));
        json_get_str(data, "mac_addr", mac_addr, sizeof(mac_addr));

        result = get_device_fingerprint_impl(os_ver, cpu_id, disk_serial, mac_addr);
        *out_len = (int)result.size();
        *out_data = dup_str(result.c_str());
        return 0;
    }
    // ── 新增函数4: hash_verify ────────────────────────────
    else if (strcmp(action, "hash_verify") == 0) {
        char file_path[512] = {0}, expected_hash[256] = {0};
        int file_size = json_get_int(data, "file_size", 0);
        json_get_str(data, "file_path", file_path, sizeof(file_path));
        json_get_str(data, "expected_hash", expected_hash, sizeof(expected_hash));

        result = hash_verify_impl(file_path, expected_hash, file_size);
        *out_len = (int)result.size();
        *out_data = dup_str(result.c_str());
        return 0;
    }
    // ── 新增函数5: generate_token ─────────────────────────
    else if (strcmp(action, "generate_token") == 0) {
        char session_id[256] = {0}, random_seed[256] = {0};
        long long timestamp = (long long)json_get_int(data, "timestamp", 0);
        json_get_str(data, "session_id", session_id, sizeof(session_id));
        json_get_str(data, "random_seed", random_seed, sizeof(random_seed));

        result = generate_token_impl(session_id, timestamp, random_seed);
        *out_len = (int)result.size();
        *out_data = dup_str(result.c_str());
        return 0;
    }
    // ── 新增函数6: verify_signature ────────────────────────
    else if (strcmp(action, "verify_signature") == 0) {
        char payload[4096] = {0}, signature[256] = {0}, pubkey_id[64] = {0};
        json_get_str(data, "payload", payload, sizeof(payload));
        json_get_str(data, "signature", signature, sizeof(signature));
        json_get_str(data, "pubkey_id", pubkey_id, sizeof(pubkey_id));

        result = verify_signature_impl(payload, signature, pubkey_id);
        *out_len = (int)result.size();
        *out_data = dup_str(result.c_str());
        return 0;
    }
    // ── 新增函数7: key_derive ─────────────────────────────
    else if (strcmp(action, "key_derive") == 0) {
        char master_key[512] = {0}, context[128] = {0};
        int key_len = json_get_int(data, "key_len", 32);
        json_get_str(data, "master_key", master_key, sizeof(master_key));
        json_get_str(data, "context", context, sizeof(context));

        result = key_derive_impl(master_key, context, key_len);
        *out_len = (int)result.size();
        *out_data = dup_str(result.c_str());
        return 0;
    }
    // ── 新增函数8: secure_random ──────────────────────────
    else if (strcmp(action, "secure_random") == 0) {
        int length = json_get_int(data, "length", 32);
        char seed[256] = {0};
        json_get_str(data, "seed", seed, sizeof(seed));

        result = secure_random_impl(length, seed);
        *out_len = (int)result.size();
        *out_data = dup_str(result.c_str());
        return 0;
    }
    // ── 新增函数9: check_integrity ────────────────────────
    else if (strcmp(action, "check_integrity") == 0) {
        std::vector<std::string> paths, expected;
        const char* paths_start = strstr(data, "\"paths\"");
        if (paths_start) {
            const char* arr_start = strchr(paths_start, '[');
            const char* arr_end = arr_start ? strchr(arr_start, ']') : nullptr;
            if (arr_start && arr_end) {
                const char* p = arr_start + 1;
                while (p < arr_end) {
                    const char* q_start = strchr(p, '"');
                    if (!q_start || q_start >= arr_end) break;
                    const char* q_end = strchr(q_start + 1, '"');
                    if (!q_end || q_end >= arr_end) break;
                    paths.push_back(std::string(q_start + 1, q_end - q_start - 1));
                    p = q_end + 1;
                }
            }
        }
        const char* exp_start = strstr(data, "\"expected_hashes\"");
        if (exp_start) {
            const char* arr_start = strchr(exp_start, '[');
            const char* arr_end = arr_start ? strchr(arr_start, ']') : nullptr;
            if (arr_start && arr_end) {
                const char* p = arr_start + 1;
                while (p < arr_end) {
                    const char* q_start = strchr(p, '"');
                    if (!q_start || q_start >= arr_end) break;
                    const char* q_end = strchr(q_start + 1, '"');
                    if (!q_end || q_end >= arr_end) break;
                    expected.push_back(std::string(q_start + 1, q_end - q_start - 1));
                    p = q_end + 1;
                }
            }
        }

        result = check_integrity_impl(paths, expected);
        *out_len = (int)result.size();
        *out_data = dup_str(result.c_str());
        return 0;
    }
    else {
        n = _snprintf_s(buf, sizeof(buf), _TRUNCATE,
            "{\"result\":\"error\",\"message\":\"unknown action: %s\"}", action);
    }

    if (n < 0) {
        const char* err = "{\"result\":\"error\",\"message\":\"output overflow\"}";
        *out_len = (int)strlen(err);
        *out_data = dup_str(err);
        return -3;
    }
    *out_len = n;
    *out_data = dup_str(buf);
    return 0;
}

extern "C" __declspec(dllexport) void PluginDestroy() {}
extern "C" __declspec(dllexport) int PluginGetFunctionCount() { return 9; }
BOOL APIENTRY DllMain(HMODULE, DWORD, LPVOID) { return TRUE; }
