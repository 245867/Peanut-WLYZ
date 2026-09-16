// PeanutMockServer - demo server with RSA handshake on large-stack thread
#include "../PeanutClient/crypto/key_files.h"
#include "../PeanutClient/crypto/wy_cipher.h"
#include "../PeanutClient/crypto/wy_hash.h"
#include "../PeanutClient/crypto/wy_rsa.h"
#include "../PeanutClient/crypto/wy_random.h"
#include "../PeanutClient/protocol/shadow_tunnel.h"
#include "../PeanutClient/util/util.h"
#include "../PeanutClient/plugin/plugin_interface.h"
#include <httplib.h>
#include <nlohmann/json.hpp>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iostream>
#include <string>
#include <vector>
#include <sstream>
#include <iomanip>
#include <filesystem>
#include <mutex>
#include <unordered_map>
#include <functional>
#include <cstring>
#include <cstdlib>
#include <thread>
#include <fstream>
#include <chrono>
#pragma comment(lib, "ws2_32.lib")

using Json = nlohmann::ordered_json;
namespace fs = std::filesystem;
using namespace peanut::psp;

static std::string g_key_dir = "keys";
static std::string g_cipher_hex;
static std::string g_hmac_key;
static wy::wy_rsa_prikey g_pri;
static HMODULE g_echo_dll = nullptr;
static PluginExecuteFunc g_plugin_exec = nullptr;
static PluginFreeFunc g_plugin_free = nullptr;
struct DemoSession { std::string cardkey, machine_code; long long expires_at = 0; };
static std::mutex g_auth_mutex;
static std::unordered_map<std::string, std::string> g_card_bindings;
static std::unordered_map<std::string, DemoSession> g_sessions;
static std::unordered_map<std::string, long long> g_card_expiries;
static bool g_multi_open_enabled = false;
static int g_max_online_per_card = 1;
static bool g_force_update = false;
static std::string g_target_sha256, g_package_path, g_package_sha256;
static long long g_package_size = 0;

// ── 速率限制 ───────────────────────────────────────────────
static const long long RATE_WINDOW_MS = 60'000;        // 1分钟窗口
static const int     RATE_MAX_AUTH_ATTEMPTS = 10;       // 每窗口最多10次激活请求
static const int     RATE_MAX_TOTAL_REQUESTS = 60;      // 每窗口最多60次总请求
static std::mutex g_rate_mutex;
struct RateEntry { long long window_start = 0; int auth_attempts = 0; int total_requests = 0; };
static std::unordered_map<std::string, RateEntry> g_rate_limits;

static bool CheckRateLimit(const std::string& ip, bool is_auth) {
    std::lock_guard<std::mutex> lock(g_rate_mutex);
    auto& e = g_rate_limits[ip];
    long long now = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    if (now - e.window_start > RATE_WINDOW_MS) { e = {now, 0, 0}; }
    if (e.window_start == 0) e.window_start = now;
    if (is_auth) {
        if (++e.auth_attempts > RATE_MAX_AUTH_ATTEMPTS) return false;
    } else {
        if (++e.total_requests > RATE_MAX_TOTAL_REQUESTS) return false;
    }
    return true;
}

// ── 工具函数 ───────────────────────────────────────────────
static std::string BytesToHex(const uint8_t* d, size_t n);
static std::string HmacHex(const std::string& data, const std::string& key);
static std::string WyEncryptB64(const std::string&, const std::string&);
static std::string WyDecryptB64(const std::string&, const std::string&);
static std::string SignJson(Json);
static std::string RandomToken(const std::string&, const std::string&);
static bool ValidSession(const Json&, DemoSession*);
static bool RegisterSession(const std::string&, const DemoSession&, std::string&);
static std::string TcpEncryptedResponse(Json resp) {
    resp["signature"] = SignJson(resp);
    return WyEncryptB64(resp.dump(), g_cipher_hex);
}
static std::string TcpError(const std::string& msg) {
    return TcpEncryptedResponse({{"status","error"},{"message",msg}});
}

// ── 业务端点 ───────────────────────────────────────────────

static std::string HandleActivate(const Json& q) {
    std::string c = q.value("cardkey",""), m = q.value("machinecode","");
    std::lock_guard<std::mutex> l(g_auth_mutex);
    auto b = g_card_bindings.find(c);
    if (c.empty() || m.empty())
        return TcpError("缺少卡密或机器码");
    if (b != g_card_bindings.end() && b->second != m)
        return TcpError("该卡密已绑定其他电脑，请先解绑");
    g_card_bindings[c] = m;
    long long now = time(nullptr);
    auto expiryIt = g_card_expiries.find(c);
    long long expiry = expiryIt == g_card_expiries.end() ? now + 3600 : expiryIt->second;
    if (expiryIt == g_card_expiries.end()) g_card_expiries[c] = expiry;
    long long remaining = expiry - now;
    if (remaining <= 0)
        return TcpError("授权已经过期");
    std::string t = RandomToken(c, m), sessionError;
    if (!RegisterSession(t, {c, m, expiry}, sessionError))
        return TcpError(sessionError);
    return TcpEncryptedResponse({
        {"status","success"}, {"token",t},
        {"remaining_seconds",remaining}, {"device_id",m},
        {"multi_open_enabled",g_multi_open_enabled},
        {"max_online_per_card", g_multi_open_enabled ? g_max_online_per_card : 1}
    });
}

static std::string HandleHeartbeat(const Json& q, const DemoSession& s) {
    return TcpEncryptedResponse({
        {"status","success"}, {"card_status","active"},
        {"usage_minutes",0}, {"remaining_seconds", s.expires_at - time(nullptr)},
        {"request_nonce", q.value("nonce","")}
    });
}

static std::string HandleUpdatePolicy(const Json& q) {
    return TcpEncryptedResponse({
        {"status","success"}, {"force_update",g_force_update},
        {"build_revoked",false}, {"latest_version","2.1.0"},
        {"minimum_version","2.1.0"},
        {"target_file", q.value("product_id","client") + ".exe"},
        {"target_sha256",g_target_sha256}, {"package_id","current"},
        {"package_sha256",g_package_sha256}, {"package_size",g_package_size},
        {"manifest_version",1}
    });
}

static std::string HandleUpdateDownload() {
    std::ifstream f(g_package_path, std::ios::binary);
    std::vector<uint8_t> b((std::istreambuf_iterator<char>(f)), {});
    return TcpEncryptedResponse({
        {"status", b.empty() ? "error" : "success"},
        {"package_data", Base64Encode(b)}
    });
}

static std::string HandlePluginList() {
    return TcpEncryptedResponse({
        {"status","success"},
        {"plugins", Json::array({{{"name","echo"},{"description","echo"},
         {"version","1.0.0"},{"menu_text","Echo"},{"enabled",true}}})}
    });
}

static std::string HandlePluginExec(const Json& q, const DemoSession& s) {
    std::string plugin = q.value("plugin_name",""), input = q.value("input","");
    Json result;
    if (plugin == "monitor_policy") {
        Json args = Json::parse(input.empty() ? "{}" : input, nullptr, false);
        std::string action = args.is_discarded() ? "" : args.value("action","");
        if (action == "vertical_scene")
            result = {{"width",540},{"height",960},{"fps",20},{"cloud_factor",7}};
        else if (action == "loop_live")
            result = {{"min_minutes",1},{"max_minutes",240},{"cloud_factor",7}};
        else
            result = {{"cloud_factor",7},{"policy","default"}};
    } else {
        result = {{"cloud_factor",7},{"source","server"},{"input",input}};
    }
    return TcpEncryptedResponse({
        {"status","success"}, {"result",result.dump()},
        {"request_nonce", q.value("nonce","")}, {"device_id", s.machine_code}
    });
}

static std::string HandleConfigInfo() {
    return TcpEncryptedResponse({
        {"status","success"}, {"announcement","Peanut TCP server"},
        {"version","2.1.0"}, {"multi_open_enabled",g_multi_open_enabled},
        {"max_online_per_card", g_multi_open_enabled ? g_max_online_per_card : 1}
    });
}

// ── TCP RPC 路由 ───────────────────────────────────────────
static std::string ProcessTcpRpc(const std::string& wire) {
    try {
        Json frame = Json::parse(wire);
        std::string path = frame.value("path",""), data = frame.value("data","");
        if (path == "/psp_handshake") return "ok";

        std::string plain = WyDecryptB64(data, g_cipher_hex);
        Json q = Json::parse(plain);
        std::string sig = q.value("signature","");
        q.erase("signature");
        if (sig.empty() || HmacHex(q.dump(), g_hmac_key) != sig)
            return TcpError("请求签名校验失败");

        // 速率限制：认证路径单独计数
        if (path == "/auth_activate") {
            if (!CheckRateLimit("tcp", true))
                return TcpError("请求过于频繁，请稍后再试");
            return HandleActivate(q);
        }
        if (!CheckRateLimit("tcp", false))
            return TcpError("请求过于频繁，请稍后再试");

        // 不需要会话的路径
        if (path == "/update_policy") return HandleUpdatePolicy(q);
        if (path == "/update_download") return HandleUpdateDownload();

        // 需要有效会话
        DemoSession s;
        if (path != "/config_info" && !ValidSession(q, &s))
            return TcpError("登录会话无效或已过期，请重新登录");

        if (path == "/auth_heartbeat")  return HandleHeartbeat(q, s);
        if (path == "/plugin_list")     return HandlePluginList();
        if (path == "/plugin_exec")     return HandlePluginExec(q, s);
        if (path == "/config_info")     return HandleConfigInfo();

        return TcpError("服务端不支持该请求");
    } catch (...) {
        return TcpError("请求格式错误");
    }
}

// ── TCP 服务 ────────────────────────────────────────────────
static int RunTcpServer(int port) {
    WSADATA wd{}; WSAStartup(MAKEWORD(2,2), &wd);
    SOCKET ls = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    BOOL yes = TRUE;
    setsockopt(ls, SOL_SOCKET, SO_REUSEADDR, (char*)&yes, sizeof(yes));
    sockaddr_in a{}; a.sin_family = AF_INET; a.sin_addr.s_addr = INADDR_ANY;
    a.sin_port = htons((u_short)port);
    if (bind(ls, (sockaddr*)&a, sizeof(a)) || listen(ls, SOMAXCONN)) return 2;
    std::cout << "TCP encrypted listening 0.0.0.0:" << port << "\n";
    for (;;) {
        SOCKET c = accept(ls, nullptr, nullptr);
        std::thread([c]() {
            auto all = [&](char* p, size_t n) {
                while (n) { int x = recv(c, p, (int)n, 0); if (x <= 0) return false; p += x; n -= x; }
                return true;
            };
            for (;;) {
                uint32_t n; if (!all((char*)&n, 4)) break;
                n = ntohl(n); if (!n || n > 64*1024*1024) break;
                std::string w(n, '\0'); if (!all(w.data(), n)) break;
                std::string r = ProcessTcpRpc(w);
                uint32_t rn = htonl((uint32_t)r.size());
                send(c, (char*)&rn, 4, 0);
                size_t o = 0;
                while (o < r.size()) {
                    int x = send(c, r.data() + o, (int)(r.size() - o), 0);
                    if (x <= 0) break; o += x;
                }
            }
            closesocket(c);
        }).detach();
    }
}

// ── 会话管理 ────────────────────────────────────────────────
static bool RegisterSession(const std::string& token, const DemoSession& session, std::string& error) {
    const long long now = time(nullptr);
    for (auto it = g_sessions.begin(); it != g_sessions.end();) {
        if (it->second.expires_at <= now) it = g_sessions.erase(it);
        else ++it;
    }
    if (!g_multi_open_enabled) {
        for (auto it = g_sessions.begin(); it != g_sessions.end();) {
            if (it->second.cardkey == session.cardkey) it = g_sessions.erase(it);
            else ++it;
        }
    } else {
        int online = 0;
        for (const auto& item : g_sessions)
            if (item.second.cardkey == session.cardkey && item.second.expires_at > now) ++online;
        if (online >= (std::max)(1, g_max_online_per_card)) {
            error = "该卡密在线数量已达到服务端限制";
            return false;
        }
    }
    g_sessions[token] = session;
    return true;
}

static std::string RandomToken(const std::string& card, const std::string& machine) {
    uint8_t random[32]; wy::wy_random_bytes(random, sizeof(random));
    return HmacHex(card + "|" + machine + "|" + BytesToHex(random, sizeof(random)) + "|" +
                   std::to_string(time(nullptr)), g_hmac_key);
}
static bool ValidSession(const Json& req, DemoSession* out = nullptr) {
    std::string token = req.value("token","");
    std::lock_guard<std::mutex> lock(g_auth_mutex);
    auto it = g_sessions.find(token);
    if (it == g_sessions.end() || it->second.expires_at < time(nullptr)) return false;
    if (out) *out = it->second; return true;
}

// ── 加密工具 ────────────────────────────────────────────────
static std::vector<uint8_t> HexToBytes(const std::string& hex) {
    std::vector<uint8_t> out;
    for (size_t i = 0; i + 1 < hex.size(); i += 2)
        out.push_back((uint8_t)strtol(hex.substr(i, 2).c_str(), nullptr, 16));
    return out;
}
static std::string BytesToHex(const uint8_t* d, size_t n) {
    std::ostringstream ss; ss << std::hex << std::setfill('0');
    for (size_t i = 0; i < n; ++i) ss << std::setw(2) << (int)d[i];
    return ss.str();
}
static std::string WyEncryptB64(const std::string& plain, const std::string& key_hex) {
    auto key = HexToBytes(key_hex);
    if (key.size() < wy::WY_CIPHER_KEY_SIZE) return "";
    wy::wy_cipher_key ck; wy::wy_cipher_key_schedule(key.data(), &ck);
    uint8_t iv[16]; wy::wy_random_bytes(iv, 16);
    auto ct = wy::wy_cbc_encrypt(&ck, iv, (const uint8_t*)plain.data(), plain.size());
    std::vector<uint8_t> packed; packed.insert(packed.end(), iv, iv+16);
    packed.insert(packed.end(), ct.begin(), ct.end());
    return Base64Encode(packed);
}
static std::string WyDecryptB64(const std::string& b64, const std::string& key_hex) {
    auto raw = Base64Decode(b64);
    if (raw.size() < 16 + wy::WY_CIPHER_BLOCK_SIZE) return "";
    auto key = HexToBytes(key_hex);
    if (key.size() < wy::WY_CIPHER_KEY_SIZE) return "";
    wy::wy_cipher_key ck; wy::wy_cipher_key_schedule(key.data(), &ck);
    auto pt = wy::wy_cbc_decrypt(&ck, raw.data(), raw.data()+16, raw.size()-16);
    return std::string(pt.begin(), pt.end());
}
static std::string HmacHex(const std::string& data, const std::string& key) {
    uint8_t out[wy::WY_HASH_OUTPUT_SIZE];
    wy::wy_hmac((const uint8_t*)key.data(), key.size(),
                (const uint8_t*)data.data(), data.size(), out);
    return BytesToHex(out, wy::WY_HASH_OUTPUT_SIZE);
}
static std::string SignJson(Json j) { j.erase("signature"); return HmacHex(j.dump(), g_hmac_key); }

// ── PSP 帧解析 ─────────────────────────────────────────────
static bool ParsePspFrame(const uint8_t* data, size_t len, PspHeader& hdr,
    std::vector<uint8_t>& rsa_block, std::array<uint8_t, PSP_IV_SIZE>& iv,
    std::vector<uint8_t>& ct, std::array<uint8_t, PSP_HASH_SIZE>& hmac) {
    if (len < PSP_MIN_FRAME) return false;
    size_t off = 0;
    std::memcpy(&hdr, data + off, PSP_HEADER_SIZE); off += PSP_HEADER_SIZE;
    if (hdr.magic0 != PSP_MAGIC0 || hdr.magic1 != PSP_MAGIC1) return false;
    rsa_block.assign(data+off, data+off+PSP_RSA_BLOCK); off += PSP_RSA_BLOCK;
    std::memcpy(iv.data(), data+off, PSP_IV_SIZE); off += PSP_IV_SIZE;
    size_t ct_len = hdr.payload_len;
    if (off + ct_len + PSP_HASH_SIZE > len) return false;
    ct.assign(data+off, data+off+ct_len); off += ct_len;
    std::memcpy(hmac.data(), data+off, PSP_HASH_SIZE);
    return true;
}

struct RsaJob {
    const uint8_t* cipher;
    size_t cipher_len;
    const wy::wy_rsa_prikey* pri;
    std::vector<uint8_t> plain;
    volatile LONG done;
};

static DWORD WINAPI RsaDecryptThread(LPVOID p) {
    auto* job = (RsaJob*)p;
    job->plain = wy::wy_rsa_decrypt(job->cipher, job->cipher_len, job->pri);
    InterlockedExchange(&job->done, 1);
    return 0;
}

static std::vector<uint8_t> RsaDecryptLargeStack(const uint8_t* c, size_t n, const wy::wy_rsa_prikey* pri) {
    RsaJob job{c, n, pri, {}, 0};
    DWORD tid = 0;
    HANDLE th = CreateThread(nullptr, 32 * 1024 * 1024, RsaDecryptThread, &job,
                             STACK_SIZE_PARAM_IS_A_RESERVATION, &tid);
    if (!th) return {};
    WaitForSingleObject(th, INFINITE);
    CloseHandle(th);
    return job.plain;
}

static bool LoadEchoPlugin() {
    fs::path dll = fs::path("plugins") / "echo.dll";
    if (!fs::exists(dll)) { std::cout << "[plugin] no echo.dll\n"; return false; }
    g_echo_dll = LoadLibraryA(dll.string().c_str());
    if (!g_echo_dll) return false;
    g_plugin_exec = (PluginExecuteFunc)GetProcAddress(g_echo_dll, "PluginExecute");
    g_plugin_free = (PluginFreeFunc)GetProcAddress(g_echo_dll, "PluginFree");
    auto init = (PluginInitFunc)GetProcAddress(g_echo_dll, "PluginInit");
    if (init) init("{}");
    std::cout << "[plugin] loaded echo.dll\n";
    return g_plugin_exec && g_plugin_free;
}

// ── HTTP 服务（备用）────────────────────────────────────────
int main(int argc, char** argv) {
    SetConsoleOutputCP(CP_UTF8);
    std::cout.setf(std::ios::unitbuf);
    int port = 9001;
    if (argc >= 2) port = std::atoi(argv[1]);
    if (argc >= 3) g_key_dir = argv[2];
    std::cout << "=== PeanutMockServer === key_dir=" << g_key_dir << " port=" << port << "\n";

    peanut::keys::EnsureBusinessKeys(g_key_dir);
    if (!peanut::keys::LoadServerPrivkey(g_key_dir, g_pri)) {
        std::cerr << "Missing server_privkey.hex (generate with openssl, see keys/)\n";
        return 1;
    }
    peanut::keys::LoadCipherKeyHex(g_key_dir, g_cipher_hex);
    peanut::keys::LoadHmacKey(g_key_dir, g_hmac_key);
    LoadEchoPlugin();
    char env[4096] = {};
    if (GetEnvironmentVariableA("PEANUT_FORCE_UPDATE", env, sizeof(env))) g_force_update = std::string(env) == "1";
    if (GetEnvironmentVariableA("PEANUT_TARGET_SHA256", env, sizeof(env))) g_target_sha256 = env;
    if (GetEnvironmentVariableA("PEANUT_PACKAGE_PATH", env, sizeof(env))) g_package_path = env;
    if (GetEnvironmentVariableA("PEANUT_PACKAGE_SHA256", env, sizeof(env))) g_package_sha256 = env;
    if (GetEnvironmentVariableA("PEANUT_PACKAGE_SIZE", env, sizeof(env))) g_package_size = _atoi64(env);
    if (GetEnvironmentVariableA("PEANUT_MULTI_OPEN", env, sizeof(env))) g_multi_open_enabled = std::string(env) == "1";
    if (GetEnvironmentVariableA("PEANUT_MAX_ONLINE", env, sizeof(env))) g_max_online_per_card = (std::max)(1, std::atoi(env));

    return RunTcpServer(port);
    // HTTP server below remains as reference;
    // TCP is the primary transport for PeanutSecure SDK tests.
    httplib::Server svr;
    svr.Post("/psp_handshake", [](const httplib::Request& req, httplib::Response& res) {
        std::string b64 = req.get_param_value("data");
        if (b64.empty() && req.body.find("data=") == 0)
            b64 = httplib::detail::decode_url(req.body.substr(5), true);
        auto frame = Base64Decode(b64);
        PspHeader hdr{}; std::vector<uint8_t> rsa_block, ct;
        std::array<uint8_t, PSP_IV_SIZE> iv{}; std::array<uint8_t, PSP_HASH_SIZE> hmac{};
        if (!ParsePspFrame(frame.data(), frame.size(), hdr, rsa_block, iv, ct, hmac)) {
            res.status = 400; res.set_content("bad frame", "text/plain"); return;
        }
        std::vector<uint8_t> session;
        if (session.size() == PSP_KEY_SIZE) {
            std::vector<uint8_t> mac_in;
            mac_in.insert(mac_in.end(), (uint8_t*)&hdr, (uint8_t*)&hdr + PSP_HEADER_SIZE);
            mac_in.insert(mac_in.end(), rsa_block.begin(), rsa_block.end());
            mac_in.insert(mac_in.end(), iv.begin(), iv.end());
            mac_in.insert(mac_in.end(), ct.begin(), ct.end());
            uint8_t calc[PSP_HASH_SIZE];
            wy::wy_hmac(session.data(), PSP_KEY_SIZE, mac_in.data(), mac_in.size(), calc);
            if (!wy::wy_const_time_eq(calc, hmac.data(), PSP_HASH_SIZE)) {
                res.status = 403; res.set_content("hmac fail", "text/plain"); return;
            }
            std::cout << "[handshake] OK (rsa verified)\n";
        } else {
            std::cout << "[handshake] OK (demo accept, rsa_size=" << session.size() << ")\n";
        }
        res.status = 200; res.set_content("{\"status\":\"ok\"}", "application/json");
    });

    auto handle_encrypted = [](const httplib::Request& req, httplib::Response& res,
        const std::function<Json(const Json&)>& handler) {
        std::string enc = req.get_param_value("data");
        std::string plain = WyDecryptB64(enc, g_cipher_hex);
        if (plain.empty()) { res.status = 400; res.set_content("decrypt fail", "text/plain"); return; }
        try {
            Json reqj = Json::parse(plain);
            if (reqj.contains("signature")) {
                std::string sig = reqj["signature"].get<std::string>();
                reqj.erase("signature");
                if (HmacHex(reqj.dump(), g_hmac_key) != sig) {
                    res.status = 403; res.set_content("bad sig", "text/plain"); return;
                }
            }
            Json resp = handler(reqj);
            resp["signature"] = SignJson(resp);
            res.status = 200;
            res.set_content(WyEncryptB64(resp.dump(), g_cipher_hex), "text/plain");
        } catch (const std::exception& e) {
            res.status = 500; res.set_content(e.what(), "text/plain");
        }
    };

    auto activate_handler = [&](const httplib::Request& req, httplib::Response& res) {
        handle_encrypted(req, res, [](const Json& reqj) {
            Json resp; std::string card=reqj.value("cardkey",""), machine=reqj.value("machinecode","");
            if(card.empty()||machine.empty()){resp["status"]="error";resp["message"]="missing identity";return resp;}
            std::lock_guard<std::mutex> lock(g_auth_mutex); auto binding=g_card_bindings.find(card);
            if(binding!=g_card_bindings.end()&&binding->second!=machine){resp["status"]="error";resp["message"]="card already bound to another device";return resp;}
            g_card_bindings[card]=machine; std::string token=RandomToken(card,machine); g_sessions[token]={card,machine,time(nullptr)+3600};
            resp["status"]="success"; resp["token"]=token; resp["remaining_seconds"]=3600; resp["device_id"]=machine;
            std::cout << "[activate] " << card << " device=" << machine.substr(0,12) << "\n";
            return resp;
        });
    };
    svr.Get("/activate", activate_handler);
    svr.Get("/auth_activate", activate_handler);
    svr.Get("/auth_heartbeat", [&](const httplib::Request& req, httplib::Response& res) {
        handle_encrypted(req,res,[](const Json& reqj){Json resp;DemoSession s;if(!ValidSession(reqj,&s)){resp["status"]="error";resp["message"]="login session invalid or expired";return resp;}resp["status"]="success";resp["card_status"]="active";resp["usage_minutes"]=0;resp["remaining_seconds"]=s.expires_at-time(nullptr);return resp;});
    });
    svr.Get("/update_policy", [&](const httplib::Request& req, httplib::Response& res) {
        handle_encrypted(req,res,[](const Json& reqj){Json resp;resp["status"]="success";resp["force_update"]=g_force_update;resp["build_revoked"]=false;resp["latest_version"]="2.1.0";resp["minimum_version"]="2.1.0";resp["target_file"]=reqj.value("product_id","client")+".exe";resp["target_sha256"]=g_target_sha256;resp["package_id"]="current";resp["package_sha256"]=g_package_sha256;resp["package_size"]=g_package_size;resp["manifest_version"]=1;return resp;});
    });
    svr.Get("/config_info", [&](const httplib::Request& req, httplib::Response& res) {
        handle_encrypted(req, res, [](const Json& reqj) {
            if (!ValidSession(reqj)) return Json{{"status","error"},{"message","login session invalid or expired"}};
            Json resp; resp["status"]="success";
            resp["announcement"]="PeanutMockServer running";
            resp["version"]="2.0.0-demo"; return resp;
        });
    });
    svr.Get("/plugin_list", [&](const httplib::Request& req, httplib::Response& res) {
        handle_encrypted(req, res, [](const Json&) {
            Json resp; resp["status"]="success";
            resp["plugins"] = Json::array({
                {{"name","echo"},{"description","echo"},{"version","1.0.0"},
                 {"menu_text","Echo"},{"enabled",true}}
            }); return resp;
        });
    });
    svr.Get("/plugin_exec", [&](const httplib::Request& req, httplib::Response& res) {
        handle_encrypted(req, res, [](const Json& reqj) {
            Json resp;
            DemoSession session; if(!ValidSession(reqj,&session)){resp["status"]="error";resp["message"]="login session invalid or expired";return resp;}
            std::string name = reqj.value("plugin_name", "");
            std::string input = reqj.value("input", "");
            if (name == "echo" && g_plugin_exec) {
                int out_len=0; char* out_data=nullptr;
                int rc = g_plugin_exec(input.c_str(), (int)input.size(), &out_len, &out_data);
                if (rc==0 && out_data) {
                    resp["status"]="success"; resp["result"]=std::string(out_data, out_len); resp["device_id"]=session.machine_code; resp["request_nonce"]=reqj.value("nonce","");
                    if (g_plugin_free) g_plugin_free(out_data);
                } else { resp["status"]="error"; resp["message"]="plugin fail"; }
            } else {
                resp["status"]="success";
                resp["result"]="{\"result\":\"ok\",\"message\":\"echo-stub\"}";
            }
            return resp;
        });
    });

    std::cout << "Listening 0.0.0.0:" << port << std::endl;
    if (!svr.listen("0.0.0.0", port)) { std::cerr << "listen fail\n"; return 1; }
    return 0;
}
