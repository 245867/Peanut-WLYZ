#pragma once
#include <string>
#include <vector>
#include "nlohmann/json.hpp"
using JsonType = nlohmann::ordered_json;

// 云端插件清单条目（仅展示，无版本强制；DLL 永不落地客户端）
struct CloudPluginInfo {
    std::string name;
    std::string description;
    std::string version;    // 可选展示
    std::string menu_text;
    bool        enabled = true;
};

// 读取服务端公告和版本
void FetchServerConfigInfo(const std::string& host, int port,
                           const std::string& aes_key_hex,
                           const std::string& hmac_key);
// 加密并编码请求参数
std::string EncryptAndEncodeRequest(const JsonType& req_json,
                                    const std::string& aes_key_hex);
// 解密Base64响应
std::string DecryptServerResponse(const std::string& base64_data,
                                  const std::string& aes_key_hex);
std::string DecryptServerResponseRaw(const std::string& body,
                                      const std::string& aes_key_hex);
bool VerifySignature(const std::string& json_str, const std::string& hmac_key,
                     const std::string& signature);
void SendHeartbeatRequest(const std::string& host, int port,
                          const std::string& aes_key_hex, const std::string& hmac_key,
                          const std::string& token);

// 拉取服务端插件清单 (/plugin_list)；失败或未实现时 out 为空，不回退本地 DLL
bool FetchPluginList(const std::string& host, int port,
                     const std::string& aes_key_hex, const std::string& hmac_key,
                     const std::string& token,
                     std::vector<CloudPluginInfo>& out_plugins,
                     std::string* out_error = nullptr);

// 远程执行云 DLL (/plugin_exec)，DLL 仅在服务端加载
bool CallPluginExec(const std::string& host, int port,
                    const std::string& aes_key_hex, const std::string& hmac_key,
                    const std::string& token,
                    const std::string& plugin_name,
                    const std::string& input,
                    std::string& out_result,
                    int crypto_type = 0,
                    std::string* out_error = nullptr);

void PressureTestConfigInfo(const std::string& host, int port,
                            const std::string& aes_key_hex, const std::string& hmac_key,
                            int thread_count, int request_per_thread);
void CallLogout(const std::string& host, int port,
                const std::string& aes_key_hex, const std::string& hmac_key,
                const std::string& token, int crypto_type);
std::string MakeSignature(const JsonType& req_json, const std::string& hmac_key);
