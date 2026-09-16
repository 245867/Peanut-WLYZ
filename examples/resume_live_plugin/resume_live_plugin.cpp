// resume_live_plugin — 恢复直播检测云DLL插件（方案C）
// 检测直播是否可恢复，解析直播间信息，云端执行
#include <windows.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <string>
#include <sstream>
#include <vector>
#include <ctime>

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
    *out_name = dup_str("resume_live");
    *out_version = dup_str("1.0.0");
    *out_description = dup_str("恢复直播检测 — 检测直播状态并解析直播间信息");
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

static void json_escape(const char* src, char* dst, size_t dst_sz) {
    char* d = dst;
    const char* end = dst + dst_sz - 2;
    for (const char* s = src; *s && d < end; s++) {
        if (*s == '"' || *s == '\\') { if (d < end - 1) { *d++ = '\\'; *d++ = *s; } }
        else if (*s == '\n') { if (d < end - 2) { *d++ = '\\'; *d++ = 'n'; } }
        else if (*s == '\r') { if (d < end - 2) { *d++ = '\\'; *d++ = 'r'; } }
        else if (*s == '\t') { if (d < end - 2) { *d++ = '\\'; *d++ = 't'; } }
        else { *d++ = *s; }
    }
    *d = '\0';
}

// ── 检测直播恢复状态 ───────────────────────────────────────
static std::string check_resume_impl(const char* cookie, const char* roomApiUrl) {
    // 方案C核心：云端分析直播状态
    // 实际部署时通过HTTP请求检测，此处提供框架实现
    std::string ck(cookie ? cookie : "");
    std::string url(roomApiUrl ? roomApiUrl : "");

    // 解析cookie有效性
    bool hasSession = (ck.find("sessionid") != std::string::npos) ||
                      (ck.find("session") != std::string::npos);
    bool hasToken = (ck.find("token") != std::string::npos) ||
                    (ck.find("auth") != std::string::npos);

    // 判断直播状态
    const char* liveStatus = "unknown";
    const char* canResume = "false";
    int roomId = 0;

    // 从URL中尝试提取room_id
    size_t ridPos = url.find("room_id=");
    if (ridPos != std::string::npos) {
        roomId = atoi(url.c_str() + ridPos + 8);
    }
    if (roomId == 0) {
        ridPos = url.find("room/");
        if (ridPos != std::string::npos) {
            roomId = atoi(url.c_str() + ridPos + 5);
        }
    }

    if (hasSession && hasToken && roomId > 0) {
        liveStatus = "live";
        canResume = "true";
    } else if (hasSession && roomId > 0) {
        liveStatus = "ended";
        canResume = "false";
    }

    char result[2048];
    _snprintf_s(result, sizeof(result), _TRUNCATE,
        "{\"can_resume\":%s,\"live_status\":\"%s\",\"room_id\":%d,\"has_session\":%s,\"has_token\":%s}",
        canResume, liveStatus, roomId,
        hasSession ? "true" : "false",
        hasToken ? "true" : "false");
    return std::string(result);
}

// ── 解析直播间信息 ─────────────────────────────────────────
static std::string extract_info_impl(const char* responseBody) {
    std::string body(responseBody ? responseBody : "");

    // 方案C核心：云端解析直播间信息，提取关键字段
    std::string title = "unknown";
    std::string status = "unknown";
    std::string streamUrl = "";
    int onlineCount = 0;
    int likeCount = 0;

    // 简易JSON字段提取（实际部署时可使用完整JSON解析库）
    auto find_field = [&body](const char* key, char* out, size_t sz) {
        out[0] = '\0';
        std::string search = std::string("\"") + key + "\"";
        size_t pos = body.find(search);
        if (pos == std::string::npos) return;
        pos = body.find(':', pos + search.length());
        if (pos == std::string::npos) return;
        pos++;
        while (pos < body.length() && (body[pos] == ' ' || body[pos] == '\t')) pos++;
        if (pos >= body.length()) return;
        if (body[pos] == '"') {
            pos++;
            size_t end = body.find('"', pos);
            if (end != std::string::npos) {
                size_t len = end - pos;
                if (len >= sz) len = sz - 1;
                memcpy(out, body.c_str() + pos, len);
                out[len] = '\0';
            }
        } else {
            size_t end = body.find_first_of(",}\n\r ", pos);
            if (end == std::string::npos) end = body.length();
            size_t len = end - pos;
            if (len >= sz) len = sz - 1;
            memcpy(out, body.c_str() + pos, len);
            out[len] = '\0';
        }
    };

    char tmp[1024];
    find_field("title", tmp, sizeof(tmp));
    if (tmp[0]) title = tmp;
    find_field("status", tmp, sizeof(tmp));
    if (tmp[0]) status = tmp;
    find_field("stream_url", tmp, sizeof(tmp));
    if (tmp[0]) streamUrl = tmp;
    find_field("user_count", tmp, sizeof(tmp));
    if (tmp[0]) onlineCount = atoi(tmp);
    find_field("like_count", tmp, sizeof(tmp));
    if (tmp[0]) likeCount = atoi(tmp);

    char escaped_title[1024], escaped_status[256], escaped_url[1024];
    json_escape(title.c_str(), escaped_title, sizeof(escaped_title));
    json_escape(status.c_str(), escaped_status, sizeof(escaped_status));
    json_escape(streamUrl.c_str(), escaped_url, sizeof(escaped_url));

    char result[4096];
    _snprintf_s(result, sizeof(result), _TRUNCATE,
        "{\"title\":\"%s\",\"status\":\"%s\",\"stream_url\":\"%s\",\"online_count\":%d,\"like_count\":%d}",
        escaped_title, escaped_status, escaped_url, onlineCount, likeCount);
    return std::string(result);
}

// ── PluginExecute 主入口 ────────────────────────────────────
extern "C" __declspec(dllexport) int PluginGetFunctionCount() { return 1; }

extern "C" __declspec(dllexport) int PluginExecute(
    const char* data, int len, int* out_len, char** out_data)
{
    if (!data || len <= 0) {
        const char* err = "{\"result\":\"error\",\"message\":\"invalid input\"}";
        *out_len = (int)strlen(err);
        *out_data = dup_str(err);
        return -1;
    }

    char action[64] = {0};
    json_get_str(data, "action", action, sizeof(action));
    if (action[0] == '\0') {
        const char* err = "{\"result\":\"error\",\"message\":\"missing action\"}";
        *out_len = (int)strlen(err);
        *out_data = dup_str(err);
        return -2;
    }

    char buf[4096];
    int n = 0;

    if (strcmp(action, "check_resume_live") == 0) {
        char cookie[4096] = {0}, roomApiUrl[2048] = {0};
        json_get_str(data, "cookie", cookie, sizeof(cookie));
        json_get_str(data, "roomApiUrl", roomApiUrl, sizeof(roomApiUrl));

        std::string status = check_resume_impl(cookie, roomApiUrl);

        n = _snprintf_s(buf, sizeof(buf), _TRUNCATE,
            "{\"result\":\"ok\",\"data\":%s}", status.c_str());
    }
    else if (strcmp(action, "extract_live_info") == 0) {
        char responseBody[16384] = {0};
        json_get_str(data, "responseBody", responseBody, sizeof(responseBody));

        std::string info = extract_info_impl(responseBody);

        n = _snprintf_s(buf, sizeof(buf), _TRUNCATE,
            "{\"result\":\"ok\",\"data\":%s}", info.c_str());
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
BOOL APIENTRY DllMain(HMODULE, DWORD, LPVOID) { return TRUE; }
