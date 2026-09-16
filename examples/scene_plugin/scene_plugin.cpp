// scene_plugin — 竖屏场景应用云DLL插件（方案C）
// 计算竖屏场景配置，验证场景配置合法性，云端执行
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
    *out_name = dup_str("scene");
    *out_version = dup_str("1.0.0");
    *out_description = dup_str("竖屏场景应用 — 计算场景配置并验证合法性");
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

// ── 计算竖屏场景配置 ───────────────────────────────────────
static std::string compute_vertical_scene_impl(const char* sourcePath, const char* targetPath) {
    std::string src(sourcePath ? sourcePath : "");
    std::string dst(targetPath ? targetPath : "");

    // 方案C核心：云端计算竖屏场景的OBS/直播伴侣配置
    // 竖屏分辨率: 1080x1920 (9:16)
    int baseWidth = 1080;
    int baseHeight = 1920;
    int canvasWidth = 1080;
    int canvasHeight = 1920;

    // 输入源区域计算（居中裁剪）
    int sourceX = 0, sourceY = 0, sourceW = 1920, sourceH = 1080;
    if (src.find("1920x1080") != std::string::npos || src.find("16:9") != std::string::npos) {
        // 横屏源 → 竖屏：居中裁剪
        sourceW = 1920; sourceH = 1080;
        int cropW = (int)(sourceH * 9.0 / 16.0);
        sourceX = (sourceW - cropW) / 2;
        sourceW = cropW;
        sourceY = 0;
    }

    // 输出区域
    int outputX = 0, outputY = 0, outputW = canvasWidth, outputH = canvasHeight;

    // 生成场景配置JSON
    char result[4096];
    _snprintf_s(result, sizeof(result), _TRUNCATE,
        "{"
        "\"scene_type\":\"vertical\","
        "\"canvas\":{\"width\":%d,\"height\":%d},"
        "\"source\":{"
            "\"x\":%d,\"y\":%d,\"width\":%d,\"height\":%d,"
            "\"path\":\"%s\""
        "},"
        "\"output\":{"
            "\"x\":%d,\"y\":%d,\"width\":%d,\"height\":%d,"
            "\"path\":\"%s\""
        "},"
        "\"aspect_ratio\":\"9:16\","
        "\"rotation\":0"
        "}",
        canvasWidth, canvasHeight,
        sourceX, sourceY, sourceW, sourceH, src.c_str(),
        outputX, outputY, outputW, outputH, dst.c_str());
    return std::string(result);
}

// ── 验证场景配置 ───────────────────────────────────────────
static std::string validate_config_impl(const char* jsonConfig) {
    std::string cfg(jsonConfig ? jsonConfig : "");

    bool valid = true;
    std::string errors;
    std::string warnings;

    // 检查必需字段
    if (cfg.find("\"scene_type\"") == std::string::npos) {
        valid = false;
        errors += "missing scene_type;";
    }
    if (cfg.find("\"canvas\"") == std::string::npos) {
        valid = false;
        errors += "missing canvas;";
    }
    if (cfg.find("\"source\"") == std::string::npos) {
        valid = false;
        errors += "missing source;";
    }
    if (cfg.find("\"output\"") == std::string::npos) {
        valid = false;
        errors += "missing output;";
    }

    // 检查分辨率范围
    int canvasW = json_get_int(cfg.c_str(), "width", 0);
    int canvasH = json_get_int(cfg.c_str(), "height", 0);
    if (canvasW > 0 && canvasH > 0) {
        if (canvasW < 320 || canvasW > 7680) {
            valid = false;
            errors += "canvas width out of range (320-7680);";
        }
        if (canvasH < 320 || canvasH > 7680) {
            valid = false;
            errors += "canvas height out of range (320-7680);";
        }
        if (canvasW > canvasH) {
            warnings += "canvas is landscape, not vertical (9:16);";
        }
    }

    // 检查宽高比
    if (canvasW > 0 && canvasH > 0) {
        double ratio = (double)canvasH / (double)canvasW;
        if (ratio < 1.5 || ratio > 2.0) {
            warnings += "aspect ratio not ideal for vertical (expected ~1.78);";
        }
    }

    char result[4096];
    char escaped_errors[2048], escaped_warnings[2048];
    json_escape(errors.c_str(), escaped_errors, sizeof(escaped_errors));
    json_escape(warnings.c_str(), escaped_warnings, sizeof(escaped_warnings));

    _snprintf_s(result, sizeof(result), _TRUNCATE,
        "{\"valid\":%s,\"errors\":\"%s\",\"warnings\":\"%s\"}",
        valid ? "true" : "false", escaped_errors, escaped_warnings);
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

    if (strcmp(action, "compute_vertical_scene") == 0) {
        char sourcePath[1024] = {0}, targetPath[1024] = {0};
        json_get_str(data, "sourcePath", sourcePath, sizeof(sourcePath));
        json_get_str(data, "targetPath", targetPath, sizeof(targetPath));

        std::string config = compute_vertical_scene_impl(sourcePath, targetPath);

        n = _snprintf_s(buf, sizeof(buf), _TRUNCATE,
            "{\"result\":\"ok\",\"data\":%s}", config.c_str());
    }
    else if (strcmp(action, "validate_scene_config") == 0) {
        char jsonConfig[8192] = {0};
        json_get_str(data, "jsonConfig", jsonConfig, sizeof(jsonConfig));

        std::string validation = validate_config_impl(jsonConfig);

        n = _snprintf_s(buf, sizeof(buf), _TRUNCATE,
            "{\"result\":\"ok\",\"data\":%s}", validation.c_str());
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
