// echo_plugin — 云 DLL 基础示例（仅服务端加载）
#include <windows.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

static char* dup_str(const char* s) {
    size_t n = strlen(s) + 1;
    char* p = (char*)malloc(n);
    if (p) memcpy(p, s, n);
    return p;
}

extern "C" __declspec(dllexport) void PluginFree(char* data) { free(data); }

extern "C" __declspec(dllexport) int PluginGetInfo(
    char** out_name, char** out_version,
    char** out_description, char** out_author)
{
    *out_name = dup_str("echo");
    *out_version = dup_str("1.0.0");
    *out_description = dup_str("echo input");
    *out_author = dup_str("Peanut");
    return 0;
}

extern "C" __declspec(dllexport) int PluginInit(const char*) { return 0; }
extern "C" __declspec(dllexport) int PluginGetFunctionCount() { return 1; }

extern "C" __declspec(dllexport) int PluginExecute(
    const char* data, int len, int* out_len, char** out_data)
{
    char buf[4096];
    int n = _snprintf_s(buf, sizeof(buf), _TRUNCATE,
        "{\"result\":\"ok\",\"message\":\"echo\",\"data\":{\"input_len\":%d}}", len);
    if (n < 0) return -1;
    *out_len = n;
    *out_data = dup_str(buf);
    (void)data;
    return 0;
}

extern "C" __declspec(dllexport) void PluginDestroy() {}
BOOL APIENTRY DllMain(HMODULE, DWORD, LPVOID) { return TRUE; }
