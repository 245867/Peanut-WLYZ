#include <windows.h>
#include <cstdlib>
#include <cstring>
#include <string>

static char* Copy(const std::string& value) {
    char* p = static_cast<char*>(std::malloc(value.size() + 1));
    if (p) std::memcpy(p, value.c_str(), value.size() + 1);
    return p;
}

extern "C" __declspec(dllexport) void PluginFree(char* data) { std::free(data); }
extern "C" __declspec(dllexport) int PluginGetFunctionCount() { return 3; }
extern "C" __declspec(dllexport) int PluginInit(const char*) { return 0; }
extern "C" __declspec(dllexport) void PluginDestroy() {}
extern "C" __declspec(dllexport) int PluginGetInfo(char** name, char** version, char** description, char** author) {
    *name=Copy("monitor_policy"); *version=Copy("1.0.0");
    *description=Copy("Monitor App low-frequency cloud policy"); *author=Copy("Peanut"); return 0;
}
extern "C" __declspec(dllexport) int PluginExecute(const char* data, int len, int* outLen, char** outData) {
    std::string input(data && len > 0 ? std::string(data, len) : std::string());
    std::string result;
    if (input.find("vertical_scene") != std::string::npos)
        result = "{\"policy\":\"vertical-v1\",\"width\":540,\"height\":960,\"fps\":20,\"bitrate\":1000,\"audio_bitrate\":160}";
    else if (input.find("loop_live") != std::string::npos)
        result = "{\"policy\":\"loop-v1\",\"min_minutes\":10,\"max_minutes\":240,\"cooldown_minutes\":11}";
    else if (input.find("inject_compat") != std::string::npos)
        result = "{\"policy\":\"inject-v1\",\"retry_count\":3,\"retry_delay_ms\":1200}";
    else return -2;
    *outLen = static_cast<int>(result.size()); *outData = Copy(result); return *outData ? 0 : -3;
}
BOOL APIENTRY DllMain(HMODULE, DWORD, LPVOID) { return TRUE; }
