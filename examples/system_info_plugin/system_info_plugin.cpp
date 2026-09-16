#include <windows.h>
#include <intrin.h>
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
    *out_name = dup_str("system_info");
    *out_version = dup_str("1.0.0");
    *out_description = dup_str("Get system information: OS, CPU, memory, disk");
    *out_author = dup_str("Peanut");
    return 0;
}

extern "C" __declspec(dllexport) int PluginInit(const char*) { return 0; }

static void get_os_info(char* buf, size_t sz) {
    OSVERSIONINFOEXW vi = { sizeof(vi) };
    typedef LONG(WINAPI* RtlGetVersionPtr)(PRTL_OSVERSIONINFOW);
    auto RtlGetVersion = (RtlGetVersionPtr)GetProcAddress(GetModuleHandleW(L"ntdll"), "RtlGetVersion");
    if (RtlGetVersion) RtlGetVersion((PRTL_OSVERSIONINFOW)&vi);
    char arch[16] = "x86";
    SYSTEM_INFO si; GetSystemInfo(&si);
    if (si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64) strcpy_s(arch, "x64");
    else if (si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_ARM64) strcpy_s(arch, "ARM64");
    _snprintf_s(buf, sz, _TRUNCATE, "Windows %d.%d.%d %s", vi.dwMajorVersion, vi.dwMinorVersion, vi.dwBuildNumber, arch);
}

static void get_cpu_info(char* buf, size_t sz) {
    SYSTEM_INFO si; GetSystemInfo(&si);
    _snprintf_s(buf, sz, _TRUNCATE, "%lu logical processors", si.dwNumberOfProcessors);
}

static void get_mem_info(char* buf, size_t sz) {
    MEMORYSTATUSEX ms = { sizeof(ms) };
    GlobalMemoryStatusEx(&ms);
    double totalGB = (double)ms.ullTotalPhys / 1073741824.0;
    double availGB = (double)ms.ullAvailPhys / 1073741824.0;
    _snprintf_s(buf, sz, _TRUNCATE, "Total: %.1f GB, Available: %.1f GB (%lu%%)",
        totalGB, availGB, ms.dwMemoryLoad);
}

extern "C" __declspec(dllexport) int PluginGetFunctionCount() { return 1; }

extern "C" __declspec(dllexport) int PluginExecute(
    const char* data, int len, int* out_len, char** out_data)
{
    (void)data; (void)len;
    char os[256], cpu[256], mem[256], buf[4096];
    get_os_info(os, sizeof(os));
    get_cpu_info(cpu, sizeof(cpu));
    get_mem_info(mem, sizeof(mem));
    int n = _snprintf_s(buf, sizeof(buf), _TRUNCATE,
        "{\"result\":\"ok\",\"os\":\"%s\",\"cpu\":\"%s\",\"memory\":\"%s\"}", os, cpu, mem);
    if (n < 0) return -1;
    *out_len = n;
    *out_data = dup_str(buf);
    return 0;
}

extern "C" __declspec(dllexport) void PluginDestroy() {}

BOOL APIENTRY DllMain(HMODULE, DWORD, LPVOID) { return TRUE; }
