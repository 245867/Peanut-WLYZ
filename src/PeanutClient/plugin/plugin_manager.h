// ============================================================
// 插件管理器 — 服务端加载器原型（非客户端业务路径）
//
// 云 DLL 只在服务端 LoadLibrary。客户端通过 /plugin_list、
// /plugin_exec 远程调用，永不落地 DLL。
//
// 热替换：更新文件前必须 unload_plugin / unload_all，
// 否则 Windows 会占用 DLL 文件导致覆盖失败。
// ============================================================

#pragma once

#include "plugin_interface.h"

#ifdef _WIN32
#include <windows.h>
#else
#include <dlfcn.h>
#endif

#include <string>
#include <vector>
#include <memory>
#include <functional>

namespace peanut {
namespace plugin {

// ── 插件元信息 ─────────────────────────────────────────────
struct PluginInfo {
    std::string name;           // 插件名称
    std::string version;        // 版本号
    std::string description;    // 功能描述
    std::string author;         // 作者
    std::string file_path;      // DLL文件路径
    bool        loaded = false; // 是否已加载
    bool        has_info = false;     // 是否有GetInfo函数
    bool        has_init = false;     // 是否有Init函数
    bool        has_destroy = false;  // 是否有Destroy函数
};

// ── 插件实例 ───────────────────────────────────────────────
struct PluginInstance {
    PluginInfo info;

#ifdef _WIN32
    HMODULE handle = nullptr;
#else
    void* handle = nullptr;
#endif

    PluginExecuteFunc   execute   = nullptr;
    PluginFreeFunc      free      = nullptr;
    PluginGetInfoFunc   get_info  = nullptr;
    PluginInitFunc      init      = nullptr;
    PluginDestroyFunc   destroy   = nullptr;
};

// ── 插件回调 ───────────────────────────────────────────────
using PluginLogCallback = std::function<void(const std::string& msg)>;

// ── 插件管理器 ─────────────────────────────────────────────
class PluginManager {
public:
    static PluginManager& instance() {
        static PluginManager mgr;
        return mgr;
    }

    // 设置日志回调
    void set_log_callback(PluginLogCallback cb) { log_cb_ = std::move(cb); }

    // 扫描插件目录
    std::vector<PluginInfo> scan_directory(const std::string& dir_path);

    // 加载单个插件
    bool load_plugin(const std::string& dll_path);

    // 加载目录下所有插件
    int load_all(const std::string& dir_path);

    // 卸载插件（热替换前必须调用，以 FreeLibrary 释放文件锁）
    bool unload_plugin(const std::string& name);
    void unload_all();

    // 获取已加载插件列表
    const std::vector<PluginInstance>& loaded_plugins() const { return plugins_; }
    std::vector<PluginInfo> loaded_plugin_infos() const;

    // 执行插件
    struct ExecResult {
        bool        success;
        int         error_code;
        std::string output;
    };

    ExecResult execute(const std::string& plugin_name,
                       const std::string& input);

    // 初始化所有插件
    void init_all(const std::string& config_json = "");

private:
    PluginManager() = default;
    ~PluginManager() { unload_all(); }
    PluginManager(const PluginManager&) = delete;
    PluginManager& operator=(const PluginManager&) = delete;

    void log(const std::string& msg) {
        if (log_cb_) log_cb_(msg);
    }

    // 分配器辅助: 在DLL内分配, 跨模块free
    static std::string drain_plugin_string(char* ptr, PluginFreeFunc free_fn);

    std::vector<PluginInstance> plugins_;
    PluginLogCallback log_cb_;
};

} // namespace plugin
} // namespace peanut
