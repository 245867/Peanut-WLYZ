// ============================================================
// 插件管理器实现
// ============================================================

#include "plugin_manager.h"

#include <filesystem>
#include <algorithm>

namespace peanut {
namespace plugin {

namespace fs = std::filesystem;

std::string PluginManager::drain_plugin_string(char* ptr, PluginFreeFunc free_fn) {
    if (!ptr) return "";
    std::string result(ptr);
    if (free_fn) free_fn(ptr);
    return result;
}

std::vector<PluginInfo> PluginManager::scan_directory(const std::string& dir_path) {
    std::vector<PluginInfo> result;
    if (!fs::exists(dir_path) || !fs::is_directory(dir_path)) {
        log("[PluginManager] 插件目录不存在: " + dir_path);
        return result;
    }

    for (const auto& entry : fs::directory_iterator(dir_path)) {
        if (!entry.is_regular_file()) continue;
        auto ext = entry.path().extension().string();
        // Windows: .dll, Linux: .so
        if (ext == ".dll" || ext == ".so" || ext == ".DLL") {
            PluginInfo info;
            info.file_path = entry.path().string();
            info.name = entry.path().stem().string();
            result.push_back(info);
        }
    }
    log("[PluginManager] 扫描到 " + std::to_string(result.size()) + " 个插件");
    return result;
}

bool PluginManager::load_plugin(const std::string& dll_path) {
    // 检查是否重复加载
    for (auto& p : plugins_) {
        if (p.info.file_path == dll_path) {
            log("[PluginManager] 插件已加载: " + dll_path);
            return true;
        }
    }

    PluginInstance inst;
    inst.info.file_path = dll_path;
    inst.info.name = fs::path(dll_path).stem().string();

#ifdef _WIN32
    inst.handle = LoadLibraryA(dll_path.c_str());
    if (!inst.handle) {
        DWORD err = GetLastError();
        log("[PluginManager] 加载DLL失败: " + dll_path + " (错误码: " + std::to_string(err) + ")");
        return false;
    }

    // 加载必选函数
    inst.execute = reinterpret_cast<PluginExecuteFunc>(
        GetProcAddress(inst.handle, "PluginExecute"));
    inst.free = reinterpret_cast<PluginFreeFunc>(
        GetProcAddress(inst.handle, "PluginFree"));

    if (!inst.execute || !inst.free) {
        log("[PluginManager] 插件缺少必选函数 PluginExecute/PluginFree: " + dll_path);
        FreeLibrary(inst.handle);
        return false;
    }

    // 加载可选增强函数
    inst.get_info = reinterpret_cast<PluginGetInfoFunc>(
        GetProcAddress(inst.handle, "PluginGetInfo"));
    inst.init = reinterpret_cast<PluginInitFunc>(
        GetProcAddress(inst.handle, "PluginInit"));
    inst.destroy = reinterpret_cast<PluginDestroyFunc>(
        GetProcAddress(inst.handle, "PluginDestroy"));
#else
    inst.handle = dlopen(dll_path.c_str(), RTLD_LAZY);
    if (!inst.handle) {
        log("[PluginManager] 加载SO失败: " + dll_path + " (" + dlerror() + ")");
        return false;
    }
    inst.execute = reinterpret_cast<PluginExecuteFunc>(dlsym(inst.handle, "PluginExecute"));
    inst.free = reinterpret_cast<PluginFreeFunc>(dlsym(inst.handle, "PluginFree"));
    if (!inst.execute || !inst.free) {
        log("[PluginManager] 插件缺少必选函数: " + dll_path);
        dlclose(inst.handle);
        return false;
    }
    inst.get_info = reinterpret_cast<PluginGetInfoFunc>(dlsym(inst.handle, "PluginGetInfo"));
    inst.init = reinterpret_cast<PluginInitFunc>(dlsym(inst.handle, "PluginInit"));
    inst.destroy = reinterpret_cast<PluginDestroyFunc>(dlsym(inst.handle, "PluginDestroy"));
#endif

    inst.info.loaded = true;

    // 如果有GetInfo, 读取元信息
    if (inst.get_info) {
        inst.info.has_info = true;
        char *name_p = nullptr, *ver_p = nullptr, *desc_p = nullptr, *author_p = nullptr;
        if (inst.get_info(&name_p, &ver_p, &desc_p, &author_p) == PLUGIN_SUCCESS) {
            inst.info.name        = drain_plugin_string(name_p, inst.free);
            inst.info.version     = drain_plugin_string(ver_p, inst.free);
            inst.info.description = drain_plugin_string(desc_p, inst.free);
            inst.info.author      = drain_plugin_string(author_p, inst.free);
        }
    }

    inst.info.has_init    = (inst.init != nullptr);
    inst.info.has_destroy = (inst.destroy != nullptr);

    plugins_.push_back(inst);
    log("[PluginManager] 插件加载成功: " + inst.info.name +
        " v" + inst.info.version + " by " + inst.info.author);
    return true;
}

int PluginManager::load_all(const std::string& dir_path) {
    auto infos = scan_directory(dir_path);
    int count = 0;
    for (auto& info : infos) {
        if (load_plugin(info.file_path)) {
            ++count;
        }
    }
    return count;
}

bool PluginManager::unload_plugin(const std::string& name) {
    auto it = std::find_if(plugins_.begin(), plugins_.end(),
        [&name](const PluginInstance& p) { return p.info.name == name; });

    if (it == plugins_.end()) {
        log("[PluginManager] 未找到插件: " + name);
        return false;
    }

    if (it->info.has_destroy && it->destroy) {
        it->destroy();
    }

#ifdef _WIN32
    if (it->handle) FreeLibrary(it->handle);
#else
    if (it->handle) dlclose(it->handle);
#endif

    log("[PluginManager] 插件已卸载: " + name);
    plugins_.erase(it);
    return true;
}

void PluginManager::unload_all() {
    for (auto it = plugins_.rbegin(); it != plugins_.rend(); ++it) {
        if (it->info.has_destroy && it->destroy) {
            it->destroy();
        }
#ifdef _WIN32
        if (it->handle) FreeLibrary(it->handle);
#else
        if (it->handle) dlclose(it->handle);
#endif
    }
    plugins_.clear();
    log("[PluginManager] 所有插件已卸载");
}

std::vector<PluginInfo> PluginManager::loaded_plugin_infos() const {
    std::vector<PluginInfo> result;
    for (auto& p : plugins_) {
        result.push_back(p.info);
    }
    return result;
}

PluginManager::ExecResult PluginManager::execute(
    const std::string& plugin_name, const std::string& input)
{
    ExecResult result;
    result.success = false;

    auto it = std::find_if(plugins_.begin(), plugins_.end(),
        [&plugin_name](const PluginInstance& p) { return p.info.name == plugin_name; });

    if (it == plugins_.end()) {
        result.error_code = PLUGIN_ERROR_GENERAL;
        log("[PluginManager] 插件未加载: " + plugin_name);
        return result;
    }

    int out_len = 0;
    char* out_data = nullptr;
    int ret = it->execute(input.c_str(), static_cast<int>(input.size()),
                           &out_len, &out_data);
    result.error_code = ret;

    if (ret == PLUGIN_SUCCESS && out_data && out_len > 0) {
        result.output.assign(out_data, out_len);
        result.success = true;
        if (it->free) it->free(out_data);
    } else if (out_data && it->free) {
        it->free(out_data);
    }

    return result;
}

void PluginManager::init_all(const std::string& config_json) {
    for (auto& p : plugins_) {
        if (p.info.has_init && p.init) {
            int ret = p.init(config_json.c_str());
            if (ret == PLUGIN_SUCCESS) {
                log("[PluginManager] 插件初始化成功: " + p.info.name);
            } else {
                log("[PluginManager] 插件初始化失败: " + p.info.name +
                    " (错误码: " + std::to_string(ret) + ")");
            }
        }
    }
}

} // namespace plugin
} // namespace peanut
