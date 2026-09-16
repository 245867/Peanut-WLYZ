// ============================================================
// 增强插件接口 v2.0
// 扩展原有接口, 增加元数据查询功能
// ============================================================

#pragma once

#ifdef _WIN32
#define PLUGIN_API __declspec(dllexport)
#else
#define PLUGIN_API
#endif

// ── 错误码 ─────────────────────────────────────────────────
#define PLUGIN_SUCCESS                0
#define PLUGIN_ERROR_GENERAL         -1
#define PLUGIN_ERROR_INVALID_PARAM   -2
#define PLUGIN_ERROR_MEMORY          -3

// ── 基础插件执行 ───────────────────────────────────────────
// data: 输入数据
// len: 输入数据长度
// out_len: 输出数据长度 (出参)
// out_data: 输出数据 (出参, 插件负责分配内存)
typedef int (*PluginExecuteFunc)(const char* data, int len, int* out_len, char** out_data);

// ── 内存释放 ───────────────────────────────────────────────
typedef void (*PluginFreeFunc)(char* data);

// ── 增强接口: 获取插件元信息 ──────────────────────────────
// out_name: 插件名称 (出参, 插件分配, 调用方用 PluginFree 释放)
// out_version: 插件版本 (出参)
// out_description: 插件描述 (出参)
// out_author: 插件作者 (出参)
typedef int (*PluginGetInfoFunc)(char** out_name, char** out_version,
                                  char** out_description, char** out_author);

// ── 增强接口: 插件初始化 ─────────────────────────────────
// config_json: 配置JSON字符串 (可为空)
// 返回: 0=成功, 负值=错误码
typedef int (*PluginInitFunc)(const char* config_json);

// ── 增强接口: 插件销毁 ───────────────────────────────────
typedef void (*PluginDestroyFunc)();

// ============================================================
// 插件导出函数约定
// ============================================================
// 必选:
//   PluginExecute(data, len, out_len, out_data) → int
//   PluginFree(data) → void
//
// 可选 (增强功能):
//   PluginGetInfo(out_name, out_version, out_description, out_author) → int
//   PluginInit(config_json) → int
//   PluginDestroy() → void
