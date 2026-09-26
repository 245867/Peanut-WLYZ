// ============================================================
// Peanut WLYZ — 矢量图标库
// 全部用 GDI+ 路径绘制，不依赖任何图标字体 / 位图资源，
// 因此在任何机器上渲染结果完全一致，且可随主题任意着色。
//
// 设计网格：24 x 24，内容安全区 3..21
// 使用方式：DrawIcon(g, L"key", RectF(x,y,16,16), color, 1.8f);
// ============================================================
#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <objidl.h>
#include <propidl.h>
#include <gdiplus.h>

namespace peanut { namespace ui {

// 在 box 区域内绘制指定图标，颜色与线宽可调（线宽基于 24 网格）
void DrawIcon(Gdiplus::Graphics& g, const wchar_t* name,
              const Gdiplus::RectF& box,
              Gdiplus::Color color,
              float strokeW = 1.8f);

// 便捷重载：整型矩形
void DrawIcon(Gdiplus::Graphics& g, const wchar_t* name,
              int x, int y, int w, int h,
              Gdiplus::Color color,
              float strokeW = 1.8f);

// 图标存在性检查（用于降级处理）
bool HasIcon(const wchar_t* name);

}} // namespace peanut::ui
