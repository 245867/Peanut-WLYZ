// ============================================================
// Peanut WLYZ — 矢量图标库 (实现)
// ============================================================
#include "ui_icons.h"
#include <cmath>
#include <cwchar>
#include <algorithm>

using namespace Gdiplus;

namespace peanut { namespace ui {
namespace {

const float PI = 3.14159265358979f;

// 圆角矩形路径（24 网格坐标）。GraphicsPath 不可拷贝，故用输出参数。
void RRect(GraphicsPath& p, float x, float y, float w, float h, float r) {
    p.Reset();
    float d = r * 2.0f;
    if (d > w) d = w;
    if (d > h) d = h;
    if (d < 1.0f) { p.AddRectangle(RectF(x, y, w, h)); return; }
    p.AddArc(x, y, d, d, 180.0f, 90.0f);
    p.AddArc(x + w - d, y, d, d, 270.0f, 90.0f);
    p.AddArc(x + w - d, y + h - d, d, d, 0.0f, 90.0f);
    p.AddArc(x, y + h - d, d, d, 90.0f, 90.0f);
    p.CloseFigure();
}

PointF P(float x, float y) { return PointF(x, y); }

PointF Polar(float cx, float cy, float r, float deg) {
    const float a = deg * PI / 180.0f;
    return PointF(cx + r * std::cos(a), cy + r * std::sin(a));
}

// ── 各图标绘制（均在 24x24 网格内） ──────────────────────

void IcoDashboard(Graphics& g, const Pen&, const SolidBrush& br) {
    GraphicsPath p;
    const float pos[4][2] = { {3,3}, {13.5f,3}, {3,13.5f}, {13.5f,13.5f} };
    for (int i = 0; i < 4; ++i) {
        RRect(p, pos[i][0], pos[i][1], 7.5f, 7.5f, 2.2f);
        g.FillPath(&br, &p);
    }
}

void IcoKey(Graphics& g, const Pen& pen, const SolidBrush&) {
    g.DrawEllipse(&pen, 3.6f, 3.6f, 9.0f, 9.0f);
    g.DrawLine(&pen, P(11.0f, 11.0f), P(20.0f, 20.0f));
    g.DrawLine(&pen, P(16.4f, 16.4f), P(19.6f, 13.2f));
    g.DrawLine(&pen, P(19.0f, 19.0f), P(21.4f, 16.6f));
}

void IcoPlugin(Graphics& g, const Pen&, const SolidBrush& br) {
    GraphicsPath p;
    RRect(p, 3.0f, 3.0f, 14.0f, 14.0f, 2.4f);
    g.FillPath(&br, &p);
    g.FillEllipse(&br, 15.2f, 7.0f, 5.6f, 5.6f);
    g.FillEllipse(&br, 7.0f, 15.2f, 5.6f, 5.6f);
}

void IcoShield(Graphics& g, const Pen& pen, const SolidBrush&) {
    GraphicsPath p;
    p.AddLine(P(12.0f, 2.8f), P(19.8f, 5.9f));
    p.AddLine(P(19.8f, 5.9f), P(19.8f, 12.4f));
    p.AddBezier(P(19.8f, 12.4f), P(19.8f, 16.6f), P(16.8f, 20.0f), P(12.0f, 21.4f));
    p.AddBezier(P(12.0f, 21.4f), P(7.2f, 20.0f), P(4.2f, 16.6f), P(4.2f, 12.4f));
    p.AddLine(P(4.2f, 12.4f), P(4.2f, 5.9f));
    p.CloseFigure();
    g.DrawPath(&pen, &p);
}

void IcoGear(Graphics& g, const Pen&, const SolidBrush& br) {
    const int N = 16;
    PointF pts[N];
    for (int i = 0; i < N; ++i) {
        const float r = (i % 2 == 0) ? 10.2f : 7.4f;
        pts[i] = Polar(12.0f, 12.0f, r, -90.0f + i * (360.0f / N));
    }
    GraphicsPath p;
    p.SetFillMode(FillModeAlternate);
    p.AddPolygon(pts, N);
    p.AddEllipse(9.0f, 9.0f, 6.0f, 6.0f);
    g.FillPath(&br, &p);
}

void IcoPlus(Graphics& g, const Pen& pen, const SolidBrush&) {
    g.DrawLine(&pen, P(12.0f, 4.5f), P(12.0f, 19.5f));
    g.DrawLine(&pen, P(4.5f, 12.0f), P(19.5f, 12.0f));
}

void IcoRefresh(Graphics& g, const Pen& pen, const SolidBrush& br) {
    GraphicsPath p;
    p.AddArc(4.0f, 4.0f, 16.0f, 16.0f, -55.0f, 290.0f);
    g.DrawPath(&pen, &p);
    PointF tri[3] = { P(17.6f, 1.4f), P(21.2f, 6.6f), P(13.6f, 6.4f) };
    g.FillPolygon(&br, tri, 3);
}

void IcoSearch(Graphics& g, const Pen& pen, const SolidBrush&) {
    g.DrawEllipse(&pen, 3.6f, 3.6f, 12.4f, 12.4f);
    g.DrawLine(&pen, P(15.2f, 15.2f), P(20.6f, 20.6f));
}

void IcoDownload(Graphics& g, const Pen& pen, const SolidBrush&) {
    g.DrawLine(&pen, P(12.0f, 3.2f), P(12.0f, 15.4f));
    g.DrawLine(&pen, P(6.8f, 10.4f), P(12.0f, 15.8f));
    g.DrawLine(&pen, P(17.2f, 10.4f), P(12.0f, 15.8f));
    g.DrawLine(&pen, P(4.6f, 19.8f), P(19.4f, 19.8f));
}

void IcoUpload(Graphics& g, const Pen& pen, const SolidBrush&) {
    g.DrawLine(&pen, P(12.0f, 15.8f), P(12.0f, 3.6f));
    g.DrawLine(&pen, P(6.8f, 8.6f), P(12.0f, 3.2f));
    g.DrawLine(&pen, P(17.2f, 8.6f), P(12.0f, 3.2f));
    g.DrawLine(&pen, P(4.6f, 19.8f), P(19.4f, 19.8f));
}

void IcoTrash(Graphics& g, const Pen& pen, const SolidBrush&) {
    g.DrawLine(&pen, P(3.6f, 6.4f), P(20.4f, 6.4f));
    g.DrawLine(&pen, P(9.4f, 6.4f), P(9.4f, 3.4f));
    g.DrawLine(&pen, P(9.4f, 3.4f), P(14.6f, 3.4f));
    g.DrawLine(&pen, P(14.6f, 3.4f), P(14.6f, 6.4f));
    g.DrawLine(&pen, P(5.8f, 6.4f), P(6.9f, 20.6f));
    g.DrawLine(&pen, P(6.9f, 20.6f), P(17.1f, 20.6f));
    g.DrawLine(&pen, P(17.1f, 20.6f), P(18.2f, 6.4f));
    g.DrawLine(&pen, P(10.2f, 9.8f), P(10.2f, 17.4f));
    g.DrawLine(&pen, P(13.8f, 9.8f), P(13.8f, 17.4f));
}

void IcoUnlink(Graphics& g, const Pen& pen, const SolidBrush&) {
    g.DrawArc(&pen, 1.6f, 7.6f, 9.4f, 9.4f, 70.0f, 210.0f);
    g.DrawArc(&pen, 13.0f, 7.6f, 9.4f, 9.4f, -100.0f, 210.0f);
    g.DrawLine(&pen, P(9.9f, 3.6f), P(14.1f, 20.4f));
}

void IcoNote(Graphics& g, const Pen& pen, const SolidBrush&) {
    GraphicsPath p;
    p.AddLine(P(4.6f, 19.4f), P(7.4f, 12.2f));
    p.AddLine(P(7.4f, 12.2f), P(15.4f, 4.2f));
    p.AddLine(P(15.4f, 4.2f), P(19.8f, 8.6f));
    p.AddLine(P(19.8f, 8.6f), P(11.8f, 16.6f));
    p.CloseFigure();
    g.DrawPath(&pen, &p);
    g.DrawLine(&pen, P(4.6f, 19.4f), P(8.6f, 19.4f));
}

void IcoCheck(Graphics& g, const Pen& pen, const SolidBrush&) {
    g.DrawLine(&pen, P(4.2f, 12.6f), P(9.6f, 18.0f));
    g.DrawLine(&pen, P(9.6f, 18.0f), P(19.8f, 6.2f));
}

void IcoBolt(Graphics& g, const Pen&, const SolidBrush& br) {
    PointF pts[6] = {
        P(13.6f, 2.2f), P(4.8f, 13.4f), P(10.6f, 13.4f),
        P(9.6f, 21.8f), P(19.2f, 10.2f), P(13.2f, 10.2f)
    };
    g.FillPolygon(&br, pts, 6);
}

void IcoServer(Graphics& g, const Pen&, const SolidBrush& br) {
    GraphicsPath p;
    RRect(p, 3.0f, 4.0f, 18.0f, 6.6f, 1.8f);
    g.FillPath(&br, &p);
    RRect(p, 3.0f, 13.4f, 18.0f, 6.6f, 1.8f);
    g.FillPath(&br, &p);
}

void IcoWifi(Graphics& g, const Pen& pen, const SolidBrush& br) {
    g.DrawArc(&pen, 1.4f, 4.6f, 21.2f, 21.2f, 215.0f, 110.0f);
    g.DrawArc(&pen, 5.6f, 8.8f, 12.8f, 12.8f, 215.0f, 110.0f);
    g.DrawArc(&pen, 9.6f, 12.8f, 4.8f, 4.8f, 215.0f, 110.0f);
    g.FillEllipse(&br, 10.6f, 18.4f, 2.8f, 2.8f);
}

void IcoCards(Graphics& g, const Pen& pen, const SolidBrush&) {
    GraphicsPath p;
    RRect(p, 6.4f, 3.2f, 14.4f, 11.0f, 2.2f);
    g.DrawPath(&pen, &p);
    RRect(p, 3.2f, 8.6f, 14.4f, 11.0f, 2.2f);
    g.DrawPath(&pen, &p);
}

void IcoCopy(Graphics& g, const Pen& pen, const SolidBrush&) {
    GraphicsPath p;
    RRect(p, 8.4f, 3.2f, 12.4f, 12.4f, 2.2f);
    g.DrawPath(&pen, &p);
    RRect(p, 3.2f, 8.4f, 12.4f, 12.4f, 2.2f);
    g.DrawPath(&pen, &p);
}

void IcoPlay(Graphics& g, const Pen&, const SolidBrush& br) {
    PointF pts[3] = { P(7.6f, 4.4f), P(19.6f, 12.0f), P(7.6f, 19.6f) };
    g.FillPolygon(&br, pts, 3);
}

void IcoClock(Graphics& g, const Pen& pen, const SolidBrush&) {
    g.DrawEllipse(&pen, 3.2f, 3.2f, 17.6f, 17.6f);
    g.DrawLine(&pen, P(12.0f, 6.8f), P(12.0f, 12.4f));
    g.DrawLine(&pen, P(12.0f, 12.4f), P(15.8f, 14.6f));
}

void IcoLock(Graphics& g, const Pen& pen, const SolidBrush& br) {
    GraphicsPath p;
    RRect(p, 4.4f, 10.4f, 15.2f, 10.0f, 2.4f);
    g.FillPath(&br, &p);
    g.DrawArc(&pen, 7.6f, 3.4f, 8.8f, 11.0f, 180.0f, 180.0f);
}

void IcoClose(Graphics& g, const Pen& pen, const SolidBrush&) {
    g.DrawLine(&pen, P(5.6f, 5.6f), P(18.4f, 18.4f));
    g.DrawLine(&pen, P(18.4f, 5.6f), P(5.6f, 18.4f));
}

void IcoDot(Graphics& g, const Pen&, const SolidBrush& br) {
    g.FillEllipse(&br, 7.6f, 7.6f, 8.8f, 8.8f);
}

void IcoActivity(Graphics& g, const Pen& pen, const SolidBrush&) {
    GraphicsPath p;
    p.StartFigure();
    p.AddLine(P(2.6f, 15.6f), P(7.4f, 15.6f));
    p.AddLine(P(7.4f, 15.6f), P(10.4f, 7.6f));
    p.AddLine(P(10.4f, 7.6f), P(13.6f, 18.4f));
    p.AddLine(P(13.6f, 18.4f), P(16.6f, 11.6f));
    p.AddLine(P(16.6f, 11.6f), P(21.4f, 11.6f));
    g.DrawPath(&pen, &p);
}

void IcoFilter(Graphics& g, const Pen&, const SolidBrush& br) {
    PointF pts[4] = { P(3.0f, 4.4f), P(21.0f, 4.4f),
                      P(13.6f, 12.8f), P(13.6f, 20.4f) };
    GraphicsPath p;
    p.AddPolygon(pts, 3);
    g.FillPath(&br, &p);
}

void IcoChevron(Graphics& g, const Pen& pen, const SolidBrush&) {
    g.DrawLine(&pen, P(7.4f, 10.0f), P(12.0f, 14.6f));
    g.DrawLine(&pen, P(12.0f, 14.6f), P(16.6f, 10.0f));
}

void IcoLogo(Graphics& g, const Pen& pen, const SolidBrush& br) {
    GraphicsPath p;
    p.AddLine(P(12.0f, 2.2f), P(20.4f, 5.6f));
    p.AddLine(P(20.4f, 5.6f), P(20.4f, 12.6f));
    p.AddBezier(P(20.4f, 12.6f), P(20.4f, 17.0f), P(17.2f, 20.6f), P(12.0f, 22.0f));
    p.AddBezier(P(12.0f, 22.0f), P(6.8f, 20.6f), P(3.6f, 17.0f), P(3.6f, 12.6f));
    p.AddLine(P(3.6f, 12.6f), P(3.6f, 5.6f));
    p.CloseFigure();
    g.DrawPath(&pen, &p);

    PointF pts[6] = {
        P(13.2f, 6.6f), P(8.6f, 12.6f), P(11.6f, 12.6f),
        P(10.8f, 17.4f), P(15.4f, 11.2f), P(12.4f, 11.2f)
    };
    g.FillPolygon(&br, pts, 6);
}

struct IcoDef { const wchar_t* name; void (*fn)(Graphics&, const Pen&, const SolidBrush&); };

const IcoDef kIcons[] = {
    { L"dashboard", IcoDashboard },
    { L"key",       IcoKey       },
    { L"plugin",    IcoPlugin    },
    { L"shield",    IcoShield    },
    { L"gear",      IcoGear      },
    { L"plus",      IcoPlus      },
    { L"refresh",   IcoRefresh   },
    { L"search",    IcoSearch    },
    { L"import",    IcoDownload  },
    { L"export",    IcoUpload    },
    { L"trash",     IcoTrash     },
    { L"unlink",    IcoUnlink    },
    { L"note",      IcoNote      },
    { L"check",     IcoCheck     },
    { L"bolt",      IcoBolt      },
    { L"server",    IcoServer    },
    { L"wifi",      IcoWifi      },
    { L"cards",     IcoCards     },
    { L"copy",      IcoCopy      },
    { L"play",      IcoPlay      },
    { L"clock",     IcoClock     },
    { L"lock",      IcoLock      },
    { L"close",     IcoClose     },
    { L"dot",       IcoDot       },
    { L"activity",  IcoActivity  },
    { L"filter",    IcoFilter    },
    { L"chevron",   IcoChevron   },
    { L"logo",      IcoLogo      },
};

const int kIconCount = (int)(sizeof(kIcons) / sizeof(kIcons[0]));

const IcoDef* Find(const wchar_t* name) {
    if (!name) return nullptr;
    for (int i = 0; i < kIconCount; ++i)
        if (std::wcscmp(kIcons[i].name, name) == 0) return &kIcons[i];
    return nullptr;
}

} // namespace

bool HasIcon(const wchar_t* name) { return Find(name) != nullptr; }

void DrawIcon(Graphics& g, const wchar_t* name,
              const RectF& box, Color color, float strokeW) {
    const IcoDef* def = Find(name);
    if (!def) return;
    if (box.Width <= 0.0f || box.Height <= 0.0f) return;

    // 统一缩放到 24 网格；线宽按缩放反向补偿，保证视觉粗细一致
    const float s = (std::min)(box.Width / 24.0f, box.Height / 24.0f);
    if (s <= 0.0f) return;

    GraphicsState st = g.Save();
    g.SetSmoothingMode(SmoothingModeAntiAlias);
    g.SetPixelOffsetMode(PixelOffsetModeHalf);
    const float offX = box.X + (box.Width  - 24.0f * s) * 0.5f;
    const float offY = box.Y + (box.Height - 24.0f * s) * 0.5f;
    g.TranslateTransform(offX, offY);
    g.ScaleTransform(s, s);

    // strokeW 语义是"目标视觉像素线宽"，换算回 24 网格需除以缩放系数
    Pen pen(color, strokeW / s);
    pen.SetLineJoin(LineJoinRound);
    pen.SetStartCap(LineCapRound);
    pen.SetEndCap(LineCapRound);
    SolidBrush br(color);

    def->fn(g, pen, br);

    g.Restore(st);
}

void DrawIcon(Graphics& g, const wchar_t* name,
              int x, int y, int w, int h, Color color, float strokeW) {
    DrawIcon(g, name, RectF((REAL)x, (REAL)y, (REAL)w, (REAL)h), color, strokeW);
}

}} // namespace peanut::ui
