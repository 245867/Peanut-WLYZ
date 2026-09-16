// ============================================================
// Peanut WLYZ SDK — 控制流混淆原语
// 对非 VMP 标记路径做手动混淆
// 提供: 不透明谓词 / 垃圾指令 / 控制流平坦化辅助
// ============================================================

#pragma once

#if defined(PEANUT_RELEASE) || defined(VM_PROTECT_ACTIVE)

#include <windows.h>
#include <intrin.h>

// ═══════════════════════════════════════════════════════════
//  垃圾指令 — 编译器不会优化掉 (volatile + __rdtsc)
// ═══════════════════════════════════════════════════════════

#define FLOW_JUNK_1() do { volatile int _j = (int)(__rdtsc() & 0xFF); (void)_j; } while(0)
#define FLOW_JUNK_2() do { volatile DWORD _j1 = (DWORD)(__rdtsc() & 0xFFFF); volatile DWORD _j2 = _j1 ^ 0xDEAD; (void)_j1; (void)_j2; } while(0)
#define FLOW_JUNK_3() do { volatile ULONGLONG _j = __rdtsc(); _j = (_j * 0xA5A5A5A5) ^ 0x5A5A5A5A; (void)_j; } while(0)

// ═══════════════════════════════════════════════════════════
//  不透明谓词 — 永远为真/假的复杂条件
// ═══════════════════════════════════════════════════════════

// 永远为真: 两个连续整数的积永远是偶数 → (x*(x+1))%2 == 0
// 编译器无法优化掉因为 x 来自 volatile/runtime
#define OPAQUE_TRUE  ([]() -> bool { volatile DWORD _x = (DWORD)(__rdtsc() & 0xFFF); return ((_x * (_x + 1)) % 2) == 0; }())

// 永远为假: (x+1)*(x+2)%2 == 0 也是永远为真 → 取反
#define OPAQUE_FALSE ([]() -> bool { volatile DWORD _x = (DWORD)(__rdtsc() & 0xFFF); return ((_x * (_x + 1)) % 2) != 0; }())

// ═══════════════════════════════════════════════════════════
//  控制流分叉 (multiplex) — 多个入口 → 同一出口
//  攻击者需要分别分析每条路径
// ═══════════════════════════════════════════════════════════

// 用法:
//   int result;
//   FLOW_MULTIPLEX_3(result,
//       path_0_code,
//       path_1_code,
//       path_2_code
//   );
//  → 三条路径做同样的事, 但写法略有不同

// ═══════════════════════════════════════════════════════════
//  随机延迟 (反时序攻击) — 插入不可预测的延迟
// ═══════════════════════════════════════════════════════════

inline void FlowRandomDelay() {
    volatile int _d = (int)(__rdtsc() & 0x1F);  // 0-31
    for (volatile int _i = 0; _i < _d; ++_i) {
        __nop();
    }
}

// ═══════════════════════════════════════════════════════════
//  switch-case 展开宏 (控制流平坦化)
// ═══════════════════════════════════════════════════════════

// 将 if-else 转为 switch-case 状态机:
//
//   int state = init_state();
//   while (state != STATE_EXIT) {
//       switch (state) {
//           case STATE_0: ...; state = next0; break;
//           case STATE_1: ...; state = next1; break;
//       }
//   }
//
// 每个 case 可以插入 FLOW_JUNK_*() 增强混淆

#define FLOW_STATE_BEGIN(var, init) \
    int var = (init); \
    while ((var) != -1) { \
        switch (var) {

#define FLOW_STATE_CASE(s, body) \
            case (s): do { body } while(0); break;

#define FLOW_STATE_END() \
            default: var = -1; break; \
        } \
    }

#else  // Debug: 空实现
#define FLOW_JUNK_1()      ((void)0)
#define FLOW_JUNK_2()      ((void)0)
#define FLOW_JUNK_3()      ((void)0)
#define OPAQUE_TRUE        (true)
#define OPAQUE_FALSE       (false)
#define FLOW_STATE_BEGIN(var, init) if (true)
#define FLOW_STATE_CASE(s, body) body
#define FLOW_STATE_END()   else {}
inline void FlowRandomDelay() {}
#endif
