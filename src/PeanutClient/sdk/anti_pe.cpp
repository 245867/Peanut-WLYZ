// ============================================================
// Peanut WLYZ SDK — PE 头运行时自擦除 实现
// ============================================================

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include "anti_pe.h"

#if defined(PEANUT_RELEASE) || defined(VM_PROTECT_ACTIVE)

namespace peanut { namespace security { namespace peguard {

// 安全改写内存
static bool SafeWrite(BYTE* addr, SIZE_T size, const BYTE* data = nullptr) {
    DWORD old;
    if (!VirtualProtect(addr, size, PAGE_READWRITE, &old))
        return false;
    if (data) {
        memcpy(addr, data, size);
    } else {
        SecureZeroMemory(addr, size);
    }
    // 不恢复保护，让 attack surface 保持 RW (反正后面也要读)
    return true;
}

void ErasePEHeaders() {
    HMODULE base = GetModuleHandleW(nullptr);
    if (!base) return;

    // 验证 DOS 签名
    auto* dos = reinterpret_cast<PIMAGE_DOS_HEADER>(base);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return;

    // NT 头
    auto* nt = reinterpret_cast<PIMAGE_NT_HEADERS>(
        reinterpret_cast<BYTE*>(base) + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return;

    DWORD old = 0;

    // ═══ 1. 擦除 DOS 头 (保留 e_lfanew 字段) ═══
    // 做法: 清零 DOS stub，但必须保留 "MZ" 签名和 e_lfanew。
    //
    // 关键约束: 不能抹掉 DOS 头里的 e_magic ("MZ")。Windows 在创建线程时
    // 会调用 RtlImageNtHeader 读取 PE 头里的默认栈大小；一旦 MZ 签名被清掉，
    // RtlImageNtHeader 返回 NULL，此后 CreateThread 会以 ERROR_BAD_EXE_FORMAT
    // (193) 失败，std::thread 则抛异常 —— GUI 的 StartServer() 正是在启动
    // 线程时因此崩溃 (未捕获异常 → 0xC0000409 fail-fast)。
    // 只擦 DOS stub 的非关键字段即可达到隐藏效果，MZ 和 e_lfanew 必须保留。
    WORD saved_lfanew = dos->e_lfanew;
    WORD saved_magic  = dos->e_magic;

    if (SafeWrite(reinterpret_cast<BYTE*>(dos) + 8, 0x3C - 8)) {
        // 擦掉 e_lfanew 之前的 DOS stub 内容 (偏移 8..0x3B)，
        // 但完整保留偏移 0 的 e_magic("MZ") 和偏移 0x3C 的 e_lfanew
        dos->e_magic  = saved_magic;
        dos->e_lfanew = saved_lfanew;
    }

    // ═══ 2. 擦除区段名称 ═══
    auto* sections = IMAGE_FIRST_SECTION(nt);
    WORD numSections = nt->FileHeader.NumberOfSections;
    // 填写随机填充 (不是全 0，避免看起来太规律)
    BYTE randomFill[8];
    DWORD tick = GetTickCount();
    for (int i = 0; i < 8; ++i) {
        randomFill[i] = static_cast<BYTE>((tick + i * 0x7D) & 0xFF);
    }
    for (WORD i = 0; i < numSections; ++i) {
        SafeWrite(reinterpret_cast<BYTE*>(&sections[i].Name), 8, randomFill);
    }

    // ═══ 3. 擦除 Rich Header (在 DOS stub 里，VS 编译器插入) ═══
    // Rich Header 签名: "Rich" + 4字节 XOR key (offset DOS header 后 0x80 开始查找)
    // 起始位置: DOS header 后 +0x80，搜索 "Rich"
    BYTE* richSearch = reinterpret_cast<BYTE*>(dos) + 0x80;
    BYTE* richEnd    = reinterpret_cast<BYTE*>(nt);  // 不要碰 NT 头
    for (BYTE* p = richSearch; p < richEnd - 3; ++p) {
        if (p[0] == 'R' && p[1] == 'i' && p[2] == 'c' && p[3] == 'h') {
            // 擦除 "Rich" 签名 → Rich Header 解析失败
            SafeWrite(p, 4);
            // 顺便擦除 XOR key (紧随其后的 4 字节)
            SafeWrite(p + 4, 4);
            break;  // 只有一个 Rich Header
        }
    }

    // ═══ 4. 擦除 Debug Directory ═══
    auto& debugDir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG];
    if (debugDir.Size > 0 && debugDir.VirtualAddress > 0) {
        BYTE* debugData = reinterpret_cast<BYTE*>(base) + debugDir.VirtualAddress;
        // 逐个 IMAGE_DEBUG_DIRECTORY 擦除
        DWORD count = debugDir.Size / sizeof(IMAGE_DEBUG_DIRECTORY);
        for (DWORD i = 0; i < count; ++i) {
            auto* dd = reinterpret_cast<PIMAGE_DEBUG_DIRECTORY>(debugData) + i;
            if (dd->AddressOfRawData > 0 && dd->SizeOfData > 0) {
                // 擦除调试数据 (PDB 路径、CV 记录等)
                BYTE* data = reinterpret_cast<BYTE*>(base) + dd->AddressOfRawData;
                SIZE_T sz = dd->SizeOfData;
                if (sz < 0x10000) {  // 安全检查: 不大可能超过 64KB
                    SafeWrite(data, sz);
                }
            }
            // 擦除目录条目自身
            SafeWrite(reinterpret_cast<BYTE*>(dd), sizeof(IMAGE_DEBUG_DIRECTORY));
        }
        // 擦 Directory 入口
        debugDir.Size = 0;
        debugDir.VirtualAddress = 0;
    }

    // ═══ 5. 擦除 TLS 目录 (避免暴露 TLS callback 地址) ═══
    auto& tlsDir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
    if (tlsDir.Size > 0 && tlsDir.VirtualAddress > 0) {
        auto* tls = reinterpret_cast<PIMAGE_TLS_DIRECTORY>(
            reinterpret_cast<BYTE*>(base) + tlsDir.VirtualAddress);
        // 擦除 Callback 数组指针
        SafeWrite(reinterpret_cast<BYTE*>(&tls->AddressOfCallBacks), sizeof(ULONGLONG));
        tlsDir.Size = 0;
        tlsDir.VirtualAddress = 0;
    }
}

}}} // namespace

#endif
