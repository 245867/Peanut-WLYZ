// ============================================================
// PeanutWLYZ Transport Layer — TCP Client (IOCP)
// ============================================================
// Professional-grade TCP transport using Windows I/O Completion
// Ports (IOCP) — the same pattern used by IIS, SQL Server,
// and Exchange.
//
// Design goals:
//   - Zero extra DLLs: kernel32.dll + ws2_32.dll only
//     (both are system DLLs every Win32 PE links against)
//   - Non-blocking async I/O via IOCP
//   - Connection pooling ready (socket handle can be reused)
//   - Nagle's algorithm disabled for minimal latency
//   - Thread-safe close with proper cleanup ordering
//
// Binary characteristics:
//   - Creates an IOCP handle via CreateIoCompletionPort
//   - Uses WSASend/WSARecv with overlapped I/O
//   - Standard WinSock2 calls — indistinguishable from any
//     other Win32 socket code under static analysis
// ============================================================

#pragma once

#include "network_client.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

// winsock2.h MUST precede windows.h to avoid winsock.h collision
#include <winsock2.h>
#include <ws2tcpip.h>
#include <mswsock.h>
#include <windows.h>

#include <string>
#include <atomic>
#include <mutex>
#include <cstdint>

namespace peanut {
namespace transport {

// ── TCP Client with IOCP ──────────────────────────────────
// Implements NetworkClient using raw TCP sockets with IOCP
// for efficient async I/O. Thread-safe.
class TcpClient final : public NetworkClient {
public:
    // ── Construction / Destruction ─────────────────────────
    TcpClient();
    ~TcpClient() override;

    // Non-copyable, non-movable (owns system handles)
    TcpClient(const TcpClient&) = delete;
    TcpClient& operator=(const TcpClient&) = delete;
    TcpClient(TcpClient&&) = delete;
    TcpClient& operator=(TcpClient&&) = delete;

    // ── NetworkClient Interface ────────────────────────────
    bool Connect(const std::string& host, uint16_t port) override;
    int  Send(const uint8_t* data, size_t len) override;
    int  Receive(uint8_t* buffer, size_t buffer_size,
                 int timeout_ms) override;
    void Disconnect() override;
    bool IsConnected() const override;
    TransportMode GetTransportMode() const override;

    // ── TCP-Specific Configuration ─────────────────────────
    // Set socket option before Connect().
    // @param timeout_ms  Connect timeout in milliseconds.
    void SetConnectTimeout(uint32_t timeout_ms);

    // @param timeout_ms  Send timeout in milliseconds.
    void SetSendTimeout(uint32_t timeout_ms);

    // @param timeout_ms  Receive timeout in milliseconds.
    void SetReceiveTimeout(uint32_t timeout_ms);

    // @param enable  Enable/disable Nagle's algorithm.
    //                Disabled by default for low latency.
    void SetNoDelay(bool enable);

    // @param size  Send buffer size (SO_SNDBUF).
    void SetSendBufferSize(int size);

    // @param size  Receive buffer size (SO_RCVBUF).
    void SetReceiveBufferSize(int size);

private:
    // ── WSA Lifecycle ──────────────────────────────────────
    // WSAStartup is reference-counted; safe to call from
    // multiple TcpClient instances.
    static bool InitializeWSA();
    static void CleanupWSA();
    static std::atomic<int> s_wsa_ref_count_;
    static std::mutex s_wsa_mutex_;

    // ── IOCP Overlapped Context ────────────────────────────
    // Extended OVERLAPPED for I/O completion identification.
    enum class IoOperation : uint8_t {
        OP_SEND    = 1,
        OP_RECV    = 2,
        OP_CONNECT = 3
    };

    struct IoContext : public OVERLAPPED {
        IoOperation    op_code;
        WSABUF         wsa_buf;
        uint8_t*       user_buffer;    // Original user buffer (for OP_RECV)
        bool           completed;

        IoContext() : op_code(static_cast<IoOperation>(0)),
                      user_buffer(nullptr), completed(false) {
            memset(static_cast<OVERLAPPED*>(this), 0, sizeof(OVERLAPPED));
        }
    };

    // ── Internal Helpers ───────────────────────────────────
    bool CreateSocket();
    bool BindIocp();
    bool ConnectNonBlocking(const sockaddr* addr, int addr_len);
    bool WaitForConnectCompletion(uint32_t timeout_ms);
    int  WaitForCompletion(IoContext* ctx, uint32_t timeout_ms);
    void CleanupSocket();
    int  GetLastWsaError() const;

    // ── Per-Connection State ───────────────────────────────
    SOCKET          socket_ = INVALID_SOCKET;
    HANDLE          iocp_   = nullptr;    // I/O Completion Port handle

    std::atomic<bool> connected_{false};

    // ── Configuration ──────────────────────────────────────
    uint32_t connect_timeout_ms_ = 10000;   // Default: 10s
    uint32_t send_timeout_ms_    = 5000;    // Default: 5s
    uint32_t recv_timeout_ms_    = 30000;   // Default: 30s
    bool     no_delay_           = true;    // Nagle off by default
    int      send_buf_size_      = 65536;   // 64KB
    int      recv_buf_size_      = 65536;   // 64KB

    // ── Thread Safety ──────────────────────────────────────
    // Protects socket_ creation/close and iocp_ operations.
    // I/O operations themselves are thread-safe via IOCP.
    mutable std::mutex state_mutex_;
};

} // namespace transport
} // namespace peanut
