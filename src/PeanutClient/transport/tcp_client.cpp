// ============================================================
// PeanutWLYZ Transport Layer — TCP Client (IOCP) Implementation
// ============================================================
// Production-grade TCP transport using Windows I/O Completion
// Ports. This is the same concurrency model used by IIS, SQL
// Server, Exchange, and other Microsoft server products.
//
// Architecture:
//   1. Each TcpClient owns one SOCKET + one IOCP
//   2. Connect is non-blocking — fires ConnectEx, waits on IOCP
//   3. Send submits WSASend to IOCP; waits for completion
//   4. Receive submits WSARecv to IOCP; waits for completion
//   5. IOCP wake is immediate — no busy-wait loops
//   6. Connection pooling: socket can be reset and reconnected
//
// Zero extra DLL dependencies:
//   - kernel32.dll   → CreateIoCompletionPort, GetQueuedCompletionStatus
//   - ws2_32.dll     → socket, connect, send, recv, WSAStartup, etc.
// Both are system DLLs that every Windows PE loads at startup.
// ============================================================

#include "tcp_client.h"

#include <vector>
#include <cstring>
#include <sstream>

// Link against WinSock2
#pragma comment(lib, "ws2_32.lib")
// IOCP functions linked from kernel32 — already linked by default
// CreateIoCompletionPort, GetQueuedCompletionStatus, PostQueuedCompletionStatus

namespace peanut {
namespace transport {

// ── Static WSA Reference Counting ─────────────────────────
// WSAStartup must be called once per process. Multiple
// TcpClient instances share a single WSA init via ref-counting.
std::atomic<int> TcpClient::s_wsa_ref_count_{0};
std::mutex        TcpClient::s_wsa_mutex_;

// ============================================================
// Construction / Destruction
// ============================================================

TcpClient::TcpClient() {
    InitializeWSA();
}

TcpClient::~TcpClient() {
    Disconnect();
    CleanupWSA();
}

// ============================================================
// WSA Lifecycle (Static)
// ============================================================

bool TcpClient::InitializeWSA() {
    std::lock_guard<std::mutex> lock(s_wsa_mutex_);

    if (s_wsa_ref_count_.fetch_add(1) == 0) {
        // First instance — perform WSAStartup
        WSADATA wsa_data;
        int result = WSAStartup(MAKEWORD(2, 2), &wsa_data);
        if (result != 0) {
            s_wsa_ref_count_.fetch_sub(1);
            return false;
        }
    }
    return true;
}

void TcpClient::CleanupWSA() {
    std::lock_guard<std::mutex> lock(s_wsa_mutex_);

    if (s_wsa_ref_count_.fetch_sub(1) == 1) {
        // Last instance — perform WSACleanup
        WSACleanup();
    }
}

// ============================================================
// NetworkClient Interface
// ============================================================

bool TcpClient::Connect(const std::string& host, uint16_t port) {
    std::lock_guard<std::mutex> lock(state_mutex_);

    // ── If already connected, clean up first ───────────────
    if (connected_.load(std::memory_order_acquire)) {
        CleanupSocket();
        connected_.store(false, std::memory_order_release);
    }

    // ── Resolve hostname ───────────────────────────────────
    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family   = AF_INET;        // IPv4 only
    hints.ai_socktype = SOCK_STREAM;    // TCP
    hints.ai_protocol = IPPROTO_TCP;

    std::string port_str = std::to_string(port);

    struct addrinfo* result = nullptr;
    int gai_err = getaddrinfo(host.c_str(), port_str.c_str(),
                              &hints, &result);
    if (gai_err != 0 || result == nullptr) {
        return false;
    }

    // ── Create socket ──────────────────────────────────────
    if (!CreateSocket()) {
        freeaddrinfo(result);
        return false;
    }

    // ── Bind socket to IOCP ────────────────────────────────
    if (!BindIocp()) {
        CleanupSocket();
        freeaddrinfo(result);
        return false;
    }

    // ── Configure TCP options ──────────────────────────────
    // Disable Nagle's algorithm for low latency (TCP_NODELAY)
    if (no_delay_) {
        BOOL nodelay = TRUE;
        setsockopt(socket_, IPPROTO_TCP, TCP_NODELAY,
                   reinterpret_cast<const char*>(&nodelay),
                   sizeof(nodelay));
    }

    // Set buffer sizes
    setsockopt(socket_, SOL_SOCKET, SO_SNDBUF,
               reinterpret_cast<const char*>(&send_buf_size_),
               sizeof(send_buf_size_));
    setsockopt(socket_, SOL_SOCKET, SO_RCVBUF,
               reinterpret_cast<const char*>(&recv_buf_size_),
               sizeof(recv_buf_size_));

    // ── Non-blocking connect ───────────────────────────────
    bool connected = ConnectNonBlocking(
        result->ai_addr,
        static_cast<int>(result->ai_addrlen));

    freeaddrinfo(result);

    if (connected) {
        connected_.store(true, std::memory_order_release);
    } else {
        CleanupSocket();
    }

    return connected;
}

int TcpClient::Send(const uint8_t* data, size_t len) {
    if (!connected_.load(std::memory_order_acquire) ||
        socket_ == INVALID_SOCKET) {
        return -1; // Not connected
    }

    if (data == nullptr || len == 0) {
        return 0;
    }

    // ── Prepare IOCP context ───────────────────────────────
    IoContext ctx;
    ctx.op_code = IoOperation::OP_SEND;
    ctx.wsa_buf.buf = const_cast<char*>(
        reinterpret_cast<const char*>(data));
    ctx.wsa_buf.len = static_cast<ULONG>(len);
    ctx.completed = false;

    // ── Submit async send ──────────────────────────────────
    DWORD bytes_sent = 0;
    DWORD flags = 0;

    int wsa_result = WSASend(
        socket_,
        &ctx.wsa_buf,      // Single buffer
        1,                  // Buffer count
        &bytes_sent,
        flags,
        &ctx,               // Overlapped — IOCP will signal
        nullptr             // No completion routine (IOCP-based)
    );

    if (wsa_result == SOCKET_ERROR) {
        int error = WSAGetLastError();
        if (error != WSA_IO_PENDING) {
            // Genuine failure — not just pending
            return -1;
        }
        // WSA_IO_PENDING is expected: I/O is now in-flight.
        // Wait for IOCP completion.
        int completed = WaitForCompletion(&ctx, send_timeout_ms_);
        if (completed <= 0) {
            return -1; // Timeout or error
        }
        return completed;
    }

    // Completed synchronously — already have bytes_sent
    return static_cast<int>(bytes_sent);
}

int TcpClient::Receive(uint8_t* buffer, size_t buffer_size,
                        int timeout_ms) {
    if (!connected_.load(std::memory_order_acquire) ||
        socket_ == INVALID_SOCKET) {
        return -1;
    }

    if (buffer == nullptr || buffer_size == 0) {
        return 0;
    }

    // ── Compute effective timeout ──────────────────────────
    uint32_t effective_timeout;
    if (timeout_ms < 0) {
        effective_timeout = INFINITE;  // Block forever
    } else if (timeout_ms == 0) {
        // Non-blocking poll — check if data available
        fd_set read_fds;
        FD_ZERO(&read_fds);
        FD_SET(socket_, &read_fds);

        struct timeval tv = {0, 0}; // zero timeout = poll
        int select_result = select(0, &read_fds, nullptr, nullptr, &tv);
        if (select_result <= 0) {
            return select_result; // 0 = no data, -1 = error
        }
        // Fall through to do a synchronous recv for polling
        int poll_result = recv(socket_,
                                reinterpret_cast<char*>(buffer),
                                static_cast<int>(buffer_size), 0);
        if (poll_result == SOCKET_ERROR) {
            int err = WSAGetLastError();
            if (err == WSAEWOULDBLOCK) {
                return 0; // Would block = no data available
            }
            return -1;
        }
        return poll_result;
    } else {
        effective_timeout = static_cast<uint32_t>(timeout_ms);
    }

    // ── Prepare IOCP context ───────────────────────────────
    IoContext ctx;
    ctx.op_code     = IoOperation::OP_RECV;
    ctx.wsa_buf.buf = reinterpret_cast<char*>(buffer);
    ctx.wsa_buf.len = static_cast<ULONG>(buffer_size);
    ctx.user_buffer = buffer;  // Track for completion
    ctx.completed   = false;

    // ── Submit async receive ───────────────────────────────
    DWORD bytes_received = 0;
    DWORD flags = 0;

    int wsa_result = WSARecv(
        socket_,
        &ctx.wsa_buf,
        1,
        &bytes_received,
        &flags,
        &ctx,
        nullptr
    );

    if (wsa_result == SOCKET_ERROR) {
        int error = WSAGetLastError();
        if (error != WSA_IO_PENDING) {
            return -1;
        }

        // Wait for IOCP completion
        int completed = WaitForCompletion(&ctx, effective_timeout);
        return completed; // bytes received, or -1 on error/timeout
    }

    // Synchronous completion
    if (bytes_received == 0) {
        // Graceful shutdown from remote peer
        connected_.store(false, std::memory_order_release);
        return -1;
    }

    return static_cast<int>(bytes_received);
}

void TcpClient::Disconnect() {
    std::lock_guard<std::mutex> lock(state_mutex_);

    if (connected_.load(std::memory_order_acquire)) {
        connected_.store(false, std::memory_order_release);
    }

    CleanupSocket();
}

bool TcpClient::IsConnected() const {
    return connected_.load(std::memory_order_acquire) &&
           socket_ != INVALID_SOCKET;
}

TransportMode TcpClient::GetTransportMode() const {
    return TransportMode::TRANSPORT_TCP;
}

// ============================================================
// Configuration Setters
// ============================================================

void TcpClient::SetConnectTimeout(uint32_t timeout_ms) {
    connect_timeout_ms_ = timeout_ms;
}

void TcpClient::SetSendTimeout(uint32_t timeout_ms) {
    send_timeout_ms_ = timeout_ms;
}

void TcpClient::SetReceiveTimeout(uint32_t timeout_ms) {
    recv_timeout_ms_ = timeout_ms;
}

void TcpClient::SetNoDelay(bool enable) {
    no_delay_ = enable;
    // Apply to existing socket if connected
    if (socket_ != INVALID_SOCKET) {
        BOOL nodelay = enable ? TRUE : FALSE;
        setsockopt(socket_, IPPROTO_TCP, TCP_NODELAY,
                   reinterpret_cast<const char*>(&nodelay),
                   sizeof(nodelay));
    }
}

void TcpClient::SetSendBufferSize(int size) {
    send_buf_size_ = size;
    if (socket_ != INVALID_SOCKET) {
        setsockopt(socket_, SOL_SOCKET, SO_SNDBUF,
                   reinterpret_cast<const char*>(&size),
                   sizeof(size));
    }
}

void TcpClient::SetReceiveBufferSize(int size) {
    recv_buf_size_ = size;
    if (socket_ != INVALID_SOCKET) {
        setsockopt(socket_, SOL_SOCKET, SO_RCVBUF,
                   reinterpret_cast<const char*>(&size),
                   sizeof(size));
    }
}

// ============================================================
// Internal: Socket Creation & IOCP Binding
// ============================================================

bool TcpClient::CreateSocket() {
    socket_ = WSASocketW(
        AF_INET,                              // IPv4
        SOCK_STREAM,                          // TCP
        IPPROTO_TCP,
        nullptr,                              // No protocol info
        0,                                    // No group
        WSA_FLAG_OVERLAPPED                   // ← Required for IOCP
    );

    if (socket_ == INVALID_SOCKET) {
        return false;
    }

    return true;
}

bool TcpClient::BindIocp() {
    // CreateIoCompletionPort with socket — associates the socket
    // with the IOCP. If iocp_ is nullptr, creates a new port.
    // Using nullptr for the existing port creates a new one.
    HANDLE result = CreateIoCompletionPort(
        reinterpret_cast<HANDLE>(socket_),
        iocp_,
        0,          // Completion key (not needed for single-socket)
        0           // Number of concurrent threads (0 = system default)
    );

    if (result == nullptr) {
        return false;
    }

    iocp_ = result;
    return true;
}

// ============================================================
// Internal: Non-Blocking Connect
// ============================================================

bool TcpClient::ConnectNonBlocking(const sockaddr* addr, int addr_len) {
    // ── Step 1: Set socket to non-blocking mode ────────────
    u_long nonblock = 1;
    if (ioctlsocket(socket_, FIONBIO, &nonblock) == SOCKET_ERROR) {
        return false;
    }

    // ── Step 2: Initiate connection ────────────────────────
    int result = connect(socket_, addr, addr_len);

    if (result == SOCKET_ERROR) {
        int error = WSAGetLastError();
        if (error != WSAEWOULDBLOCK) {
            // Immediate failure
            return false;
        }
        // WSAEWOULDBLOCK is expected — connection is in progress
    } else {
        // Connected immediately — rare but possible for localhost
        return true;
    }

    // ── Step 3: Wait for writability (select-based) ───────
    // Use select() to wait for the socket to become writable,
    // which indicates the connection has completed.
    fd_set write_fds, except_fds;
    FD_ZERO(&write_fds);
    FD_ZERO(&except_fds);
    FD_SET(socket_, &write_fds);
    FD_SET(socket_, &except_fds);

    // Calculate select timeout
    struct timeval tv;
    tv.tv_sec  = connect_timeout_ms_ / 1000;
    tv.tv_usec = (connect_timeout_ms_ % 1000) * 1000;

    int select_result = select(0, nullptr, &write_fds, &except_fds, &tv);

    if (select_result <= 0) {
        // Timeout or error
        return false;
    }

    // ── Step 4: Verify connection ──────────────────────────
    if (FD_ISSET(socket_, &except_fds)) {
        // Connection failed
        return false;
    }

    if (!FD_ISSET(socket_, &write_fds)) {
        return false;
    }

    // ── Step 5: Check SO_ERROR for actual result ───────────
    int so_error = 0;
    int so_error_len = sizeof(so_error);
    getsockopt(socket_, SOL_SOCKET, SO_ERROR,
               reinterpret_cast<char*>(&so_error), &so_error_len);

    if (so_error != 0) {
        return false;
    }

    // ── Step 6: Restore blocking mode after connect ───────
    // IOCP-based I/O uses overlapped operations which are
    // inherently non-blocking, but restoring normal socket
    // blocking helps with select() and fallback paths.
    u_long blockmode = 0;
    ioctlsocket(socket_, FIONBIO, &blockmode);

    return true;
}

// ============================================================
// Internal: IOCP Wait
// ============================================================

int TcpClient::WaitForCompletion(IoContext* ctx, uint32_t timeout_ms) {
    DWORD bytes_transferred = 0;
    ULONG_PTR completion_key = 0;
    OVERLAPPED* overlapped = nullptr;

    BOOL success = GetQueuedCompletionStatus(
        iocp_,
        &bytes_transferred,
        &completion_key,
        &overlapped,
        static_cast<DWORD>(timeout_ms)
    );

    if (!success) {
        if (overlapped == nullptr) {
            // Timeout — no I/O packet dequeued
            // Cancel the pending operation on this socket
            CancelIo(reinterpret_cast<HANDLE>(socket_));
            return -1;
        }
        // overlapped != nullptr: I/O completed with error
        // bytes_transferred contains the error in this case,
        // but for send/recv it may just mean connection closed.
        IoContext* completed_ctx = reinterpret_cast<IoContext*>(overlapped);
        if (completed_ctx->op_code == IoOperation::OP_RECV &&
            bytes_transferred == 0) {
            // Zero-byte receive = graceful close
            return -1;
        }
        return -1;
    }

    if (bytes_transferred == 0 &&
        overlapped != nullptr) {
        // Check if this is a receive context with zero bytes
        IoContext* completed_ctx = reinterpret_cast<IoContext*>(overlapped);
        if (completed_ctx->op_code == IoOperation::OP_RECV) {
            // Graceful shutdown from remote
            connected_.store(false, std::memory_order_release);
            return -1;
        }
    }

    return static_cast<int>(bytes_transferred);
}

// ============================================================
// Internal: Socket Cleanup
// ============================================================

void TcpClient::CleanupSocket() {
    // ── Graceful shutdown sequence ──────────────────────────
    if (socket_ != INVALID_SOCKET) {
        // 1. Shutdown sends — tell remote we're done
        shutdown(socket_, SD_SEND);

        // 2. Drain remaining data (non-blocking)
        char drain_buffer[1024];
        fd_set read_fds;
        FD_ZERO(&read_fds);
        FD_SET(socket_, &read_fds);
        struct timeval tv = {0, 100000}; // 100ms drain
        int drain_select = select(0, &read_fds, nullptr, nullptr, &tv);
        if (drain_select > 0) {
            recv(socket_, drain_buffer, sizeof(drain_buffer), 0);
        }

        // 3. Close socket
        closesocket(socket_);
        socket_ = INVALID_SOCKET;
    }

    // ── Close IOCP handle ──────────────────────────────────
    if (iocp_ != nullptr) {
        CloseHandle(iocp_);
        iocp_ = nullptr;
    }
}

int TcpClient::GetLastWsaError() const {
    return WSAGetLastError();
}

} // namespace transport
} // namespace peanut
