// ============================================================
// PeanutWLYZ Transport Layer — Base Network Client
// ============================================================
// Abstract interface for all transport backends.
// PeanutSecure Protocol (PSP) wraps on top of this layer.
// ============================================================

#pragma once

#include <cstdint>
#include <cstddef>
#include <string>

namespace peanut {
namespace transport {

// ── Transport Mode Enum ───────────────────────────────────
// Determines which backend is created by TransportFactory.
enum class TransportMode : uint8_t {
    TRANSPORT_HTTP  = 0x00,   // cpp-httplib based HTTP transport
    TRANSPORT_TCP   = 0x01    // Raw TCP with IOCP (Win32, no extra DLLs)
};

// ── Abstract Network Client Interface ─────────────────────
// All transport implementations inherit from this.
// Designed for PSP protocol wrapping — provides raw byte
// send/receive that PSP encodes/decodes on top.
class NetworkClient {
public:
    virtual ~NetworkClient() = default;

    // ── Connection ─────────────────────────────────────────
    // Establish a connection to the remote endpoint.
    // @param host  Remote hostname or IP address
    // @param port  Remote port number (1-65535)
    // @return true if connected, false on failure
    virtual bool Connect(const std::string& host, uint16_t port) = 0;

    // ── Send Data ──────────────────────────────────────────
    // Send raw bytes to the connected peer.
    // @param data  Pointer to buffer to send
    // @param len   Number of bytes to send
    // @return Number of bytes actually sent, or -1 on error
    virtual int Send(const uint8_t* data, size_t len) = 0;

    // ── Receive Data ───────────────────────────────────────
    // Receive raw bytes from the connected peer.
    // @param timeout_ms  Maximum time to wait for data (ms).
    //                    0 = non-blocking poll, -1 = block forever
    // @return Number of bytes received, or -1 on error/closed
    virtual int Receive(uint8_t* buffer, size_t buffer_size,
                        int timeout_ms) = 0;

    // ── Disconnect ─────────────────────────────────────────
    // Gracefully close the connection.
    virtual void Disconnect() = 0;

    // ── Connection State ───────────────────────────────────
    // @return true if a connection is currently established
    virtual bool IsConnected() const = 0;

    // ── Transport Identification ───────────────────────────
    // @return The transport mode this client implements
    virtual TransportMode GetTransportMode() const = 0;
};

} // namespace transport
} // namespace peanut
