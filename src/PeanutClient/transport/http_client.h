// ============================================================
// PeanutWLYZ Transport Layer — HTTP Client
// ============================================================
// Wraps cpp-httplib (header-only, MIT License) into the
// NetworkClient interface for PSP protocol transport over HTTP.
//
// This adapter design allows PSP frames to be tunneled over
// HTTP as well as raw TCP, providing transport flexibility
// while keeping the same upper-layer protocol code.
// ============================================================

#pragma once

#include "network_client.h"

#include <string>
#include <memory>
#include <atomic>
#include <mutex>
#include <cstdint>

// Forward-declare httplib types to avoid including the
// heavy header in this file. The implementation file
// includes httplib.h directly.
namespace httplib {
    class Client;
    struct Result;
    struct Response;
}

namespace peanut {
namespace transport {

// ── HTTP Client Transport ─────────────────────────────────
// Adapts httplib::Client to the NetworkClient interface.
// PSP frames are sent as POST body; received as response body.
//
// HTTP-specific features:
//   - GET with query parameters
//   - Custom headers
//   - Base URL management
//   - Connection keep-alive via httplib built-in
class HttpClient final : public NetworkClient {
public:
    // ── Construction / Destruction ─────────────────────────
    HttpClient();
    explicit HttpClient(const std::string& host, uint16_t port);
    ~HttpClient() override;

    // Non-copyable, movable
    HttpClient(const HttpClient&) = delete;
    HttpClient& operator=(const HttpClient&) = delete;
    HttpClient(HttpClient&&) noexcept;
    HttpClient& operator=(HttpClient&&) noexcept;

    // ── NetworkClient Interface ────────────────────────────
    // Connect initializes the httplib::Client with host:port.
    // For HTTP, the "connection" is virtual — the underlying
    // library manages keep-alive connections automatically.
    bool Connect(const std::string& host, uint16_t port) override;
    int  Send(const uint8_t* data, size_t len) override;
    int  Receive(uint8_t* buffer, size_t buffer_size,
                 int timeout_ms) override;
    void Disconnect() override;
    bool IsConnected() const override;
    TransportMode GetTransportMode() const override;

    // ── HTTP-Specific Methods ──────────────────────────────
    // Perform an HTTP GET request.
    // @param path       Request path, e.g. "/api/config"
    // @param query      Query string (without '?'), e.g. "data=xxx"
    // @param out_status Output HTTP status code
    // @param out_body   Output response body
    // @return true if HTTP request succeeded (2xx status)
    bool Get(const std::string& path,
             const std::string& query,
             int& out_status,
             std::string& out_body);

    // Perform an HTTP POST request with raw body.
    // @param path       Request path
    // @param body       POST body (binary safe)
    // @param content_type Content-Type header value
    // @param out_status Output HTTP status code
    // @param out_body   Output response body
    // @return true if HTTP request succeeded (2xx status)
    bool Post(const std::string& path,
              const std::string& body,
              const std::string& content_type,
              int& out_status,
              std::string& out_body);

    // Set a custom HTTP header applied to all requests.
    void SetHeader(const std::string& key, const std::string& value);

    // Remove a custom header.
    void RemoveHeader(const std::string& key);

    // Set read/write timeout for the underlying httplib client.
    void SetReadTimeout(uint32_t seconds, uint32_t microseconds = 0);
    void SetWriteTimeout(uint32_t seconds, uint32_t microseconds = 0);

    // Set connection timeout.
    void SetConnectionTimeout(uint32_t seconds, uint32_t microseconds = 0);

    // Enable/disable HTTP keep-alive (enabled by default).
    void SetKeepAlive(bool enable);

    // Get the underlying httplib::Client for advanced usage.
    // Use with caution — bypasses the NetworkClient interface.
    httplib::Client* GetRawClient();

private:
    // ── Internal Helpers ───────────────────────────────────
    void ResetClient();

    // ── State ──────────────────────────────────────────────
    std::unique_ptr<httplib::Client> cli_;
    std::string host_;
    uint16_t    port_ = 0;
    std::atomic<bool> connected_{false};
    mutable std::mutex mutex_;

    // ── PSP Tunnel State ───────────────────────────────────
    // When tunneling PSP over HTTP, Send() posts to a fixed
    // endpoint and Receive() is a no-op (response comes back
    // synchronously with Send). This tracks the last response.
    std::string last_response_body_;
    int         last_response_status_ = 0;
    size_t      response_read_offset_ = 0;
};

} // namespace transport
} // namespace peanut
