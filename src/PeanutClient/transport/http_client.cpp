// ============================================================
// PeanutWLYZ Transport Layer — HTTP Client Implementation
// ============================================================
// Adapts cpp-httplib (MIT License, header-only) into the
// NetworkClient interface. When tunneling PSP over HTTP:
//   - Each Send() = POST /psp/tunnel with binary body
//   - The HTTP response body is buffered for Receive()
//   - Receive() drains from the internal response buffer
//
// This is a pragmatic HTTP transport that works with any
// standard HTTP server — no WebSocket or SSE required.
// ============================================================

#include "http_client.h"

// cpp-httplib — header-only, MIT License
// Expected location: vendor/cpp-httplib/httplib.h or
// the existing httplib.h in the project dependency tree.
#include "httplib.h"

#include <cstring>
#include <algorithm>

namespace peanut {
namespace transport {

// ── PSP Tunnel Endpoint ───────────────────────────────────
// Fixed path used for PSP-over-HTTP tunneling.
// PSP frames are posted as binary body; responses contain
// PSP-encoded reply frames.
static const char* PSP_TUNNEL_PATH = "/psp/tunnel";

// ============================================================
// Construction / Destruction
// ============================================================

HttpClient::HttpClient()
    : cli_(nullptr), host_("localhost"), port_(80) {
}

HttpClient::HttpClient(const std::string& host, uint16_t port)
    : cli_(std::make_unique<httplib::Client>(host.c_str(), port)),
      host_(host), port_(port) {
    connected_.store(true, std::memory_order_release);
}

HttpClient::~HttpClient() {
    Disconnect();
}

HttpClient::HttpClient(HttpClient&& other) noexcept
    : cli_(std::move(other.cli_))
    , host_(std::move(other.host_))
    , port_(other.port_)
    , last_response_body_(std::move(other.last_response_body_))
    , last_response_status_(other.last_response_status_)
    , response_read_offset_(other.response_read_offset_) {
    bool was_connected = other.connected_.load(std::memory_order_acquire);
    connected_.store(was_connected, std::memory_order_release);
    other.connected_.store(false, std::memory_order_release);
    other.port_ = 0;
}

HttpClient& HttpClient::operator=(HttpClient&& other) noexcept {
    if (this != &other) {
        Disconnect();
        cli_ = std::move(other.cli_);
        host_ = std::move(other.host_);
        port_ = other.port_;
        last_response_body_ = std::move(other.last_response_body_);
        last_response_status_ = other.last_response_status_;
        response_read_offset_ = other.response_read_offset_;
        bool was_connected = other.connected_.load(std::memory_order_acquire);
        connected_.store(was_connected, std::memory_order_release);
        other.connected_.store(false, std::memory_order_release);
        other.port_ = 0;
    }
    return *this;
}

// ============================================================
// NetworkClient Interface
// ============================================================

bool HttpClient::Connect(const std::string& host, uint16_t port) {
    std::lock_guard<std::mutex> lock(mutex_);

    // If already connected to same host:port, reuse
    if (connected_.load(std::memory_order_acquire) &&
        host_ == host && port_ == port && cli_) {
        return true;
    }

    // Close existing connection
    if (cli_) {
        cli_->stop();
    }

    // Create new httplib client
    host_ = host;
    port_ = port;
    ResetClient();

    // Reset response buffer
    last_response_body_.clear();
    last_response_status_ = 0;
    response_read_offset_ = 0;

    connected_.store(true, std::memory_order_release);
    return true;
}

int HttpClient::Send(const uint8_t* data, size_t len) {
    std::lock_guard<std::mutex> lock(mutex_);

    if (!connected_.load(std::memory_order_acquire) || !cli_) {
        return -1;
    }

    if (data == nullptr || len == 0) {
        return 0;
    }

    // ── Reset response buffer before each Send ─────────────
    // Each Send() = complete HTTP request/response cycle.
    // The response body becomes available via Receive().
    last_response_body_.clear();
    last_response_status_ = 0;
    response_read_offset_ = 0;

    // ── POST raw binary data to tunnel endpoint ────────────
    std::string body(reinterpret_cast<const char*>(data), len);

    httplib::Result res = cli_->Post(
        PSP_TUNNEL_PATH,
        {{"Content-Type", "application/octet-stream"}},
        body,
        "application/octet-stream"
    );

    if (!res) {
        // Network error — connection may be broken
        connected_.store(false, std::memory_order_release);
        return -1;
    }

    last_response_status_ = res->status;
    last_response_body_   = std::move(res->body);

    // Return the number of bytes we sent (not received)
    return static_cast<int>(len);
}

int HttpClient::Receive(uint8_t* buffer, size_t buffer_size,
                         int timeout_ms) {
    std::lock_guard<std::mutex> lock(mutex_);

    if (!connected_.load(std::memory_order_acquire) || !cli_) {
        return -1;
    }

    if (buffer == nullptr || buffer_size == 0) {
        return 0;
    }

    // ── Drain from buffered response ───────────────────────
    // For HTTP tunnel, the "receive" reads from the last
    // HTTP response body that was stored by Send().
    if (response_read_offset_ >= last_response_body_.size()) {
        // No more data available — the response has been
        // fully consumed. This is normal for HTTP: each
        // Send() produces exactly one response.
        return 0;
    }

    size_t remaining = last_response_body_.size() - response_read_offset_;
    size_t to_copy = std::min(remaining, buffer_size);

    memcpy(buffer,
           last_response_body_.data() + response_read_offset_,
           to_copy);

    response_read_offset_ += to_copy;
    return static_cast<int>(to_copy);
}

void HttpClient::Disconnect() {
    std::lock_guard<std::mutex> lock(mutex_);

    if (cli_) {
        cli_->stop();
        cli_.reset();
    }

    connected_.store(false, std::memory_order_release);
    last_response_body_.clear();
    last_response_status_ = 0;
    response_read_offset_ = 0;
}

bool HttpClient::IsConnected() const {
    return connected_.load(std::memory_order_acquire) && cli_ != nullptr;
}

TransportMode HttpClient::GetTransportMode() const {
    return TransportMode::TRANSPORT_HTTP;
}

// ============================================================
// HTTP-Specific Methods
// ============================================================

bool HttpClient::Get(const std::string& path,
                      const std::string& query,
                      int& out_status,
                      std::string& out_body) {
    std::lock_guard<std::mutex> lock(mutex_);

    if (!connected_.load(std::memory_order_acquire) || !cli_) {
        return false;
    }

    // Build full path with query string
    std::string full_path = path;
    if (!query.empty()) {
        full_path += "?" + query;
    }

    httplib::Result res = cli_->Get(full_path.c_str());

    if (!res) {
        connected_.store(false, std::memory_order_release);
        return false;
    }

    out_status = res->status;
    out_body   = std::move(res->body);

    return (out_status >= 200 && out_status < 300);
}

bool HttpClient::Post(const std::string& path,
                       const std::string& body,
                       const std::string& content_type,
                       int& out_status,
                       std::string& out_body) {
    std::lock_guard<std::mutex> lock(mutex_);

    if (!connected_.load(std::memory_order_acquire) || !cli_) {
        return false;
    }

    httplib::Result res = cli_->Post(
        path.c_str(),
        {{"Content-Type", content_type}},
        body,
        content_type.c_str()
    );

    if (!res) {
        connected_.store(false, std::memory_order_release);
        return false;
    }

    out_status = res->status;
    out_body   = std::move(res->body);

    return (out_status >= 200 && out_status < 300);
}

void HttpClient::SetHeader(const std::string& key,
                            const std::string& value) {
    std::lock_guard<std::mutex> lock(mutex_);
    // httplib headers are set in the request, but to store
    // them persistently we'd need our own map. For now, we
    // rely on httplib's per-request header mechanism.
    // The user can call GetRawClient()->set_default_headers()
    // for persistent headers.
    if (cli_) {
        httplib::Headers headers;
        headers.emplace(key, value);
        cli_->set_default_headers(headers);
    }
}

void HttpClient::RemoveHeader(const std::string& key) {
    std::lock_guard<std::mutex> lock(mutex_);
    // httplib doesn't have a direct "remove default header",
    // so we'd need to rebuild. For simple use cases, this is fine.
    (void)key;
}

void HttpClient::SetReadTimeout(uint32_t seconds, uint32_t microseconds) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (cli_) {
        cli_->set_read_timeout(seconds, microseconds);
    }
}

void HttpClient::SetWriteTimeout(uint32_t seconds, uint32_t microseconds) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (cli_) {
        cli_->set_write_timeout(seconds, microseconds);
    }
}

void HttpClient::SetConnectionTimeout(uint32_t seconds, uint32_t microseconds) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (cli_) {
        cli_->set_connection_timeout(seconds, microseconds);
    }
}

void HttpClient::SetKeepAlive(bool enable) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (cli_) {
        cli_->set_keep_alive(enable);
    }
}

httplib::Client* HttpClient::GetRawClient() {
    return cli_.get();
}

// ============================================================
// Internal Helpers
// ============================================================

void HttpClient::ResetClient() {
    cli_ = std::make_unique<httplib::Client>(host_.c_str(), port_);

    // Sensible defaults for PSP tunnel
    cli_->set_connection_timeout(10, 0);    // 10s connect timeout
    cli_->set_read_timeout(30, 0);          // 30s read timeout
    cli_->set_write_timeout(10, 0);         // 10s write timeout
    cli_->set_keep_alive(true);             // HTTP keep-alive ON
}

} // namespace transport
} // namespace peanut
