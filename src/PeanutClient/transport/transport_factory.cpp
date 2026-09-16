// ============================================================
// PeanutWLYZ Transport Layer — Transport Factory Implementation
// ============================================================

#include "transport_factory.h"
#include "tcp_client.h"
#include "http_client.h"

#include <cstring>
#include <algorithm>
#include <cctype>

namespace peanut {
namespace transport {

// ============================================================
// Factory Method
// ============================================================

std::unique_ptr<NetworkClient> TransportFactory::Create(TransportMode mode) {
    switch (mode) {
        case TransportMode::TRANSPORT_TCP:
            return std::make_unique<TcpClient>();

        case TransportMode::TRANSPORT_HTTP:
            return std::make_unique<HttpClient>();

        default:
            // Unknown mode — default to TCP (most secure/private)
            return std::make_unique<TcpClient>();
    }
}

std::unique_ptr<NetworkClient> TransportFactory::CreateAndConnect(
    TransportMode mode,
    const std::string& host,
    uint16_t port) {
    auto client = Create(mode);
    if (!client) {
        return nullptr;
    }

    if (!client->Connect(host, port)) {
        return nullptr;
    }

    return client;
}

// ============================================================
// Mode Parsing / String Conversion
// ============================================================

TransportMode TransportFactory::ParseMode(const std::string& mode_str) {
    // Case-insensitive comparison
    std::string lower = mode_str;
    std::transform(lower.begin(), lower.end(), lower.begin(),
                   [](unsigned char c) { return std::tolower(c); });

    if (lower == "tcp") {
        return TransportMode::TRANSPORT_TCP;
    }

    if (lower == "http") {
        return TransportMode::TRANSPORT_HTTP;
    }

    // Default to HTTP (backward compatible with existing server)
    return TransportMode::TRANSPORT_HTTP;
}

const char* TransportFactory::ModeToString(TransportMode mode) {
    switch (mode) {
        case TransportMode::TRANSPORT_TCP:
            return "tcp";
        case TransportMode::TRANSPORT_HTTP:
            return "http";
        default:
            return "unknown";
    }
}

} // namespace transport
} // namespace peanut
