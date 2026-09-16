// ============================================================
// PeanutWLYZ Transport Layer — Transport Factory
// ============================================================
// Creates the appropriate NetworkClient implementation based
// on TransportMode. Ensures PSP layer doesn't need to know
// about specific transport implementations.
// ============================================================

#pragma once

#include "network_client.h"

#include <memory>
#include <string>
#include <cstdint>

namespace peanut {
namespace transport {

// ── TransportFactory ──────────────────────────────────────
// Simple factory: maps TransportMode → concrete NetworkClient.
//
// Usage:
//   auto client = TransportFactory::Create(TransportMode::TRANSPORT_TCP);
//   client->Connect("127.0.0.1", 5555);
//   client->Send(data, len);
//   ...
class TransportFactory {
public:
    // ── Factory Method ─────────────────────────────────────
    // Creates a new transport client.
    //
    // @param mode  Which transport to create.
    // @return  A heap-allocated NetworkClient. Caller owns.
    //          Never returns nullptr.
    static std::unique_ptr<NetworkClient> Create(TransportMode mode);

    // ── Convenience: Create and Connect ────────────────────
    // Combines Create() + Connect() in one call.
    //
    // @param mode  Which transport to create.
    // @param host  Remote hostname or IP.
    // @param port  Remote port.
    // @return  Connected client, or nullptr on failure.
    static std::unique_ptr<NetworkClient> CreateAndConnect(
        TransportMode mode,
        const std::string& host,
        uint16_t port);

    // ── Parse TransportMode from string ────────────────────
    // @param mode_str  "http" or "tcp" (case-insensitive)
    // @return  The parsed mode, defaults to TRANSPORT_HTTP
    static TransportMode ParseMode(const std::string& mode_str);

    // ── Convert TransportMode to string ────────────────────
    static const char* ModeToString(TransportMode mode);
};

} // namespace transport
} // namespace peanut
