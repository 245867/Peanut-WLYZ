// ============================================================
// PeanutWLYZ — Protocol Test Suite Entry Point
// ============================================================
// Thin entry point: parses CLI args, populates the global
// TestConfig, then runs all tests defined in protocol_test.cpp.
// ============================================================

#include <string>
#include <iostream>
#include <atomic>

#ifdef _WIN32
#include <winsock2.h>
#include <windows.h>
#pragma comment(lib, "ws2_32.lib")
#endif

#include "test_framework.h"

// ============================================================
// main
// ============================================================

int main(int argc, char* argv[]) {
#ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD dwMode = 0;
    if (hOut != INVALID_HANDLE_VALUE && GetConsoleMode(hOut, &dwMode)) {
        dwMode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING;
        SetConsoleMode(hOut, dwMode);
    }
    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);
#endif

    print_header();

    // ── Help ────────────────────────────────────────────────
    if (argc > 1 && (std::string(argv[1]) == "-h" || std::string(argv[1]) == "--help")) {
        std::cout << "Usage: " << argv[0]
                  << " [host] [port] [hmac_key] [aes_key_hex] [psp_key_hex] [cardkey] [machinecode]\n"
                  << "\n"
                  << "Arguments:\n"
                  << "  host           Server hostname/IP (default: 127.0.0.1)\n"
                  << "  port           Server port (default: 9001)\n"
                  << "  hmac_key       HMAC signing key (default: built-in test key)\n"
                  << "  aes_key_hex    AES-256 key in hex (default: built-in test key)\n"
                  << "  psp_key_hex    PSP pre-shared key in hex (default: built-in test key)\n"
                  << "  cardkey        Card activation key (default: built-in test key)\n"
                  << "  machinecode    Machine code identifier (default: test_machine)\n"
                  << "\n"
                  << "Examples:\n"
                  << "  " << argv[0] << "                                          # All defaults\n"
                  << "  " << argv[0] << " 10.0.0.1 9090                             # Custom server\n"
                  << "  " << argv[0] << " 127.0.0.1 9001 mykey VALID_AES_HEX...      # Full custom\n"
                  << "\n"
                  << "Unit tests (crypto) run unconditionally.\n"
                  << "Integration tests auto-detect the server; skipped if unreachable.\n";
#ifdef _WIN32
        WSACleanup();
#endif
        return 0;
    }

    // ── Parse Args ──────────────────────────────────────────
    if (argc > 1) g_config.host        = argv[1];
    if (argc > 2) g_config.port        = std::stoi(argv[2]);
    if (argc > 3) g_config.hmac_key    = argv[3];
    if (argc > 4) g_config.aes_key_hex = argv[4];
    if (argc > 5) g_config.psp_key_hex = argv[5];
    if (argc > 6) g_config.cardkey     = argv[6];
    if (argc > 7) g_config.machinecode = argv[7];

    print_config(g_config);

    // ── Run All Tests ───────────────────────────────────────
    std::cout << std::endl;

    RUN_ALL_TESTS();

    int exit_code = TEST_EXIT_CODE();

#ifdef _WIN32
    WSACleanup();
#endif

    return exit_code;
}
