// PeanutSdkDemo
#include "../PeanutClient/sdk/peanut_secure_client.h"
#include "../PeanutClient/crypto/key_files.h"
#include <iostream>
#include <string>
#include <filesystem>
namespace fs = std::filesystem;

static std::string ResolveKeyDir() {
    const char* cands[] = { "keys", "..\\..\\keys", "..\\..\\bin\\Release\\keys" };
    for (auto* c : cands) {
        if (fs::exists(fs::path(c) / peanut::keys::kServerPubkeyFile)) return c;
    }
    return "keys";
}

int main(int argc, char** argv) {
    std::string host = "127.0.0.1";
    int port = 9001;
    std::string key_dir = ResolveKeyDir();
    std::string card = "DEMO-CARD-001";
    std::string machine = "DEMO-MACHINE-PC";
    if (argc >= 2) host = argv[1];
    if (argc >= 3) port = std::atoi(argv[2]);
    if (argc >= 4) key_dir = argv[3];
    if (argc >= 5) machine = argv[4];
    if (argc >= 6) card = argv[5];

    std::cout << "=== PeanutSdkDemo ===\n";
    std::cout << "server=" << host << ":" << port << " keys=" << key_dir << "\n";

    if (!fs::exists(fs::path(key_dir) / peanut::keys::kServerPubkeyFile)) {
        std::cerr << "missing server_pubkey.hex\n";
        return 2;
    }

    peanut::sdk::PeanutSecureClient client;
    client.SetTransportMode(peanut::sdk::TransportMode::TCP);
    client.SetCallbacks([](const std::string& msg, int level) {
        const char* tag = level >= 3 ? "ERR" : "INF";
        std::cout << "[" << tag << "] " << msg << "\n";
    });
    client.SetServer(host, port);
    if (!client.LoadKeysFromDir(key_dir)) return 3;

    std::cout << "-- Connect --\n";
    if (!client.Connect()) { std::cerr << "FAIL Connect\n"; return 10; }
    std::cout << "OK connected\n";

    peanut::sdk::UpdatePolicy update;
    std::string update_error;
    if (!client.FetchUpdatePolicy("PeanutSdkDemo", "2.1.0", "test-build", update, &update_error)) {
        std::cerr << "FAIL update policy " << update_error << "\n"; return 15;
    }
    std::cout << "OK update force=" << (update.force_update ? 1 : 0)
              << " revoked=" << (update.build_revoked ? 1 : 0) << "\n";

    std::string ann, ver;
    if (!client.FetchConfigInfo(ann, ver)) { std::cerr << "FAIL config\n"; return 11; }
    std::cout << "OK config " << ann << " " << ver << "\n";

    std::string token;
    if (!client.Activate(card, machine, token)) { std::cerr << "FAIL activate\n"; return 12; }
    std::cout << "OK token=" << token << "\n";

    std::vector<CloudPluginInfo> plugins;
    std::string err;
    if (!client.FetchPluginList(token, plugins, &err)) { std::cerr << "FAIL list " << err << "\n"; return 13; }
    std::cout << "OK plugins=" << plugins.size() << "\n";

    if (!plugins.empty()) {
        std::string result;
        if (!client.CallPlugin(token, plugins[0].name, "{\"hello\":\"sdk\"}", result, &err)) {
            std::cerr << "FAIL exec " << err << "\n"; return 14;
        }
        std::cout << "OK result=" << result << "\n";
    }
    client.Disconnect();
    std::cout << "=== ALL PASSED ===\n";
    return 0;
}
