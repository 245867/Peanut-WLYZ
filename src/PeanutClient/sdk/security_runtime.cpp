#define _CRT_SECURE_NO_WARNINGS
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include "security_runtime.h"
#include "../crypto/wy_hash.h"
#include "../vmprotect_markers.h"
#include "../util/util.h"
#include <windows.h>
#include <shellapi.h>
#include <wincrypt.h>
#include <iphlpapi.h>
#include <algorithm>
#include <fstream>
#include <sstream>
#include <vector>

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "iphlpapi.lib")

namespace peanut { namespace security {

static HANDLE g_single_instance_mutex = nullptr;

static std::string Hex(const BYTE* data, DWORD size) {
    static const char kHex[] = "0123456789abcdef";
    std::string out(size * 2, '0');
    for (DWORD i = 0; i < size; ++i) {
        out[i * 2] = kHex[data[i] >> 4];
        out[i * 2 + 1] = kHex[data[i] & 15];
    }
    return out;
}

std::string FileSha256Hex(const std::wstring& path) {
    std::ifstream in(path, std::ios::binary);
    if (!in) return {};
    HCRYPTPROV provider = 0; HCRYPTHASH hash = 0;
    if (!CryptAcquireContextW(&provider, nullptr, nullptr, PROV_RSA_AES, CRYPT_VERIFYCONTEXT) ||
        !CryptCreateHash(provider, CALG_SHA_256, 0, 0, &hash)) {
        if (provider) CryptReleaseContext(provider, 0);
        return {};
    }
    char buffer[64 * 1024];
    while (in.good()) {
        in.read(buffer, sizeof(buffer));
        auto count = in.gcount();
        if (count > 0)
            CryptHashData(hash, reinterpret_cast<BYTE*>(buffer), static_cast<DWORD>(count), 0);
    }
    BYTE digest[32]; DWORD size = sizeof(digest);
    bool ok = CryptGetHashParam(hash, HP_HASHVAL, digest, &size, 0) != FALSE;
    CryptDestroyHash(hash);
    CryptReleaseContext(provider, 0);
    return ok ? Hex(digest, size) : std::string();
}

static std::string ReadRegistryString(HKEY root, const wchar_t* subkey, const wchar_t* name) {
    wchar_t data[512] = {};
    DWORD bytes = sizeof(data), type = 0;
    if (RegGetValueW(root, subkey, name, RRF_RT_REG_SZ, &type, data, &bytes) != ERROR_SUCCESS)
        return {};
    int n = WideCharToMultiByte(CP_UTF8, 0, data, -1, nullptr, 0, nullptr, nullptr);
    std::vector<char> out(n > 0 ? n : 1);
    if (n > 1) WideCharToMultiByte(CP_UTF8, 0, data, -1, out.data(), n, nullptr, nullptr);
    return n > 1 ? std::string(out.data()) : std::string();
}

static std::string HashText(const std::string& text) {
    uint8_t digest[wy::WY_HASH_OUTPUT_SIZE];
    wy::wy_hash(reinterpret_cast<const uint8_t*>(text.data()), text.size(), digest);
    return Hex(digest, sizeof(digest));
}

DeviceIdentity CollectDeviceIdentity(const std::string& challenge, const std::string& product_id) {
    VMProtectScope scope("CollectDeviceIdentity");
    std::vector<std::string> parts;
    DWORD serial = 0;
    if (GetVolumeInformationW(L"C:\\", nullptr, 0, &serial, nullptr, nullptr, nullptr, 0))
        parts.push_back("VOL:" + std::to_string(serial));
    auto guid = ReadRegistryString(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Cryptography", L"MachineGuid");
    if (!guid.empty()) parts.push_back("GUID:" + guid);
    wchar_t computer[256] = {};
    DWORD cch = 256;
    if (GetComputerNameW(computer, &cch)) {
        int n = WideCharToMultiByte(CP_UTF8, 0, computer, -1, nullptr, 0, nullptr, nullptr);
        std::vector<char> b(n > 0 ? n : 1);
        if (n > 1) WideCharToMultiByte(CP_UTF8, 0, computer, -1, b.data(), n, nullptr, nullptr);
        parts.push_back("HOST:" + std::string(b.data()));
    }
    SYSTEM_INFO si{};
    GetNativeSystemInfo(&si);
    parts.push_back("CPU:" + std::to_string(si.dwProcessorType) + ":" +
                    std::to_string(si.dwNumberOfProcessors) + ":" +
                    std::to_string(si.wProcessorArchitecture));
    UINT fwSize = GetSystemFirmwareTable('RSMB', 0, nullptr, 0);
    if (fwSize && fwSize < 4 * 1024 * 1024) {
        std::vector<BYTE> fw(fwSize);
        if (GetSystemFirmwareTable('RSMB', 0, fw.data(), fwSize) == fwSize)
            parts.push_back("SMBIOS:" + HashText(std::string(reinterpret_cast<char*>(fw.data()), fw.size())));
    }
    auto biosVendor = ReadRegistryString(HKEY_LOCAL_MACHINE, L"HARDWARE\\DESCRIPTION\\System\\BIOS", L"BIOSVendor");
    if (!biosVendor.empty()) parts.push_back("BIOSV:" + biosVendor);
    auto biosVersion = ReadRegistryString(HKEY_LOCAL_MACHINE, L"HARDWARE\\DESCRIPTION\\System\\BIOS", L"BIOSVersion");
    if (!biosVersion.empty()) parts.push_back("BIOSR:" + biosVersion);
    auto systemProduct = ReadRegistryString(HKEY_LOCAL_MACHINE, L"HARDWARE\\DESCRIPTION\\System\\BIOS", L"SystemProductName");
    if (!systemProduct.empty()) parts.push_back("PRODUCT:" + systemProduct);
    auto boardProduct = ReadRegistryString(HKEY_LOCAL_MACHINE, L"HARDWARE\\DESCRIPTION\\System\\BIOS", L"BaseBoardProduct");
    if (!boardProduct.empty()) parts.push_back("BOARD:" + boardProduct);
    DWORD adaptersSize = 0;
    GetAdaptersInfo(nullptr, &adaptersSize);
    if (adaptersSize) {
        std::vector<BYTE> raw(adaptersSize);
        auto info = reinterpret_cast<PIP_ADAPTER_INFO>(raw.data());
        if (GetAdaptersInfo(info, &adaptersSize) == ERROR_SUCCESS) {
            for (auto* p = info; p; p = p->Next)
                if (p->AddressLength)
                    parts.push_back("NIC:" + Hex(p->Address, p->AddressLength));
        }
    }
    std::sort(parts.begin(), parts.end());
    std::ostringstream joined;
    for (auto& p : parts) joined << p << '\n';
    DeviceIdentity out;
    out.source_count = static_cast<unsigned int>(parts.size());
    std::string full = HashText("device-v4|peanut-hardware|" + joined.str());
    out.device_id = full.substr(0, 24);
    std::transform(out.device_id.begin(), out.device_id.end(), out.device_id.begin(), ::toupper);
    out.proof = HashText("proof-v4|" + product_id + "|" + out.device_id + "|" + challenge);
    return out;
}

static std::wstring ModulePath() {
    wchar_t p[MAX_PATH] = {};
    GetModuleFileNameW(nullptr, p, MAX_PATH);
    return p;
}
static std::wstring Utf8Wide(const std::string& s) {
    int n = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, nullptr, 0);
    std::vector<wchar_t> b(n > 0 ? n : 1);
    if (n > 1) MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, b.data(), n);
    return std::wstring(b.data());
}

bool HandleUpdaterMode() {
    int argc = 0;
    LPWSTR* argv = CommandLineToArgvW(GetCommandLineW(), &argc);
    if (!argv || argc < 6 || std::wstring(argv[1]) != L"--apply-update") {
        if (argv) LocalFree(argv);
        return false;
    }
    DWORD pid = wcstoul(argv[2], nullptr, 10);
    std::wstring target = argv[3], staged = argv[4];
    std::string expected;
    {
        std::wstring x = argv[5];
        expected.reserve(x.size());
        for (wchar_t ch : x) expected.push_back(static_cast<char>(ch));
    }
    HANDLE process = OpenProcess(SYNCHRONIZE, FALSE, pid);
    if (process) {
        WaitForSingleObject(process, 30000);
        CloseHandle(process);
    }
    bool ok = FileSha256Hex(staged) == expected && CopyFileW(staged.c_str(), target.c_str(), FALSE);
    if (ok) ShellExecuteW(nullptr, L"open", target.c_str(), nullptr, nullptr, SW_SHOWNORMAL);
    LocalFree(argv);
    ExitProcess(ok ? 0 : 31);
    return true;
}

UpdateCheckResult CheckAndApplyUpdate(sdk::PeanutSecureClient& client, const std::string& product_id,
                                      const std::string& client_version,
                                      const std::function<void(int, const std::string&)>& progress) {
    auto report = [&](int value, const std::string& text) {
        if (progress) progress(value, text);
    };
    report(8, "正在检查更新策略");
    UpdateCheckResult result;
    std::wstring current = ModulePath();
    std::string currentHash = FileSha256Hex(current);
    sdk::UpdatePolicy policy;
    std::string error;
    if (!client.FetchUpdatePolicy(product_id, client_version, currentHash, policy, &error)) {
        result.message = "无法取得服务器更新策略: " + error;
        return result;
    }
    if (!policy.force_update && !policy.build_revoked) {
        report(100, "已是最新版本");
        result.allowed = true;
        result.message = "服务器未开启强制更新";
        return result;
    }
    std::string expected = !policy.target_sha256.empty() ? policy.target_sha256 : policy.package_sha256;
    std::transform(expected.begin(), expected.end(), expected.begin(), ::tolower);
    if (!policy.build_revoked && !expected.empty() && currentHash == expected) {
        report(100, "当前版本校验通过");
        result.allowed = true;
        result.message = "当前程序校验通过";
        return result;
    }
    result.update_required = true;
    if (policy.package_id.empty() || policy.package_sha256.empty()) {
        result.message = "服务器要求更新，但 TCP 包标识或 SHA-256 未配置";
        return result;
    }
    report(25, "正在通过加密 TCP 下载更新");
    std::vector<uint8_t> package;
    if (!client.DownloadUpdatePackage(policy.package_id, package, &error) ||
        (policy.package_size > 0 && static_cast<long long>(package.size()) != policy.package_size)) {
        report(0, "更新下载失败");
        result.message = "TCP 更新包下载失败: " + error;
        return result;
    }
    report(72, "下载完成，正在校验 SHA-256");
    std::wstring staged = current + L".update.exe";
    {
        std::ofstream out(staged, std::ios::binary | std::ios::trunc);
        out.write(reinterpret_cast<const char*>(package.data()), package.size());
        SecureZeroMemory(package.data(), package.size());
    }
    std::string packageHash = policy.package_sha256;
    std::transform(packageHash.begin(), packageHash.end(), packageHash.begin(), ::tolower);
    if (FileSha256Hex(staged) != packageHash) {
        DeleteFileW(staged.c_str());
        report(0, "更新包校验失败");
        result.message = "更新包 SHA-256 校验失败";
        return result;
    }
    report(90, "校验通过，正在准备替换");
    std::wstring args = L"--apply-update " + std::to_wstring(GetCurrentProcessId()) + L" \"" +
                        current + L"\" \"" + staged + L"\" " + Utf8Wide(packageHash);
    auto h = ShellExecuteW(nullptr, L"open", staged.c_str(), args.c_str(), nullptr, SW_HIDE);
    if (reinterpret_cast<INT_PTR>(h) <= 32) {
        result.message = "无法启动更新器";
        return result;
    }
    report(100, "更新程序已启动");
    result.update_started = true;
    result.message = "更新已启动";
    return result;
}

bool TryAcquireSingleInstance(const wchar_t* mutex_name) {
    if (!mutex_name || !*mutex_name) return false;
    if (g_single_instance_mutex) return true;
    g_single_instance_mutex = CreateMutexW(nullptr, TRUE, mutex_name);
    if (!g_single_instance_mutex) return false;
    if (GetLastError() == ERROR_ALREADY_EXISTS) {
        CloseHandle(g_single_instance_mutex);
        g_single_instance_mutex = nullptr;
        return false;
    }
    return true;
}

void ReleaseSingleInstance() {
    if (g_single_instance_mutex) {
        ReleaseMutex(g_single_instance_mutex);
        CloseHandle(g_single_instance_mutex);
        g_single_instance_mutex = nullptr;
    }
}

void SecureErase(std::string& value) {
    VMProtectScope scope("SecureErase");
    if (!value.empty()) SecureZeroMemory(value.data(), value.size());
    value.clear();
    value.shrink_to_fit();
}

uint64_t AuthorizationGuard::IntegrityTag() const {
    // 使用自研哈希，避免 std::hash 易伪造
    std::string material = "peanut-guard-v3|" + token_ + "|" + device_id_ + "|" +
                           std::to_string(remaining_seconds_) + "|" +
                           std::to_string(remaining_at_login_);
    uint8_t dig[wy::WY_HASH_OUTPUT_SIZE];
    wy::wy_hash(reinterpret_cast<const uint8_t*>(material.data()), material.size(), dig);
    uint64_t tag = 0;
    for (int i = 0; i < 8; ++i)
        tag = (tag << 8) | dig[i];
    return tag;
}

bool AuthorizationGuard::BeginLogin() {
    VMProtectScope scope("AuthBeginLogin");
    std::lock_guard<std::mutex> l(mutex_);
    const auto current = state_.load();
    if (current == AuthorizationState::AUTHORIZED ||
        current == AuthorizationState::RUNNING ||
        current == AuthorizationState::AUTHENTICATING)
        return false;
    SecureErase(token_);
    SecureErase(device_id_);
    remaining_seconds_ = 0;
    remaining_at_login_ = 0;
    integrity_tag_ = 0;
    last_fail_ = AuthorizationState::BOOT;
    state_ = AuthorizationState::AUTHENTICATING;
    return true;
}

bool AuthorizationGuard::CompleteLogin(const std::string& token, long long remaining,
                                       const std::string& device) {
    VMProtectScope scope("AuthCompleteLogin");
    std::lock_guard<std::mutex> l(mutex_);
    // remaining <= 0 一律拒绝（永久卡服务端应下发大 TTL > 0）
    if (token.empty() || device.empty() || remaining <= 0) {
        state_ = AuthorizationState::AUTH_FAILED;
        last_fail_ = AuthorizationState::AUTH_FAILED;
        return false;
    }
    token_ = token;
    device_id_ = device;
    remaining_seconds_ = remaining;
    remaining_at_login_ = remaining;
    login_mono_ = std::chrono::steady_clock::now();
    last_heartbeat_ = login_mono_;
    integrity_tag_ = IntegrityTag();
    state_ = AuthorizationState::AUTHORIZED;
    last_fail_ = AuthorizationState::BOOT;
    return true;
}

bool AuthorizationGuard::EnterRunning() {
    VMProtectScope scope("AuthEnterRunning");
    if (!RequireAuthorized()) return false;
    state_ = AuthorizationState::RUNNING;
    return true;
}

bool AuthorizationGuard::RecordHeartbeat(bool ok, long long remaining) {
    VMProtectScope scope("AuthRecordHeartbeat");
    std::lock_guard<std::mutex> l(mutex_);
    if (!ok) {
        state_ = AuthorizationState::HEARTBEAT_LOST;
        last_fail_ = AuthorizationState::HEARTBEAT_LOST;
        return false;
    }
    if (remaining <= 0) {
        state_ = AuthorizationState::AUTH_EXPIRED;
        last_fail_ = AuthorizationState::AUTH_EXPIRED;
        return false;
    }
    remaining_seconds_ = remaining;
    remaining_at_login_ = remaining;
    login_mono_ = std::chrono::steady_clock::now();
    last_heartbeat_ = login_mono_;
    integrity_tag_ = IntegrityTag();
    if (state_ == AuthorizationState::AUTHORIZED || state_ == AuthorizationState::RUNNING)
        return true;
    // 心跳恢复：若仅短暂丢失且未 SecureClear，可回到 RUNNING
    if (state_ == AuthorizationState::HEARTBEAT_LOST && !token_.empty()) {
        state_ = AuthorizationState::RUNNING;
        return true;
    }
    return state_ == AuthorizationState::AUTHORIZED || state_ == AuthorizationState::RUNNING;
}

bool AuthorizationGuard::CheckAuthorizedUnlocked() const {
    auto s = state_.load();
    if (s != AuthorizationState::AUTHORIZED && s != AuthorizationState::RUNNING)
        return false;
    if (token_.empty() || device_id_.empty())
        return false;
    if (integrity_tag_ != IntegrityTag())
        return false;
    // 本地 remaining 衰减：防止长期不心跳仍认为有效
    auto now = std::chrono::steady_clock::now();
    if (now - last_heartbeat_ >= std::chrono::seconds(kHeartbeatGraceSeconds))
        return false;
    long long elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - login_mono_).count();
    if (elapsed < 0) elapsed = 0;
    if (remaining_at_login_ - elapsed <= 0)
        return false;
    return true;
}

bool AuthorizationGuard::RequireAuthorized() const {
    VMProtectScope scope("AuthRequireAuthorized");
    std::lock_guard<std::mutex> l(mutex_);
    return CheckAuthorizedUnlocked();
}

long long AuthorizationGuard::RemainingSeconds() const {
    std::lock_guard<std::mutex> l(mutex_);
    auto now = std::chrono::steady_clock::now();
    long long elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - login_mono_).count();
    if (elapsed < 0) elapsed = 0;
    long long left = remaining_at_login_ - elapsed;
    return left > 0 ? left : 0;
}

bool AuthorizationGuard::IsTerminal() const {
    auto s = state_.load();
    return s == AuthorizationState::TERMINATED ||
           s == AuthorizationState::SECURITY_SHUTDOWN ||
           s == AuthorizationState::AUTH_EXPIRED ||
           s == AuthorizationState::SERVER_REVOKED;
}

void AuthorizationGuard::SecureClear() {
    VMProtectScope scope("AuthSecureClear");
    std::lock_guard<std::mutex> l(mutex_);
    SecureErase(token_);
    SecureErase(device_id_);
    remaining_seconds_ = 0;
    remaining_at_login_ = 0;
    integrity_tag_ = 0;
    state_ = AuthorizationState::TERMINATED;
}

void AuthorizationGuard::Invalidate(AuthorizationState reason) {
    VMProtectScope scope("AuthInvalidate");
    last_fail_ = reason;
    state_ = reason;
    // 清密钥，但 last_fail_ 保留原因
    {
        std::lock_guard<std::mutex> l(mutex_);
        SecureErase(token_);
        SecureErase(device_id_);
        remaining_seconds_ = 0;
        remaining_at_login_ = 0;
        integrity_tag_ = 0;
    }
    // 终态：TERMINATED 表示已清理；原因在 LastFailReason()
    state_ = AuthorizationState::TERMINATED;
}

void TerminateCurrentProcessSafely(unsigned int code, bool failFast) {
    ReleaseSingleInstance();
    if (failFast) RaiseFailFastException(nullptr, nullptr, 0);
    ExitProcess(code);
}

void FailClosedOnAuthLoss(AuthorizationGuard& guard, std::string* app_token,
                          bool terminate_process, unsigned int exit_code) {
    VMProtectScope scope("FailClosedOnAuthLoss");
    auto reason = guard.LastFailReason();
    if (reason == AuthorizationState::BOOT)
        reason = guard.State();
    guard.Invalidate(reason == AuthorizationState::TERMINATED
                         ? AuthorizationState::SECURITY_SHUTDOWN
                         : reason);
    if (app_token) SecureErase(*app_token);
    if (terminate_process)
        TerminateCurrentProcessSafely(exit_code, false);
}

} }
