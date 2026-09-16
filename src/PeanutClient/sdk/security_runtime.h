#pragma once

#include "peanut_secure_client.h"
#include <atomic>
#include <chrono>
#include <mutex>
#include <string>
#include <functional>

namespace peanut { namespace security {

enum class AuthorizationState {
    BOOT, CONNECTING, HANDSHAKING, AUTHENTICATING, AUTHORIZED, RUNNING,
    AUTH_FAILED, AUTH_EXPIRED, HEARTBEAT_LOST, SESSION_INVALID,
    STATE_CORRUPTED, SERVER_REVOKED, SECURITY_SHUTDOWN, TERMINATED
};

struct DeviceIdentity {
    std::string device_id;
    std::string proof;
    unsigned int source_count = 0;
};

struct UpdateCheckResult {
    bool allowed = false;
    bool update_required = false;
    bool update_started = false;
    std::string message;
};

std::string FileSha256Hex(const std::wstring& path);
DeviceIdentity CollectDeviceIdentity(const std::string& challenge,
                                     const std::string& product_id);
UpdateCheckResult CheckAndApplyUpdate(sdk::PeanutSecureClient& client,
                                      const std::string& product_id,
                                      const std::string& client_version,
                                      const std::function<void(int,const std::string&)>& progress = {});
bool HandleUpdaterMode();

// 本机单实例：返回 false 表示已有实例在运行
bool TryAcquireSingleInstance(const wchar_t* mutex_name);
void ReleaseSingleInstance();

// remaining_seconds 约定：
//   > 0  : 剩余秒数（含永久卡的大 TTL）
//   <= 0 : 已过期 / 无效（禁止把 0 当作永久）
class AuthorizationGuard {
public:
    static constexpr long long kHeartbeatGraceSeconds = 300; // 5 分钟

    bool BeginLogin();
    bool CompleteLogin(const std::string& token, long long remaining_seconds,
                       const std::string& device_id);
    bool EnterRunning();
    bool RecordHeartbeat(bool success, long long remaining_seconds);
    bool RequireAuthorized() const;
    void Invalidate(AuthorizationState reason);
    void SecureClear();
    AuthorizationState State() const { return state_.load(); }
    AuthorizationState LastFailReason() const { return last_fail_.load(); }
    const std::string& Token() const { return token_; }
    long long RemainingSeconds() const;
    bool IsTerminal() const;

private:
    uint64_t IntegrityTag() const;
    bool CheckAuthorizedUnlocked() const;
    std::atomic<AuthorizationState> state_{AuthorizationState::BOOT};
    std::atomic<AuthorizationState> last_fail_{AuthorizationState::BOOT};
    std::string token_;
    std::string device_id_;
    long long remaining_seconds_ = 0;
    std::chrono::steady_clock::time_point last_heartbeat_{};
    std::chrono::steady_clock::time_point login_mono_{};
    long long remaining_at_login_ = 0;
    uint64_t integrity_tag_ = 0;
    mutable std::mutex mutex_;
};

void SecureErase(std::string& value);
void TerminateCurrentProcessSafely(unsigned int exit_code, bool fail_fast = false);

// 授权丢失时的标准处置（清密钥 + 可选硬退）
void FailClosedOnAuthLoss(AuthorizationGuard& guard,
                          std::string* app_token,
                          bool terminate_process,
                          unsigned int exit_code = 42);

} }
