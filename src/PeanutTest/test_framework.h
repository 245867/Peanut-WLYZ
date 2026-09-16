// ============================================================
// PeanutWLYZ Protocol Test — Lightweight Test Framework
// ============================================================
// Provides a minimal yet usable C++ testing micro-framework
// with colored output, pass/fail tracking, and a summary report.
// No external dependencies — header-only.
// ============================================================

#pragma once

#include <string>
#include <vector>
#include <chrono>
#include <iostream>
#include <sstream>
#include <functional>
#include <stdexcept>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <windows.h>
#endif

namespace peanut_test {

// ── Console Colors (Windows Console API) ─────────────────
namespace color {
#ifdef _WIN32
    inline HANDLE console_handle() {
        static HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
        return h;
    }

    inline WORD get_default_attributes() {
        CONSOLE_SCREEN_BUFFER_INFO csbi;
        GetConsoleScreenBufferInfo(console_handle(), &csbi);
        return csbi.wAttributes;
    }

    inline void set(WORD attr) {
        SetConsoleTextAttribute(console_handle(), attr);
    }

    constexpr WORD GREEN   = FOREGROUND_GREEN | FOREGROUND_INTENSITY;
    constexpr WORD RED     = FOREGROUND_RED | FOREGROUND_INTENSITY;
    constexpr WORD YELLOW  = FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY;
    constexpr WORD CYAN    = FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY;
    constexpr WORD MAGENTA = FOREGROUND_RED | FOREGROUND_BLUE | FOREGROUND_INTENSITY;
    constexpr WORD WHITE   = FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY;
    constexpr WORD GRAY    = FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE;
    constexpr WORD DEFAULT = WHITE;

    inline void reset() {
        static WORD def = get_default_attributes();
        set(def);
    }
#else
    // ANSI escape codes for non-Windows platforms
    inline void set(int code) { std::cout << "\033[" << code << "m"; }
    inline void reset() { std::cout << "\033[0m"; }

    constexpr int GREEN   = 32;
    constexpr int RED     = 31;
    constexpr int YELLOW  = 33;
    constexpr int CYAN    = 36;
    constexpr int MAGENTA = 35;
    constexpr int WHITE   = 37;
    constexpr int GRAY    = 90;
    constexpr int DEFAULT = 0;
#endif
} // namespace color

// ── Test Result ──────────────────────────────────────────
struct TestResult {
    std::string name;
    bool        passed = false;
    std::string message;
    double      duration_ms = 0;
};

// ── Test Registry (Singleton) ─────────────────────────────
class TestRegistry {
public:
    static TestRegistry& instance() {
        static TestRegistry reg;
        return reg;
    }

    void add_test(const std::string& name, std::function<void()> fn) {
        tests_.push_back({name, fn});
    }

    void run_all() {
        auto total_start = std::chrono::steady_clock::now();

        for (auto& entry : tests_) {
            TestResult result;
            result.name = entry.name;

            auto start = std::chrono::steady_clock::now();
            try {
                entry.fn();
                result.passed = true;
            } catch (const TestAssertionFailure& ex) {
                result.passed = false;
                result.message = ex.what();
            } catch (const std::exception& ex) {
                result.passed = false;
                result.message = std::string("Exception: ") + ex.what();
            } catch (...) {
                result.passed = false;
                result.message = "Unknown exception";
            }
            auto end = std::chrono::steady_clock::now();
            result.duration_ms = std::chrono::duration<double, std::milli>(end - start).count();
            results_.push_back(result);

            // Print immediate result
            if (result.passed) {
                color::set(color::GREEN);
                std::cout << "  [PASS] ";
            } else {
                color::set(color::RED);
                std::cout << "  [FAIL] ";
            }
            color::reset();
            std::cout << result.name << " (" << result.duration_ms << " ms)";
            if (!result.message.empty()) {
                color::set(color::YELLOW);
                std::cout << "\n         " << result.message;
                color::reset();
            }
            std::cout << std::endl;
        }

        auto total_end = std::chrono::steady_clock::now();
        total_duration_ms_ = std::chrono::duration<double, std::milli>(total_end - total_start).count();
    }

    void print_summary() const {
        int passed = 0, failed = 0;
        for (const auto& r : results_) {
            if (r.passed) ++passed; else ++failed;
        }
        int total = passed + failed;

        std::cout << std::endl;
        color::set(color::CYAN);
        std::cout << "══════════════════════════════════════════════" << std::endl;
        std::cout << "  TEST SUMMARY" << std::endl;
        std::cout << "══════════════════════════════════════════════" << std::endl;
        color::reset();

        std::cout << "  Total:   " << total << std::endl;

        color::set(color::GREEN);
        std::cout << "  Passed:  " << passed;
        color::reset();
        std::cout << std::endl;

        if (failed > 0) {
            color::set(color::RED);
            std::cout << "  Failed:  " << failed;
            color::reset();
            std::cout << std::endl;
        }

        std::cout << "  Time:    " << total_duration_ms_ << " ms" << std::endl;
        std::cout << std::endl;

        if (failed == 0) {
            color::set(color::GREEN);
            std::cout << "  ★ ALL TESTS PASSED ★" << std::endl;
            color::reset();
        } else {
            color::set(color::RED);
            std::cout << "  ✗ " << failed << " TEST(S) FAILED" << std::endl;
            color::reset();
        }

        std::cout << std::endl;
    }

    int failed_count() const {
        int c = 0;
        for (const auto& r : results_) c += !r.passed;
        return c;
    }

private:
    struct TestEntry {
        std::string name;
        std::function<void()> fn;
    };
    std::vector<TestEntry> tests_;
    std::vector<TestResult> results_;
    double total_duration_ms_ = 0;

    TestRegistry() = default;

public:
    // Test assertion failure exception (internal)
    class TestAssertionFailure : public std::runtime_error {
    public:
        explicit TestAssertionFailure(const std::string& msg)
            : std::runtime_error(msg) {}
    };
};

// ── Expect Helpers (to be called inside test bodies) ─────
namespace expect {

inline void equal(const std::string& expected, const std::string& actual,
                   const char* file, int line) {
    if (expected != actual) {
        std::ostringstream ss;
        ss << file << ":" << line << " — Expected \"" << expected
           << "\", got \"" << actual << "\"";
        throw TestRegistry::TestAssertionFailure(ss.str());
    }
}

template<typename T>
inline void equal(T expected, T actual, const char* file, int line) {
    if (expected != actual) {
        std::ostringstream ss;
        ss << file << ":" << line << " — Expected " << expected
           << ", got " << actual;
        throw TestRegistry::TestAssertionFailure(ss.str());
    }
}

inline void equal_bytes(const uint8_t* expected, const uint8_t* actual,
                         size_t len, const char* file, int line) {
    for (size_t i = 0; i < len; ++i) {
        if (expected[i] != actual[i]) {
            std::ostringstream ss;
            ss << file << ":" << line << " — Bytes differ at index " << i
               << ": expected 0x" << std::hex << (int)expected[i]
               << ", got 0x" << (int)actual[i];
            throw TestRegistry::TestAssertionFailure(ss.str());
        }
    }
}

inline void true_expr(bool condition, const char* expr, const char* file, int line) {
    if (!condition) {
        std::ostringstream ss;
        ss << file << ":" << line << " — Expected true: " << expr;
        throw TestRegistry::TestAssertionFailure(ss.str());
    }
}

inline void false_expr(bool condition, const char* expr, const char* file, int line) {
    if (condition) {
        std::ostringstream ss;
        ss << file << ":" << line << " — Expected false: " << expr;
        throw TestRegistry::TestAssertionFailure(ss.str());
    }
}

} // namespace expect
} // namespace peanut_test

// ── Test Registration Macros ──────────────────────────────
#define TEST(name)                                                             \
    static void _test_body_##name();                                           \
    namespace {                                                                \
        struct _TestRegistrar_##name {                                         \
            _TestRegistrar_##name() {                                          \
                ::peanut_test::TestRegistry::instance().add_test(              \
                    #name, &_test_body_##name);                                \
            }                                                                  \
        } _test_reg_##name;                                                    \
    }                                                                          \
    static void _test_body_##name()

// ── Assertion Macros ──────────────────────────────────────
#define ExpectEqual(expected, actual)                                          \
    ::peanut_test::expect::equal((expected), (actual), __FILE__, __LINE__)

#define ExpectEqualBytes(expected, actual, len)                                \
    ::peanut_test::expect::equal_bytes((expected), (actual), (len), __FILE__, __LINE__)

#define ExpectTrue(expr)                                                       \
    ::peanut_test::expect::true_expr((expr), #expr, __FILE__, __LINE__)

#define ExpectFalse(expr)                                                      \
    ::peanut_test::expect::false_expr((expr), #expr, __FILE__, __LINE__)

// ── Convenience ───────────────────────────────────────────
#define RUN_ALL_TESTS()                                                        \
    do {                                                                       \
        ::peanut_test::TestRegistry::instance().run_all();                     \
        ::peanut_test::TestRegistry::instance().print_summary();               \
    } while (0)

#define TEST_EXIT_CODE()                                                       \
    (::peanut_test::TestRegistry::instance().failed_count() > 0 ? 1 : 0)

// ── Shared CLI / integration config ───────────────────────
struct TestConfig {
    std::string host        = "127.0.0.1";
    int         port        = 9001;
    std::string hmac_key    = "DVLCKCSZH4TEMZ2VB8AKOA036J3VP6LZ";
    std::string aes_key_hex = "55D49F8F4BF668B9D6854E817B4F45549D702B99DF77A7683BA1767B6BBF7952";
    std::string psp_key_hex = "B8F9D6A3C1E042175390FE2D8B7C6541A3098E7F2D5B4C6A1903876543210FED";
    std::string cardkey     = "TEST-CARD-KEY-001";
    std::string machinecode = "test_machine";
};

extern TestConfig g_config;
void print_header();
void print_config(const TestConfig& cfg);
