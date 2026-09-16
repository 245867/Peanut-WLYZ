// ============================================================
// PeanutWLYZ — WY Crypto + PSP Unit Tests
// ============================================================

#include "test_framework.h"

#include "wy_random.h"
#include "wy_hash.h"
#include "wy_cipher.h"
#include "wy_rsa.h"
#include "shadow_tunnel.h"

#include <cstdio>

TestConfig g_config;

void print_header() {
    peanut_test::color::set(peanut_test::color::CYAN);
    std::cout << "==============================================\n";
    std::cout << "  PeanutWLYZ — WY Crypto / PSP Unit Tests\n";
    std::cout << "==============================================\n";
    peanut_test::color::reset();
}

void print_config(const TestConfig& cfg) {
    std::cout << "  host=" << cfg.host << " port=" << cfg.port << "\n";
}

// ── Helpers ────────────────────────────────────────────────
static std::vector<uint8_t> hex_to_bytes(const std::string& hex) {
    auto nibble = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    std::vector<uint8_t> out;
    out.reserve(hex.size() / 2);
    for (size_t i = 0; i + 1 < hex.size(); i += 2) {
        int hi = nibble(hex[i]);
        int lo = nibble(hex[i + 1]);
        if (hi < 0 || lo < 0) break;
        out.push_back(static_cast<uint8_t>((hi << 4) | lo));
    }
    return out;
}

// ============================================================
// WY-Random
// ============================================================
TEST(WY_Random_Bytes) {
    uint8_t a[32] = {}, b[32] = {};
    ExpectTrue(wy::wy_random_bytes(a, sizeof(a)) == sizeof(a));
    ExpectTrue(wy::wy_random_bytes(b, sizeof(b)) == sizeof(b));
    ExpectFalse(std::memcmp(a, b, sizeof(a)) == 0);
    ExpectTrue(wy::wy_random_u32() != 0 || wy::wy_random_u64() != 0);
}

// ============================================================
// WY-Hash / HMAC / HKDF
// ============================================================
TEST(WY_Hash_Deterministic) {
    const char* msg = "peanut-wlyz-hash-test";
    uint8_t d1[32], d2[32];
    wy::wy_hash(reinterpret_cast<const uint8_t*>(msg), std::strlen(msg), d1);
    wy::wy_hash(reinterpret_cast<const uint8_t*>(msg), std::strlen(msg), d2);
    ExpectEqualBytes(d1, d2, 32);
    ExpectTrue(wy::wy_const_time_eq(d1, d2, 32));
}

TEST(WY_Hash_DifferentInputs) {
    uint8_t d1[32], d2[32];
    wy::wy_hash(reinterpret_cast<const uint8_t*>("aaa"), 3, d1);
    wy::wy_hash(reinterpret_cast<const uint8_t*>("aab"), 3, d2);
    ExpectFalse(wy::wy_const_time_eq(d1, d2, 32));
}

TEST(WY_HMAC_RoundtripShape) {
    const uint8_t key[] = "hmac-key-32-bytes-!!!!!!!!!!!!!";
    const uint8_t msg[] = "payload";
    uint8_t mac[32];
    wy::wy_hmac(key, sizeof(key) - 1, msg, sizeof(msg) - 1, mac);
    uint8_t zero[32] = {};
    ExpectFalse(std::memcmp(mac, zero, 32) == 0);
}

TEST(WY_HKDF_ExpandLength) {
    uint8_t ikm[32], out[48];
    wy::wy_random_bytes(ikm, sizeof(ikm));
    const uint8_t info[] = "psp-session";
    wy::wy_hkdf(ikm, sizeof(ikm), nullptr, 0, info, sizeof(info) - 1, out, sizeof(out));
    uint8_t zero[48] = {};
    ExpectFalse(std::memcmp(out, zero, sizeof(out)) == 0);
}

// ============================================================
// WY-Cipher
// ============================================================
TEST(WY_Cipher_BlockRoundtrip) {
    uint8_t key[32];
    wy::wy_random_bytes(key, sizeof(key));
    wy::wy_cipher_key ck;
    wy::wy_cipher_key_schedule(key, &ck);

    uint8_t block[32];
    wy::wy_random_bytes(block, sizeof(block));
    uint8_t original[32];
    std::memcpy(original, block, 32);

    wy::wy_cipher_encrypt_block(&ck, block);
    ExpectFalse(std::memcmp(block, original, 32) == 0);
    wy::wy_cipher_decrypt_block(&ck, block);
    ExpectEqualBytes(original, block, 32);
}

TEST(WY_Cipher_CBC_Roundtrip) {
    auto key_hex = wy::wy_cipher_generate_key_hex();
    auto key = hex_to_bytes(key_hex);
    ExpectTrue(key.size() == wy::WY_CIPHER_KEY_SIZE);

    wy::wy_cipher_key ck;
    wy::wy_cipher_key_schedule(key.data(), &ck);

    uint8_t iv[16];
    wy::wy_random_bytes(iv, sizeof(iv));

    const std::string plain = "Hello Peanut Soft Protect — CBC test payload 12345";
    auto cipher = wy::wy_cbc_encrypt(
        &ck, iv,
        reinterpret_cast<const uint8_t*>(plain.data()), plain.size());
    ExpectTrue(cipher.size() >= plain.size());
    ExpectTrue(cipher.size() % wy::WY_CIPHER_BLOCK_SIZE == 0);

    auto recovered = wy::wy_cbc_decrypt(&ck, iv, cipher.data(), cipher.size());
    ExpectEqual(plain, std::string(recovered.begin(), recovered.end()));
}

// ============================================================
// WY-RSA bigint smoke (no 2048-bit keygen in unit suite)
// ============================================================
TEST(WY_BigInt_Arithmetic) {
    wy::wy_bigint a(12345);
    wy::wy_bigint b(67890);
    ExpectTrue((a + b) == wy::wy_bigint(80235));
    ExpectTrue((b - a) == wy::wy_bigint(55545));
    ExpectFalse(a.is_zero());
    ExpectTrue(wy::wy_bigint(0).is_zero());
    ExpectTrue(wy::wy_bigint(1).is_one());
    ExpectTrue(a < b);
    ExpectTrue(b > a);
}

TEST(WY_BigInt_ModPow) {
    // 5^3 mod 13 = 125 mod 13 = 8
    wy::wy_bigint base(5);
    wy::wy_bigint exp(3);
    wy::wy_bigint mod(13);
    ExpectTrue(base.mod_pow(exp, mod) == wy::wy_bigint(8));
}

// ============================================================
// PSP helpers
// ============================================================
TEST(PSP_HeaderChecksum) {
    peanut::psp::PspHeader hdr{};
    hdr.magic0 = peanut::psp::PSP_MAGIC0;
    hdr.magic1 = peanut::psp::PSP_MAGIC1;
    hdr.version = peanut::psp::PSP_VERSION;
    hdr.type = static_cast<uint8_t>(peanut::psp::FrameType::DATA);
    hdr.seq_number = 1;
    hdr.payload_len = 32;
    hdr.checksum = peanut::psp::header_checksum(hdr);
    ExpectTrue(hdr.checksum == peanut::psp::header_checksum(hdr));
    ExpectTrue(hdr.magic0 == 0x57 && hdr.magic1 == 0x59);
}
