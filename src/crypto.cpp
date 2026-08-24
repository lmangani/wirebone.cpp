#include "crypto.hpp"

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#include <cstring>
#include <stdexcept>

namespace wirebone {
namespace {

void check(int ok, const char* what) {
    if (ok != 1) {
        throw std::runtime_error(what);
    }
}

}  // namespace

void random_bytes(std::span<std::uint8_t> out) {
    if (out.empty()) {
        return;
    }
    check(RAND_bytes(out.data(), static_cast<int>(out.size())), "RAND_bytes");
}

Bytes32 blake2s256(std::span<const std::uint8_t> a, std::span<const std::uint8_t> b) {
    Bytes32 out{};
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) {
        throw std::runtime_error("EVP_MD_CTX_new");
    }
    if (EVP_DigestInit_ex(ctx, EVP_blake2s256(), nullptr) != 1 ||
        EVP_DigestUpdate(ctx, a.data(), a.size()) != 1 ||
        (!b.empty() && EVP_DigestUpdate(ctx, b.data(), b.size()) != 1)) {
        EVP_MD_CTX_free(ctx);
        throw std::runtime_error("blake2s256");
    }
    unsigned int len = 0;
    if (EVP_DigestFinal_ex(ctx, out.data(), &len) != 1 || len != 32) {
        EVP_MD_CTX_free(ctx);
        throw std::runtime_error("blake2s256 final");
    }
    EVP_MD_CTX_free(ctx);
    return out;
}

Bytes32 hmac_blake2s(std::span<const std::uint8_t> key, std::span<const std::uint8_t> data) {
    // HMAC-BLAKE2s with 64-byte block (BLAKE2s).
    constexpr std::size_t block = 64;
    Bytes32 key_hash{};
    std::uint8_t kpad[block]{};
    if (key.size() > block) {
        key_hash = blake2s256(key);
        std::memcpy(kpad, key_hash.data(), 32);
    } else {
        std::memcpy(kpad, key.data(), key.size());
    }
    std::uint8_t ipad[block];
    std::uint8_t opad[block];
    for (std::size_t i = 0; i < block; ++i) {
        ipad[i] = static_cast<std::uint8_t>(kpad[i] ^ 0x36);
        opad[i] = static_cast<std::uint8_t>(kpad[i] ^ 0x5c);
    }
    std::vector<std::uint8_t> inner;
    inner.reserve(block + data.size());
    inner.insert(inner.end(), ipad, ipad + block);
    inner.insert(inner.end(), data.begin(), data.end());
    Bytes32 inner_hash = blake2s256(inner);
    std::vector<std::uint8_t> outer;
    outer.reserve(block + 32);
    outer.insert(outer.end(), opad, opad + block);
    outer.insert(outer.end(), inner_hash.begin(), inner_hash.end());
    return blake2s256(outer);
}

void hkdf_blake2s(std::span<const std::uint8_t> ikm, std::span<const std::uint8_t> salt,
                  std::span<std::uint8_t> out) {
    // Matches golang.org/x/crypto/hkdf.New(blake2s, ikm, salt, nil).
    Bytes32 prk = hmac_blake2s(salt, ikm);
    Bytes32 prev{};
    bool have_prev = false;
    std::size_t off = 0;
    std::uint8_t counter = 1;
    while (off < out.size()) {
        std::vector<std::uint8_t> msg;
        if (have_prev) {
            msg.insert(msg.end(), prev.begin(), prev.end());
        }
        msg.push_back(counter);
        prev = hmac_blake2s(prk, msg);
        have_prev = true;
        const std::size_t n = std::min<std::size_t>(32, out.size() - off);
        std::memcpy(out.data() + off, prev.data(), n);
        off += n;
        ++counter;
    }
}

Bytes32 generate_x25519_private() {
    Bytes32 priv{};
    random_bytes(priv);
    priv[0] &= 248;
    priv[31] &= 127;
    priv[31] |= 64;
    return priv;
}

Bytes32 x25519_public(const Bytes32& priv) {
    EVP_PKEY* pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, nullptr, priv.data(), 32);
    if (!pkey) {
        throw std::runtime_error("EVP_PKEY_new_raw_private_key");
    }
    Bytes32 pub{};
    std::size_t len = 32;
    if (EVP_PKEY_get_raw_public_key(pkey, pub.data(), &len) != 1 || len != 32) {
        EVP_PKEY_free(pkey);
        throw std::runtime_error("EVP_PKEY_get_raw_public_key");
    }
    EVP_PKEY_free(pkey);
    return pub;
}

Bytes32 x25519_shared(const Bytes32& priv, const Bytes32& pub) {
    EVP_PKEY* pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, nullptr, priv.data(), 32);
    EVP_PKEY* peer = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, nullptr, pub.data(), 32);
    if (!pkey || !peer) {
        EVP_PKEY_free(pkey);
        EVP_PKEY_free(peer);
        throw std::runtime_error("x25519 key import");
    }
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pkey, nullptr);
    Bytes32 out{};
    std::size_t len = 32;
    int ok = ctx && EVP_PKEY_derive_init(ctx) == 1 && EVP_PKEY_derive_set_peer(ctx, peer) == 1 &&
             EVP_PKEY_derive(ctx, out.data(), &len) == 1 && len == 32;
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    EVP_PKEY_free(peer);
    if (!ok) {
        throw std::runtime_error("x25519 derive");
    }
    return out;
}

std::vector<std::uint8_t> aead_seal(const Bytes32& key, std::span<const std::uint8_t> nonce12,
                                    std::span<const std::uint8_t> ad,
                                    std::span<const std::uint8_t> plaintext) {
    if (nonce12.size() != 12) {
        throw std::runtime_error("chacha20poly1305 nonce must be 12 bytes");
    }
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        throw std::runtime_error("EVP_CIPHER_CTX_new");
    }
    std::vector<std::uint8_t> out(plaintext.size() + 16);
    int len = 0;
    int ok = EVP_EncryptInit_ex(ctx, EVP_chacha20_poly1305(), nullptr, nullptr, nullptr) == 1 &&
             EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, 12, nullptr) == 1 &&
             EVP_EncryptInit_ex(ctx, nullptr, nullptr, key.data(), nonce12.data()) == 1;
    if (ok && !ad.empty()) {
        ok = EVP_EncryptUpdate(ctx, nullptr, &len, ad.data(), static_cast<int>(ad.size())) == 1;
    }
    int outl = 0;
    if (ok) {
        ok = EVP_EncryptUpdate(ctx, out.data(), &outl, plaintext.data(),
                               static_cast<int>(plaintext.size())) == 1;
    }
    int fin = 0;
    if (ok) {
        ok = EVP_EncryptFinal_ex(ctx, out.data() + outl, &fin) == 1;
    }
    if (ok) {
        ok = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16, out.data() + outl + fin) == 1;
    }
    EVP_CIPHER_CTX_free(ctx);
    if (!ok) {
        throw std::runtime_error("aead_seal");
    }
    out.resize(static_cast<std::size_t>(outl + fin + 16));
    return out;
}

bool aead_open(const Bytes32& key, std::span<const std::uint8_t> nonce12,
               std::span<const std::uint8_t> ad, std::span<const std::uint8_t> ciphertext,
               std::vector<std::uint8_t>& plaintext) {
    if (nonce12.size() != 12 || ciphertext.size() < 16) {
        return false;
    }
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        return false;
    }
    const std::size_t pt_len = ciphertext.size() - 16;
    plaintext.assign(pt_len, 0);
    int len = 0;
    int ok = EVP_DecryptInit_ex(ctx, EVP_chacha20_poly1305(), nullptr, nullptr, nullptr) == 1 &&
             EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, 12, nullptr) == 1 &&
             EVP_DecryptInit_ex(ctx, nullptr, nullptr, key.data(), nonce12.data()) == 1;
    if (ok && !ad.empty()) {
        ok = EVP_DecryptUpdate(ctx, nullptr, &len, ad.data(), static_cast<int>(ad.size())) == 1;
    }
    int outl = 0;
    if (ok && pt_len > 0) {
        ok = EVP_DecryptUpdate(ctx, plaintext.data(), &outl, ciphertext.data(),
                               static_cast<int>(pt_len)) == 1;
    }
    if (ok) {
        ok = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, 16,
                                 const_cast<std::uint8_t*>(ciphertext.data() + pt_len)) == 1;
    }
    int fin = 0;
    if (ok) {
        ok = EVP_DecryptFinal_ex(ctx, plaintext.data() + outl, &fin) == 1;
    }
    EVP_CIPHER_CTX_free(ctx);
    if (!ok) {
        plaintext.clear();
        return false;
    }
    plaintext.resize(static_cast<std::size_t>(outl + fin));
    return true;
}

std::string hex_encode(std::span<const std::uint8_t> bytes) {
    static constexpr char kHex[] = "0123456789abcdef";
    std::string s;
    s.resize(bytes.size() * 2);
    for (std::size_t i = 0; i < bytes.size(); ++i) {
        s[i * 2] = kHex[bytes[i] >> 4];
        s[i * 2 + 1] = kHex[bytes[i] & 0x0f];
    }
    return s;
}

bool hex_decode(std::string_view hex, std::span<std::uint8_t> out) {
    if (hex.size() != out.size() * 2) {
        return false;
    }
    auto nibble = [](char c) -> int {
        if (c >= '0' && c <= '9') {
            return c - '0';
        }
        if (c >= 'a' && c <= 'f') {
            return c - 'a' + 10;
        }
        if (c >= 'A' && c <= 'F') {
            return c - 'A' + 10;
        }
        return -1;
    };
    for (std::size_t i = 0; i < out.size(); ++i) {
        const int hi = nibble(hex[i * 2]);
        const int lo = nibble(hex[i * 2 + 1]);
        if (hi < 0 || lo < 0) {
            return false;
        }
        out[i] = static_cast<std::uint8_t>((hi << 4) | lo);
    }
    return true;
}

std::string b64_encode(std::span<const std::uint8_t> bytes) {
    if (bytes.empty()) {
        return {};
    }
    BIO* b64 = BIO_new(BIO_f_base64());
    BIO* mem = BIO_new(BIO_s_mem());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    BIO_push(b64, mem);
    BIO_write(b64, bytes.data(), static_cast<int>(bytes.size()));
    BIO_flush(b64);
    char* data = nullptr;
    const long len = BIO_get_mem_data(mem, &data);
    std::string out(data, static_cast<std::size_t>(len));
    BIO_free_all(b64);
    return out;
}

std::vector<std::uint8_t> b64_decode(std::string_view s) {
    if (s.empty()) {
        return {};
    }
    BIO* b64 = BIO_new(BIO_f_base64());
    BIO* mem = BIO_new_mem_buf(s.data(), static_cast<int>(s.size()));
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    BIO_push(b64, mem);
    std::vector<std::uint8_t> out(s.size());
    const int n = BIO_read(b64, out.data(), static_cast<int>(out.size()));
    BIO_free_all(b64);
    if (n < 0) {
        throw std::runtime_error("base64 decode");
    }
    out.resize(static_cast<std::size_t>(n));
    return out;
}

}  // namespace wirebone
