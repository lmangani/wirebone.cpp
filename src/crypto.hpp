#pragma once

#include <array>
#include <cstdint>
#include <span>
#include <string>
#include <vector>

namespace wirebone {

using Bytes32 = std::array<std::uint8_t, 32>;
using Bytes16 = std::array<std::uint8_t, 16>;

void random_bytes(std::span<std::uint8_t> out);
Bytes32 blake2s256(std::span<const std::uint8_t> a, std::span<const std::uint8_t> b = {});
Bytes32 hmac_blake2s(std::span<const std::uint8_t> key, std::span<const std::uint8_t> data);

// Noise HKDF: secret=ikm, salt=chaining_key, info empty. Writes n*32 bytes.
void hkdf_blake2s(std::span<const std::uint8_t> ikm, std::span<const std::uint8_t> salt,
                  std::span<std::uint8_t> out);

Bytes32 x25519_public(const Bytes32& priv);
Bytes32 x25519_shared(const Bytes32& priv, const Bytes32& pub);
Bytes32 generate_x25519_private();

// IETF ChaCha20-Poly1305 (12-byte nonce). ciphertext = plaintext || tag.
std::vector<std::uint8_t> aead_seal(const Bytes32& key, std::span<const std::uint8_t> nonce12,
                                    std::span<const std::uint8_t> ad,
                                    std::span<const std::uint8_t> plaintext);
bool aead_open(const Bytes32& key, std::span<const std::uint8_t> nonce12,
               std::span<const std::uint8_t> ad, std::span<const std::uint8_t> ciphertext,
               std::vector<std::uint8_t>& plaintext);

std::string hex_encode(std::span<const std::uint8_t> bytes);
bool hex_decode(std::string_view hex, std::span<std::uint8_t> out);
std::string b64_encode(std::span<const std::uint8_t> bytes);
std::vector<std::uint8_t> b64_decode(std::string_view s);

}  // namespace wirebone
