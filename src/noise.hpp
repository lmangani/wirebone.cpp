#pragma once

#include "crypto.hpp"

#include <cstdint>
#include <memory>
#include <span>
#include <string>
#include <vector>

namespace wirebone {

struct NoiseResult {
    Bytes32 peer_machine_public{};
    std::uint16_t protocol_version = 0;
    Bytes32 handshake_hash{};
    Bytes32 tx_key{};  // server -> client (c2)
    Bytes32 rx_key{};  // client -> server (c1)
};

// Server-side Noise IK. optional_init is the 101-byte initiation (from
// X-Tailscale-Handshake). On success, handshake_response is the 51-byte
// cleartext reply to write on the TCP connection.
bool noise_server_handshake(const Bytes32& control_private,
                            std::span<const std::uint8_t> optional_init,
                            std::vector<std::uint8_t>& handshake_response, NoiseResult& out,
                            std::string& error);

// Client-side helpers used by tests. Builds the 101-byte initiation.
std::vector<std::uint8_t> noise_client_init(const Bytes32& machine_private,
                                            const Bytes32& control_public,
                                            std::uint16_t protocol_version, Bytes32& ephemeral_priv,
                                            Bytes32& h, Bytes32& ck);

bool noise_client_finish(const Bytes32& machine_private, const Bytes32& ephemeral_priv,
                         const Bytes32& control_public, std::span<const std::uint8_t> response,
                         Bytes32& h, Bytes32& ck, NoiseResult& out, std::string& error);

class NoiseConn {
public:
    NoiseConn(int fd, const Bytes32& tx_key, const Bytes32& rx_key);
    ~NoiseConn();

    NoiseConn(const NoiseConn&) = delete;
    NoiseConn& operator=(const NoiseConn&) = delete;

    int read(std::uint8_t* buf, int n);
    int write(const std::uint8_t* buf, int n);
    void close();
    int fd() const { return fd_; }

private:
    bool decrypt_one();

    int fd_ = -1;
    Bytes32 tx_key_{};
    Bytes32 rx_key_{};
    std::uint64_t tx_nonce_ = 0;
    std::uint64_t rx_nonce_ = 0;
    std::vector<std::uint8_t> raw_buf_;
    std::vector<std::uint8_t> plaintext_;
};

}  // namespace wirebone
