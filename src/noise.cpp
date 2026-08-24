#include "noise.hpp"

#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cstring>
#include <stdexcept>

namespace wirebone {
namespace {

constexpr char kProtocolName[] = "Noise_IK_25519_ChaChaPoly_BLAKE2s";
constexpr char kProloguePrefix[] = "Tailscale Control Protocol v";

constexpr std::uint8_t kMsgInitiation = 1;
constexpr std::uint8_t kMsgResponse = 2;
constexpr std::uint8_t kMsgRecord = 4;
constexpr int kHeaderLen = 3;
constexpr int kInitHeaderLen = 5;
constexpr int kInitiationLen = 101;
constexpr int kResponseLen = 51;
constexpr int kMaxMessage = 4096;
constexpr int kMaxPlaintext = kMaxMessage - 3 - 16;

void mix_hash(Bytes32& h, std::span<const std::uint8_t> data) {
    h = blake2s256(h, data);
}

bool mix_dh(Bytes32& ck, Bytes32& k, const Bytes32& priv, const Bytes32& pub) {
    try {
        Bytes32 shared = x25519_shared(priv, pub);
        std::array<std::uint8_t, 64> out{};
        hkdf_blake2s(shared, ck, out);
        std::memcpy(ck.data(), out.data(), 32);
        std::memcpy(k.data(), out.data() + 32, 32);
        return true;
    } catch (...) {
        return false;
    }
}

void encrypt_and_hash(Bytes32& h, const Bytes32& k, std::span<std::uint8_t> ciphertext,
                      std::span<const std::uint8_t> plaintext) {
    std::uint8_t nonce[12]{};
    auto sealed = aead_seal(k, nonce, h, plaintext);
    if (sealed.size() != ciphertext.size()) {
        throw std::runtime_error("encrypt_and_hash size");
    }
    std::memcpy(ciphertext.data(), sealed.data(), sealed.size());
    mix_hash(h, sealed);
}

bool decrypt_and_hash(Bytes32& h, const Bytes32& k, std::span<std::uint8_t> plaintext,
                      std::span<const std::uint8_t> ciphertext) {
    std::uint8_t nonce[12]{};
    std::vector<std::uint8_t> pt;
    if (!aead_open(k, nonce, h, ciphertext, pt) || pt.size() != plaintext.size()) {
        return false;
    }
    if (!plaintext.empty()) {
        std::memcpy(plaintext.data(), pt.data(), pt.size());
    }
    mix_hash(h, ciphertext);
    return true;
}

bool split_keys(const Bytes32& ck, Bytes32& c1, Bytes32& c2) {
    std::array<std::uint8_t, 64> out{};
    try {
        hkdf_blake2s({}, ck, out);
    } catch (...) {
        return false;
    }
    std::memcpy(c1.data(), out.data(), 32);
    std::memcpy(c2.data(), out.data() + 32, 32);
    return true;
}

Bytes32 initial_hash() {
    return blake2s256(std::span<const std::uint8_t>{
        reinterpret_cast<const std::uint8_t*>(kProtocolName), sizeof(kProtocolName) - 1});
}

std::vector<std::uint8_t> prologue(std::uint16_t version) {
    std::string s = std::string(kProloguePrefix) + std::to_string(version);
    return {s.begin(), s.end()};
}

void put_be16(std::uint8_t* p, std::uint16_t v) {
    p[0] = static_cast<std::uint8_t>(v >> 8);
    p[1] = static_cast<std::uint8_t>(v);
}

std::uint16_t get_be16(const std::uint8_t* p) {
    return static_cast<std::uint16_t>((p[0] << 8) | p[1]);
}

void put_be64(std::uint8_t* p, std::uint64_t v) {
    for (int i = 7; i >= 0; --i) {
        p[i] = static_cast<std::uint8_t>(v);
        v >>= 8;
    }
}

bool read_full(int fd, std::uint8_t* buf, int n) {
    int got = 0;
    while (got < n) {
        const ssize_t r = ::recv(fd, buf + got, static_cast<std::size_t>(n - got), 0);
        if (r <= 0) {
            return false;
        }
        got += static_cast<int>(r);
    }
    return true;
}

bool write_full(int fd, const std::uint8_t* buf, int n) {
    int sent = 0;
    while (sent < n) {
        const ssize_t w = ::send(fd, buf + sent, static_cast<std::size_t>(n - sent), 0);
        if (w <= 0) {
            return false;
        }
        sent += static_cast<int>(w);
    }
    return true;
}

}  // namespace

bool noise_server_handshake(const Bytes32& control_private,
                            std::span<const std::uint8_t> optional_init,
                            std::vector<std::uint8_t>& handshake_response, NoiseResult& out,
                            std::string& error) {
    if (optional_init.size() != kInitiationLen) {
        error = "wrong handshake initiation size";
        return false;
    }
    const auto* init = optional_init.data();
    const std::uint16_t version = get_be16(init);
    if (init[2] != kMsgInitiation) {
        error = "unexpected handshake message type";
        return false;
    }
    if (get_be16(init + 3) != 96) {
        error = "wrong handshake initiation length";
        return false;
    }

    Bytes32 h = initial_hash();
    Bytes32 ck = h;
    mix_hash(h, prologue(version));

    const Bytes32 control_pub = x25519_public(control_private);
    mix_hash(h, control_pub);

    Bytes32 machine_eph{};
    std::memcpy(machine_eph.data(), init + kInitHeaderLen, 32);
    mix_hash(h, machine_eph);

    Bytes32 k{};
    if (!mix_dh(ck, k, control_private, machine_eph)) {
        error = "computing es";
        return false;
    }
    Bytes32 machine_key{};
    if (!decrypt_and_hash(h, k, machine_key, {init + kInitHeaderLen + 32, 48})) {
        error = "decrypting machine key";
        return false;
    }
    if (!mix_dh(ck, k, control_private, machine_key)) {
        error = "computing ss";
        return false;
    }
    if (!decrypt_and_hash(h, k, {}, {init + kInitHeaderLen + 32 + 48, 16})) {
        error = "decrypting initiation tag";
        return false;
    }

    const Bytes32 control_eph = generate_x25519_private();
    const Bytes32 control_eph_pub = x25519_public(control_eph);
    handshake_response.assign(kResponseLen, 0);
    handshake_response[0] = kMsgResponse;
    put_be16(handshake_response.data() + 1, 48);
    std::memcpy(handshake_response.data() + kHeaderLen, control_eph_pub.data(), 32);
    mix_hash(h, control_eph_pub);
    if (!mix_dh(ck, k, control_eph, machine_eph)) {
        error = "computing ee";
        return false;
    }
    if (!mix_dh(ck, k, control_eph, machine_key)) {
        error = "computing se";
        return false;
    }
    encrypt_and_hash(h, k, {handshake_response.data() + kHeaderLen + 32, 16}, {});

    Bytes32 c1{}, c2{};
    if (!split_keys(ck, c1, c2)) {
        error = "finalizing handshake";
        return false;
    }

    out.peer_machine_public = machine_key;
    out.protocol_version = version;
    out.handshake_hash = h;
    out.tx_key = c2;
    out.rx_key = c1;
    return true;
}

std::vector<std::uint8_t> noise_client_init(const Bytes32& machine_private,
                                            const Bytes32& control_public,
                                            std::uint16_t protocol_version, Bytes32& ephemeral_priv,
                                            Bytes32& h, Bytes32& ck) {
    h = initial_hash();
    ck = h;
    mix_hash(h, prologue(protocol_version));
    mix_hash(h, control_public);

    ephemeral_priv = generate_x25519_private();
    const Bytes32 eph_pub = x25519_public(ephemeral_priv);
    std::vector<std::uint8_t> init(kInitiationLen, 0);
    put_be16(init.data(), protocol_version);
    init[2] = kMsgInitiation;
    put_be16(init.data() + 3, 96);
    std::memcpy(init.data() + kInitHeaderLen, eph_pub.data(), 32);
    mix_hash(h, eph_pub);

    Bytes32 k{};
    if (!mix_dh(ck, k, ephemeral_priv, control_public)) {
        throw std::runtime_error("client es");
    }
    const Bytes32 machine_pub = x25519_public(machine_private);
    encrypt_and_hash(h, k, {init.data() + kInitHeaderLen + 32, 48}, machine_pub);
    if (!mix_dh(ck, k, machine_private, control_public)) {
        throw std::runtime_error("client ss");
    }
    encrypt_and_hash(h, k, {init.data() + kInitHeaderLen + 32 + 48, 16}, {});
    return init;
}

bool noise_client_finish(const Bytes32& machine_private, const Bytes32& ephemeral_priv,
                         const Bytes32& control_public, std::span<const std::uint8_t> response,
                         Bytes32& h, Bytes32& ck, NoiseResult& out, std::string& error) {
    (void)control_public;
    if (response.size() != kResponseLen || response[0] != kMsgResponse ||
        get_be16(response.data() + 1) != 48) {
        error = "bad handshake response";
        return false;
    }
    Bytes32 control_eph_pub{};
    std::memcpy(control_eph_pub.data(), response.data() + kHeaderLen, 32);
    mix_hash(h, control_eph_pub);
    Bytes32 k{};
    if (!mix_dh(ck, k, ephemeral_priv, control_eph_pub)) {
        error = "computing ee";
        return false;
    }
    if (!mix_dh(ck, k, machine_private, control_eph_pub)) {
        error = "computing se";
        return false;
    }
    if (!decrypt_and_hash(h, k, {}, {response.data() + kHeaderLen + 32, 16})) {
        error = "decrypting payload";
        return false;
    }
    Bytes32 c1{}, c2{};
    if (!split_keys(ck, c1, c2)) {
        error = "finalizing handshake";
        return false;
    }
    out.protocol_version = 0;
    out.handshake_hash = h;
    out.tx_key = c1;
    out.rx_key = c2;
    return true;
}

NoiseConn::NoiseConn(int fd, const Bytes32& tx_key, const Bytes32& rx_key)
    : fd_(fd), tx_key_(tx_key), rx_key_(rx_key) {}

NoiseConn::~NoiseConn() { close(); }

void NoiseConn::close() {
    if (fd_ >= 0) {
        ::shutdown(fd_, SHUT_RDWR);
        ::close(fd_);
        fd_ = -1;
    }
}

bool NoiseConn::decrypt_one() {
    std::uint8_t hdr[kHeaderLen];
    if (!read_full(fd_, hdr, kHeaderLen)) {
        return false;
    }
    if (hdr[0] != kMsgRecord) {
        return false;
    }
    const int clen = get_be16(hdr + 1);
    if (clen < 16 || clen > kMaxMessage - kHeaderLen) {
        return false;
    }
    std::vector<std::uint8_t> ct(static_cast<std::size_t>(clen));
    if (!read_full(fd_, ct.data(), clen)) {
        return false;
    }
    std::uint8_t nonce[12]{};
    put_be64(nonce + 4, rx_nonce_);
    std::vector<std::uint8_t> pt;
    if (!aead_open(rx_key_, nonce, {}, ct, pt)) {
        return false;
    }
    ++rx_nonce_;
    plaintext_.insert(plaintext_.end(), pt.begin(), pt.end());
    return true;
}

int NoiseConn::read(std::uint8_t* buf, int n) {
    if (n <= 0) {
        return 0;
    }
    while (plaintext_.empty()) {
        if (!decrypt_one()) {
            return 0;
        }
    }
    const int take = std::min(n, static_cast<int>(plaintext_.size()));
    std::memcpy(buf, plaintext_.data(), static_cast<std::size_t>(take));
    plaintext_.erase(plaintext_.begin(), plaintext_.begin() + take);
    return take;
}

int NoiseConn::write(const std::uint8_t* buf, int n) {
    int sent = 0;
    while (sent < n) {
        const int chunk = std::min(n - sent, kMaxPlaintext);
        std::uint8_t nonce[12]{};
        put_be64(nonce + 4, tx_nonce_);
        auto ct = aead_seal(tx_key_, nonce, {}, {buf + sent, static_cast<std::size_t>(chunk)});
        ++tx_nonce_;
        std::uint8_t hdr[kHeaderLen];
        hdr[0] = kMsgRecord;
        put_be16(hdr + 1, static_cast<std::uint16_t>(ct.size()));
        if (!write_full(fd_, hdr, kHeaderLen) ||
            !write_full(fd_, ct.data(), static_cast<int>(ct.size()))) {
            return sent == 0 ? -1 : sent;
        }
        sent += chunk;
    }
    return sent;
}

}  // namespace wirebone
