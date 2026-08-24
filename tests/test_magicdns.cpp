#include "dns.hpp"
#include "state.hpp"
#include "test_assert.hpp"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cstring>
#include <filesystem>
#include <thread>
#include <vector>

static void put16(std::vector<std::uint8_t>& b, std::uint16_t v) {
    b.push_back(static_cast<std::uint8_t>(v >> 8));
    b.push_back(static_cast<std::uint8_t>(v));
}

static std::vector<std::uint8_t> make_query(const std::string& name) {
    std::vector<std::uint8_t> q(12, 0);
    q[0] = 0x12;
    q[1] = 0x34;
    q[2] = 0x01;
    q[5] = 1;
    std::size_t i = 0;
    while (i < name.size()) {
        const auto dot = name.find('.', i);
        const auto lab = name.substr(i, dot == std::string::npos ? std::string::npos : dot - i);
        q.push_back(static_cast<std::uint8_t>(lab.size()));
        q.insert(q.end(), lab.begin(), lab.end());
        if (dot == std::string::npos) {
            break;
        }
        i = dot + 1;
    }
    q.push_back(0);
    put16(q, 1);
    put16(q, 1);
    return q;
}

int main() {
    const std::string path = "/tmp/wirebone-dns-" + std::to_string(getpid()) + ".json";
    std::filesystem::remove(path);
    wirebone::Store store(path, "100.64.0.0/16", "fd7a:115c:a1e0::/48");
    bool eph = false;
    const auto key = store.create_preauth_key(true, false, {});
    store.consume_preauth(key, eph);
    store.register_node("mkey:aa", "nodekey:bb", "alice", false);

    wirebone::MagicDns dns(store, "wirebone.local", "127.0.0.1:0");
    dns.start();
    const auto bound = dns.bound_address();
    WB_CHECK(!bound.empty());
    const auto port = static_cast<std::uint16_t>(std::stoi(bound.substr(bound.rfind(':') + 1)));

    const int fd = ::socket(AF_INET, SOCK_DGRAM, 0);
    WB_CHECK(fd >= 0);
    timeval tv{1, 0};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);
    auto q = make_query("alice.wirebone.local");
    WB_CHECK(::sendto(fd, q.data(), q.size(), 0, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) > 0);
    std::uint8_t buf[512];
    const ssize_t n = ::recv(fd, buf, sizeof(buf), 0);
    WB_CHECK(n > 12);
    WB_CHECK(buf[3] == 0x80);
    const int ancount = (buf[6] << 8) | buf[7];
    WB_CHECK(ancount >= 1);
    ::close(fd);
    dns.stop();
    std::filesystem::remove(path);
    return 0;
}
