#include "test_assert.hpp"
#include "wirebone/coordinator.hpp"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <chrono>
#include <cstring>
#include <string>
#include <thread>

static std::string http_get(const std::string& host, std::uint16_t port, const std::string& path) {
    const int fd = ::socket(AF_INET, SOCK_STREAM, 0);
    WB_CHECK(fd >= 0);
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    inet_pton(AF_INET, host.c_str(), &addr.sin_addr);
    WB_CHECK(::connect(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == 0);
    const std::string req = "GET " + path + " HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";
    ::send(fd, req.data(), req.size(), 0);
    std::string out;
    char buf[2048];
    while (true) {
        const ssize_t n = ::recv(fd, buf, sizeof(buf), 0);
        if (n <= 0) {
            break;
        }
        out.append(buf, static_cast<std::size_t>(n));
    }
    ::close(fd);
    return out;
}

int main() {
    wirebone::Config cfg;
    cfg.listen = "127.0.0.1:0";
    cfg.dns_listen.clear();
    cfg.state_path.clear();
    wirebone::Coordinator c(cfg);
    c.run_async();
    for (int i = 0; i < 50 && c.bound_address().empty(); ++i) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    const auto bound = c.bound_address();
    WB_CHECK(!bound.empty());
    const auto colon = bound.rfind(':');
    const auto port = static_cast<std::uint16_t>(std::stoi(bound.substr(colon + 1)));
    const auto res = http_get("127.0.0.1", port, "/key?v=131");
    WB_CHECK(res.find("200") != std::string::npos);
    WB_CHECK(res.find("publicKey") != std::string::npos);
    WB_CHECK(res.find("mkey:") != std::string::npos);
    const auto health = http_get("127.0.0.1", port, "/healthz");
    WB_CHECK(health.find("ok") != std::string::npos);
    c.stop();
    return 0;
}
