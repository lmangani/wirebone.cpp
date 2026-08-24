#include "dns.hpp"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cctype>
#include <cstring>
#include <sstream>
#include <stdexcept>
#include <vector>

namespace wirebone {
namespace {

constexpr std::uint16_t kTypeA = 1;
constexpr std::uint16_t kTypeAAAA = 28;
constexpr std::uint16_t kTypeAny = 255;
constexpr std::uint16_t kClassIN = 1;

void put16(std::vector<std::uint8_t>& b, std::uint16_t v) {
    b.push_back(static_cast<std::uint8_t>(v >> 8));
    b.push_back(static_cast<std::uint8_t>(v));
}

void put32(std::vector<std::uint8_t>& b, std::uint32_t v) {
    b.push_back(static_cast<std::uint8_t>(v >> 24));
    b.push_back(static_cast<std::uint8_t>(v >> 16));
    b.push_back(static_cast<std::uint8_t>(v >> 8));
    b.push_back(static_cast<std::uint8_t>(v));
}

bool parse_qname(const std::uint8_t* msg, int len, int& off, std::string& name) {
    name.clear();
    int hops = 0;
    int jumped = 0;
    int end = off;
    while (off < len && hops++ < 16) {
        const std::uint8_t lab = msg[off];
        if (lab == 0) {
            ++off;
            if (!jumped) {
                end = off;
            }
            off = jumped ? end : off;
            if (!name.empty() && name.back() == '.') {
                name.pop_back();
            }
            return true;
        }
        if ((lab & 0xc0) == 0xc0) {
            if (off + 1 >= len) {
                return false;
            }
            const int ptr = ((lab & 0x3f) << 8) | msg[off + 1];
            if (!jumped) {
                end = off + 2;
            }
            off = ptr;
            jumped = 1;
            continue;
        }
        ++off;
        if (off + lab > len) {
            return false;
        }
        name.append(reinterpret_cast<const char*>(msg + off), lab);
        name.push_back('.');
        off += lab;
    }
    return false;
}

std::string lower_copy(std::string s) {
    for (char& c : s) {
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    }
    return s;
}

bool parse_hostport(const std::string& s, std::string& host, std::uint16_t& port) {
    const auto colon = s.rfind(':');
    if (colon == std::string::npos) {
        host = "0.0.0.0";
        port = static_cast<std::uint16_t>(std::stoi(s));
        return true;
    }
    host = s.substr(0, colon);
    if (host.empty()) {
        host = "0.0.0.0";
    }
    port = static_cast<std::uint16_t>(std::stoi(s.substr(colon + 1)));
    return true;
}

}  // namespace

MagicDns::MagicDns(Store& store, std::string domain, std::string listen)
    : store_(store), domain_(std::move(domain)), listen_(std::move(listen)) {}

MagicDns::~MagicDns() { stop(); }

void MagicDns::start() {
    if (listen_.empty()) {
        return;
    }
    std::string host;
    std::uint16_t port = 5353;
    parse_hostport(listen_, host, port);
    fd_ = ::socket(AF_INET, SOCK_DGRAM, 0);
    if (fd_ < 0) {
        throw std::runtime_error("dns socket");
    }
    int yes = 1;
    setsockopt(fd_, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    if (inet_pton(AF_INET, host.c_str(), &addr.sin_addr) != 1) {
        addr.sin_addr.s_addr = INADDR_ANY;
    }
    if (bind(fd_, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
        ::close(fd_);
        fd_ = -1;
        throw std::runtime_error("dns bind failed on " + listen_);
    }
    sockaddr_in bound{};
    socklen_t blen = sizeof(bound);
    getsockname(fd_, reinterpret_cast<sockaddr*>(&bound), &blen);
    char ip[INET_ADDRSTRLEN]{};
    inet_ntop(AF_INET, &bound.sin_addr, ip, sizeof(ip));
    bound_ = std::string(ip) + ":" + std::to_string(ntohs(bound.sin_port));
    stop_ = false;
    thread_ = std::thread([this] { loop(); });
}

void MagicDns::stop() {
    stop_ = true;
    if (fd_ >= 0) {
        ::shutdown(fd_, SHUT_RDWR);
        ::close(fd_);
        fd_ = -1;
    }
    if (thread_.joinable()) {
        thread_.join();
    }
}

void MagicDns::loop() {
    std::uint8_t buf[2048];
    while (!stop_) {
        sockaddr_in src{};
        socklen_t slen = sizeof(src);
        const ssize_t n =
            ::recvfrom(fd_, buf, sizeof(buf), 0, reinterpret_cast<sockaddr*>(&src), &slen);
        if (n <= 0) {
            if (stop_) {
                break;
            }
            continue;
        }
        std::vector<std::uint8_t> resp;
        if (!answer(buf, static_cast<int>(n), resp) || resp.empty()) {
            continue;
        }
        ::sendto(fd_, resp.data(), resp.size(), 0, reinterpret_cast<sockaddr*>(&src), slen);
    }
}

bool MagicDns::answer(const std::uint8_t* q, int qlen, std::vector<std::uint8_t>& resp) {
    if (qlen < 12) {
        return false;
    }
    const std::uint16_t flags = (q[2] << 8) | q[3];
    if (flags & 0x8000) {
        return false;
    }
    const int qd = (q[4] << 8) | q[5];
    if (qd < 1) {
        return false;
    }
    int off = 12;
    std::string qname;
    if (!parse_qname(q, qlen, off, qname)) {
        return false;
    }
    if (off + 4 > qlen) {
        return false;
    }
    const std::uint16_t qtype = (q[off] << 8) | q[off + 1];
    off += 4;
    const std::string want = lower_copy(qname);
    const std::string domain = lower_copy(domain_);

    const auto nodes = store_.nodes();
    struct Rec {
        std::string ipv4;
        std::string ipv6;
    };
    Rec rec;
    bool found = false;
    for (const auto& n : nodes) {
        std::string host = n.hostname.empty() ? ("node-" + n.stable_id) : n.hostname;
        host = lower_copy(host);
        const std::string fqdn = host + "." + domain;
        if (want == host || want == fqdn || want == fqdn + ".") {
            rec.ipv4 = n.ipv4;
            rec.ipv6 = n.ipv6;
            found = true;
            break;
        }
    }

    resp.assign(q, q + 12);
    resp[2] = 0x81;
    resp[3] = found ? 0x80 : 0x83;  // RA + rcode
    resp[4] = q[4];
    resp[5] = q[5];
    resp[6] = 0;
    resp[7] = 0;
    resp[8] = 0;
    resp[9] = 0;
    resp[10] = 0;
    resp[11] = 0;
    resp.insert(resp.end(), q + 12, q + off);

    if (!found) {
        return true;
    }

    auto add_rr = [&](std::uint16_t type, const std::uint8_t* data, int dlen) {
        resp.push_back(0xc0);
        resp.push_back(0x0c);
        put16(resp, type);
        put16(resp, kClassIN);
        put32(resp, 30);
        put16(resp, static_cast<std::uint16_t>(dlen));
        resp.insert(resp.end(), data, data + dlen);
    };

    int answers = 0;
    if ((qtype == kTypeA || qtype == kTypeAny) && !rec.ipv4.empty()) {
        in_addr a4{};
        if (inet_pton(AF_INET, rec.ipv4.c_str(), &a4) == 1) {
            add_rr(kTypeA, reinterpret_cast<const std::uint8_t*>(&a4), 4);
            ++answers;
        }
    }
    if ((qtype == kTypeAAAA || qtype == kTypeAny) && !rec.ipv6.empty()) {
        in6_addr a6{};
        if (inet_pton(AF_INET6, rec.ipv6.c_str(), &a6) == 1) {
            add_rr(kTypeAAAA, a6.s6_addr, 16);
            ++answers;
        }
    }
    resp[6] = static_cast<std::uint8_t>(answers >> 8);
    resp[7] = static_cast<std::uint8_t>(answers);
    return true;
}

}  // namespace wirebone
