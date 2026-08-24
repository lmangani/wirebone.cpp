#include "ip_alloc.hpp"

#include <arpa/inet.h>
#include <netinet/in.h>

#include <cstring>
#include <stdexcept>

namespace wirebone {
namespace {

bool parse_cidr(const std::string& cidr, in_addr& addr, int& prefix) {
    const auto slash = cidr.find('/');
    if (slash == std::string::npos) {
        return false;
    }
    const std::string ip = cidr.substr(0, slash);
    prefix = std::stoi(cidr.substr(slash + 1));
    if (prefix < 0 || prefix > 32) {
        return false;
    }
    return inet_pton(AF_INET, ip.c_str(), &addr) == 1;
}

bool parse_cidr6(const std::string& cidr, in6_addr& addr, int& prefix) {
    const auto slash = cidr.find('/');
    if (slash == std::string::npos) {
        return false;
    }
    const std::string ip = cidr.substr(0, slash);
    prefix = std::stoi(cidr.substr(slash + 1));
    if (prefix < 0 || prefix > 128) {
        return false;
    }
    return inet_pton(AF_INET6, ip.c_str(), &addr) == 1;
}

std::string ipv4_to_string(std::uint32_t host_order) {
    in_addr a{};
    a.s_addr = htonl(host_order);
    char buf[INET_ADDRSTRLEN]{};
    inet_ntop(AF_INET, &a, buf, sizeof(buf));
    return buf;
}

std::string ipv6_to_string(const std::uint8_t raw[16]) {
    char buf[INET6_ADDRSTRLEN]{};
    inet_ntop(AF_INET6, raw, buf, sizeof(buf));
    return buf;
}

}  // namespace

IpAllocator::IpAllocator(std::string ipv4_cidr, std::string ipv6_cidr)
    : ipv4_cidr_(std::move(ipv4_cidr)), ipv6_cidr_(std::move(ipv6_cidr)) {
    in_addr a4{};
    if (!parse_cidr(ipv4_cidr_, a4, ipv4_prefix_)) {
        throw std::runtime_error("invalid ipv4 prefix: " + ipv4_cidr_);
    }
    const std::uint32_t mask = ipv4_prefix_ == 0 ? 0 : (~0u << (32 - ipv4_prefix_));
    ipv4_base_ = ntohl(a4.s_addr) & mask;
    ipv4_hosts_ = ipv4_prefix_ >= 32 ? 0 : ((1u << (32 - ipv4_prefix_)) - 1);

    in6_addr a6{};
    if (!parse_cidr6(ipv6_cidr_, a6, ipv6_prefix_)) {
        throw std::runtime_error("invalid ipv6 prefix: " + ipv6_cidr_);
    }
    std::memcpy(ipv6_base_, a6.s6_addr, 16);
}

std::pair<std::string, std::string> IpAllocator::address_for(std::uint32_t index) const {
    if (index == 0 || index > ipv4_hosts_) {
        throw std::runtime_error("ip index out of range");
    }
    const std::string v4 = ipv4_to_string(ipv4_base_ + index);

    std::uint8_t v6[16];
    std::memcpy(v6, ipv6_base_, 16);
    // Place the host index in the last 4 bytes (Tailscale-style unique host).
    v6[12] = static_cast<std::uint8_t>(index >> 24);
    v6[13] = static_cast<std::uint8_t>(index >> 16);
    v6[14] = static_cast<std::uint8_t>(index >> 8);
    v6[15] = static_cast<std::uint8_t>(index);
    return {v4, ipv6_to_string(v6)};
}

}  // namespace wirebone
