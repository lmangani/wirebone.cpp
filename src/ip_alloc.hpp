#pragma once

#include <cstdint>
#include <string>
#include <utility>

namespace wirebone {

class IpAllocator {
public:
    IpAllocator(std::string ipv4_cidr, std::string ipv6_cidr);

    // index 1 => first host address. index 0 is reserved.
    std::pair<std::string, std::string> address_for(std::uint32_t index) const;
    std::uint32_t max_index() const { return ipv4_hosts_; }

    const std::string& ipv4_cidr() const { return ipv4_cidr_; }
    const std::string& ipv6_cidr() const { return ipv6_cidr_; }

private:
    std::string ipv4_cidr_;
    std::string ipv6_cidr_;
    std::uint32_t ipv4_base_ = 0;
    int ipv4_prefix_ = 16;
    std::uint32_t ipv4_hosts_ = 0;
    std::uint8_t ipv6_base_[16]{};
    int ipv6_prefix_ = 48;
};

}  // namespace wirebone
