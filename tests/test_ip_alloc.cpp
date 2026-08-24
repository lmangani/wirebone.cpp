#include "ip_alloc.hpp"
#include "test_assert.hpp"

int main() {
    wirebone::IpAllocator a("100.64.0.0/16", "fd7a:115c:a1e0::/48");
    const auto [v4, v6] = a.address_for(1);
    WB_CHECK(v4 == "100.64.0.1");
    WB_CHECK(v6.find("fd7a:115c:a1e0") == 0);
    const auto [v4b, v6b] = a.address_for(2);
    WB_CHECK(v4b == "100.64.0.2");
    WB_CHECK(v4 != v4b);
    return 0;
}
