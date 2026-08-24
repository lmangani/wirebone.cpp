#include "state.hpp"
#include "test_assert.hpp"

#include <filesystem>
#include <unistd.h>

int main() {
    const std::string path = "/tmp/wirebone-test-state-" + std::to_string(getpid()) + ".json";
    std::filesystem::remove(path);
    {
        wirebone::Store s(path, "100.64.0.0/16", "fd7a:115c:a1e0::/48");
        const auto key = s.create_preauth_key(true, false, {});
        WB_CHECK(key.find("wbkey-") == 0);
        bool eph = false;
        WB_CHECK(s.consume_preauth(key, eph));
        const auto n = s.register_node("mkey:aa", "nodekey:bb", "alice", false);
        WB_CHECK(n.ipv4 == "100.64.0.1");
        WB_CHECK(n.hostname == "alice");
    }
    {
        wirebone::Store s(path, "100.64.0.0/16", "fd7a:115c:a1e0::/48");
        auto n = s.find_by_machine("mkey:aa");
        WB_CHECK(n.has_value());
        WB_CHECK(n->ipv4 == "100.64.0.1");
        WB_CHECK(n->hostname == "alice");
    }
    std::filesystem::remove(path);

    {
        wirebone::Store a("", "100.64.0.0/16", "fd7a:115c:a1e0::/48");
        a.create_preauth_key(true, false, {});
        a.register_node("mkey:cc", "nodekey:dd", "bob", false);
        const auto snap = a.dump_json();
        wirebone::Store b("", "100.64.0.0/16", "fd7a:115c:a1e0::/48");
        b.load_json(snap);
        auto n = b.find_by_machine("mkey:cc");
        WB_CHECK(n.has_value());
        WB_CHECK(n->hostname == "bob");
        WB_CHECK(b.preauth_keys().size() == a.preauth_keys().size());
    }
    return 0;
}
