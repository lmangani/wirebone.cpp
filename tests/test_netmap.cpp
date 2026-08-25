#include "netmap.hpp"
#include "test_assert.hpp"

#include <string>
#include <vector>

namespace {

wirebone::NodeState node(std::uint64_t id, const char* host, const char* v4, const char* token,
                         bool shared) {
    wirebone::NodeState n;
    n.id = id;
    n.stable_id = std::to_string(id);
    n.hostname = host;
    n.ipv4 = v4;
    n.ipv6 = "fd7a:115c:a1e0::" + std::to_string(id);
    n.token = token;
    n.shared = shared;
    n.node_key = "nodekey:" + std::string(host);
    n.machine_key = "mkey:" + std::string(host);
    return n;
}

std::vector<std::string> peer_hosts(const nlohmann::json& map) {
    std::vector<std::string> out;
    for (const auto& p : map["Peers"]) {
        std::string name = p.value("Name", "");
        auto dot = name.find('.');
        out.push_back(dot == std::string::npos ? name : name.substr(0, dot));
    }
    return out;
}

bool has_host(const std::vector<std::string>& hosts, const char* want) {
    for (const auto& h : hosts) {
        if (h == want) {
            return true;
        }
    }
    return false;
}

bool dns_has(const nlohmann::json& map, const char* host) {
    const std::string needle = std::string(host) + ".quackscale.local";
    for (const auto& rec : map["DNSConfig"]["ExtraRecords"]) {
        if (rec.value("Name", "") == needle && rec.value("Type", "") == "A") {
            return true;
        }
    }
    return false;
}

bool filter_has_ip(const nlohmann::json& map, const char* ip) {
    const std::string needle(ip);
    for (const auto& rule : map["PacketFilter"]) {
        for (const auto& src : rule["SrcIPs"]) {
            if (src.get<std::string>().find(needle) != std::string::npos) {
                return true;
            }
        }
    }
    return false;
}

}  // namespace

int main() {
    const auto hub = node(1, "analytics-hub", "100.64.0.1", "", true);
    const auto a1 = node(2, "analyst-1", "100.64.0.2", "alpha", false);
    const auto a2 = node(3, "analyst-2", "100.64.0.3", "alpha", false);
    const auto b1 = node(4, "etl-1", "100.64.0.4", "beta", false);
    const std::vector<wirebone::NodeState> all{hub, a1, a2, b1};

    WB_CHECK(wirebone::node_visible_to(hub, a1));
    WB_CHECK(wirebone::node_visible_to(a1, hub));
    WB_CHECK(wirebone::node_visible_to(a1, a2));
    WB_CHECK(!wirebone::node_visible_to(a1, b1));
    WB_CHECK(!wirebone::node_visible_to(b1, a1));
    WB_CHECK(wirebone::node_visible_to(hub, b1));

    const auto map_a1 = wirebone::build_full_map(a1, all, "quackscale.local");
    const auto peers_a1 = peer_hosts(map_a1);
    WB_CHECK(has_host(peers_a1, "analytics-hub"));
    WB_CHECK(has_host(peers_a1, "analyst-2"));
    WB_CHECK(!has_host(peers_a1, "etl-1"));
    WB_CHECK(dns_has(map_a1, "analytics-hub"));
    WB_CHECK(dns_has(map_a1, "analyst-1"));
    WB_CHECK(dns_has(map_a1, "analyst-2"));
    WB_CHECK(!dns_has(map_a1, "etl-1"));
    WB_CHECK(filter_has_ip(map_a1, "100.64.0.1"));
    WB_CHECK(filter_has_ip(map_a1, "100.64.0.2"));
    WB_CHECK(filter_has_ip(map_a1, "100.64.0.3"));
    WB_CHECK(!filter_has_ip(map_a1, "100.64.0.4"));

    const auto map_b1 = wirebone::build_full_map(b1, all, "quackscale.local");
    const auto peers_b1 = peer_hosts(map_b1);
    WB_CHECK(has_host(peers_b1, "analytics-hub"));
    WB_CHECK(!has_host(peers_b1, "analyst-1"));
    WB_CHECK(!has_host(peers_b1, "analyst-2"));
    WB_CHECK(dns_has(map_b1, "etl-1"));
    WB_CHECK(!dns_has(map_b1, "analyst-1"));

    const auto map_hub = wirebone::build_full_map(hub, all, "quackscale.local");
    const auto peers_hub = peer_hosts(map_hub);
    WB_CHECK(has_host(peers_hub, "analyst-1"));
    WB_CHECK(has_host(peers_hub, "analyst-2"));
    WB_CHECK(has_host(peers_hub, "etl-1"));
    WB_CHECK(filter_has_ip(map_hub, "100.64.0.4"));

    // Untagged keys (legacy / no token) stay one flat group and remain shared.
    const auto legacy = node(5, "old-client", "100.64.0.5", "", true);
    WB_CHECK(wirebone::node_visible_to(a1, legacy));
    WB_CHECK(wirebone::node_visible_to(legacy, a1));
    WB_CHECK(wirebone::node_visible_to(legacy, b1));

    return 0;
}
