#include "netmap.hpp"

#include <zstd.h>
// DuckDB vendors zstd.h inside namespace duckdb_zstd (same include guard as
// upstream). Standalone builds see the global C API.
#if defined(WIREBONE_DUCKDB_ZSTD)
using duckdb_zstd::ZSTD_compress;
using duckdb_zstd::ZSTD_compressBound;
using duckdb_zstd::ZSTD_isError;
#endif

#include <chrono>
#include <cstring>
#include <ctime>
#include <stdexcept>

namespace wirebone {

std::string rfc3339_now() {
    const auto now = std::chrono::system_clock::now();
    const std::time_t t = std::chrono::system_clock::to_time_t(now);
    std::tm tm{};
    gmtime_r(&t, &tm);
    char buf[64];
    std::strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", &tm);
    return buf;
}

nlohmann::json node_to_tailcfg(const NodeState& node, const std::string& domain, bool self) {
    std::string name = node.hostname;
    if (name.empty()) {
        name = "node-" + node.stable_id;
    }
    if (name.back() != '.') {
        name += "." + domain + ".";
    }
    nlohmann::json j;
    j["ID"] = node.id;
    j["StableID"] = node.stable_id;
    j["Name"] = name;
    j["User"] = 1;
    j["Key"] = node.node_key;
    j["Machine"] = node.machine_key;
    if (!node.disco_key.empty()) {
        j["DiscoKey"] = node.disco_key;
    }
    j["Addresses"] = nlohmann::json::array({node.ipv4 + "/32", node.ipv6 + "/128"});
    j["AllowedIPs"] = j["Addresses"];
    if (!node.endpoints.empty()) {
        j["Endpoints"] = node.endpoints;
    }
    j["HomeDERP"] = 0;
    j["Created"] = rfc3339_now();
    j["MachineAuthorized"] = true;
    j["Online"] = node.online || self;
    j["Cap"] = 131;
    // tsnet Status() dereferences Hostinfo; a missing object panics the localapi.
    j["Hostinfo"] = nlohmann::json{{"Hostname", node.hostname}};
    return j;
}

nlohmann::json build_register_response() {
    return nlohmann::json{
        {"User", user_profile()},
        {"Login", login_profile()},
        {"NodeKeyExpired", false},
        {"MachineAuthorized", true},
        {"AuthURL", ""},
        {"Error", ""},
    };
}

// Tailscale public DERP snapshot so a lone node can leave Starting
// (Running requires NumLive>0 or LiveDERPs>0). Custom control servers do
// not inherit compiled-in defaults unless we send a DERPMap.
nlohmann::json default_derp_map() {
    auto region = [](int id, const char* code, const char* name, const char* node,
                     const char* host, const char* ipv4) {
        return nlohmann::json{
            {"RegionID", id},
            {"RegionCode", code},
            {"RegionName", name},
            {"Nodes", nlohmann::json::array({nlohmann::json{
                {"Name", node},
                {"RegionID", id},
                {"HostName", host},
                {"IPv4", ipv4},
                {"CanPort80", true},
            }})},
        };
    };
    return nlohmann::json{
        {"omitDefaultRegions", true},
        {"Regions",
         {
             {"1", region(1, "nyc", "New York City", "1f", "derp1f.tailscale.com", "199.38.181.104")},
             {"2", region(2, "sfo", "San Francisco", "2d", "derp2d.tailscale.com", "192.73.252.65")},
             {"4", region(4, "fra", "Frankfurt", "4f", "derp4f.tailscale.com", "185.40.234.219")},
             {"8", region(8, "lhr", "London", "8e", "derp8e.tailscale.com", "176.58.92.144")},
         }},
    };
}

nlohmann::json build_full_map(const NodeState& self, const std::vector<NodeState>& all,
                              const std::string& domain) {
    nlohmann::json peers = nlohmann::json::array();
    for (const auto& n : all) {
        if (n.id == self.id) {
            continue;
        }
        peers.push_back(node_to_tailcfg(n, domain, false));
    }
    const std::string now = rfc3339_now();
    nlohmann::json allow = nlohmann::json::array({nlohmann::json{
        {"SrcIPs", nlohmann::json::array({"*"})},
        {"DstPorts",
         nlohmann::json::array({nlohmann::json{{"IP", "*"}, {"Ports", {{"First", 0}, {"Last", 65535}}}}})},
    }});
    nlohmann::json resp;
    resp["KeepAlive"] = false;
    resp["ControlTime"] = now;
    resp["Node"] = node_to_tailcfg(self, domain, true);
    resp["DERPMap"] = default_derp_map();
    resp["Peers"] = peers;
    nlohmann::json extra = nlohmann::json::array();
    for (const auto& n : all) {
        std::string host = n.hostname.empty() ? ("node-" + n.stable_id) : n.hostname;
        extra.push_back(nlohmann::json{{"Name", host + "." + domain}, {"Type", "A"}, {"Value", n.ipv4}});
        extra.push_back(
            nlohmann::json{{"Name", host + "." + domain}, {"Type", "AAAA"}, {"Value", n.ipv6}});
    }
    resp["DNSConfig"] = nlohmann::json{
        {"Resolvers", nlohmann::json::array()},
        {"FallbackResolvers", nlohmann::json::array()},
        {"Domains", nlohmann::json::array({domain})},
        {"Proxied", true},
        {"Routes", {{domain, nlohmann::json::array()}}},
        {"ExtraRecords", extra},
    };
    resp["Domain"] = domain;
    resp["PacketFilter"] = allow;
    resp["UserProfiles"] = nlohmann::json::array({nlohmann::json{
        {"ID", 1},
        {"LoginName", "wirebone@local"},
        {"DisplayName", "wirebone"},
    }});
    return resp;
}

nlohmann::json build_keepalive() {
    return nlohmann::json{
        {"KeepAlive", true},
        {"ControlTime", rfc3339_now()},
    };
}

std::vector<std::uint8_t> encode_map_frame(const nlohmann::json& msg, bool zstd) {
    (void)zstd;
    // Clients always zstd-decode map frames (controlclient.decodeMsg).
    const std::string json = msg.dump();
    std::vector<std::uint8_t> payload(json.begin(), json.end());
    {
        const std::size_t bound = ZSTD_compressBound(payload.size());
        std::vector<std::uint8_t> compressed(bound);
        const std::size_t n =
            ZSTD_compress(compressed.data(), bound, payload.data(), payload.size(), 1);
        if (ZSTD_isError(n)) {
            throw std::runtime_error("zstd compress failed");
        }
        compressed.resize(n);
        payload.swap(compressed);
    }
    std::vector<std::uint8_t> framed(4 + payload.size());
    const std::uint32_t len = static_cast<std::uint32_t>(payload.size());
    framed[0] = static_cast<std::uint8_t>(len);
    framed[1] = static_cast<std::uint8_t>(len >> 8);
    framed[2] = static_cast<std::uint8_t>(len >> 16);
    framed[3] = static_cast<std::uint8_t>(len >> 24);
    std::memcpy(framed.data() + 4, payload.data(), payload.size());
    return framed;
}

}  // namespace wirebone
