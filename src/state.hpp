#pragma once

#include "crypto.hpp"
#include "ip_alloc.hpp"
#include "keys.hpp"

#include <nlohmann/json.hpp>

#include <chrono>
#include <cstdint>
#include <functional>
#include <mutex>
#include <optional>
#include <string>
#include <vector>

namespace wirebone {

struct PreauthKey {
    std::string key;
    bool reusable = true;
    bool ephemeral = false;
    bool used = false;
    std::int64_t expires_unix = 0;
    // Mesh group id. Same string as the Quack token is the intended operator model.
    std::string token;
    // Visible to every group (the hub). Default true when token is empty.
    bool shared = false;
};

struct PreauthClaim {
    bool ephemeral = false;
    std::string token;
    bool shared = false;
};

struct NodeState {
    std::uint64_t id = 0;
    std::string stable_id;
    std::string hostname;
    std::string machine_key;
    std::string node_key;
    std::string disco_key;
    std::string ipv4;
    std::string ipv6;
    std::vector<std::string> endpoints;
    bool online = false;
    bool ephemeral = false;
    std::string token;
    bool shared = false;
};

class Store {
public:
    Store(std::string path, std::string ipv4_cidr, std::string ipv6_cidr);

    Bytes32 noise_private() const;
    std::string noise_public_text() const;

    std::string create_preauth_key(bool reusable, bool ephemeral, std::chrono::seconds expiration,
                                   std::string token = {}, std::optional<bool> shared = std::nullopt);
    std::vector<PreauthKey> preauth_keys() const;
    bool consume_preauth(const std::string& key, bool& ephemeral);
    bool consume_preauth(const std::string& key, PreauthClaim& claim);
    void reload_keys_from_disk();

    NodeState register_node(const std::string& machine_key, const std::string& node_key,
                            const std::string& hostname, bool ephemeral, std::string token = {},
                            bool shared = false);
    std::optional<NodeState> find_by_machine(const std::string& machine_key) const;
    std::optional<NodeState> find_by_node(const std::string& node_key) const;
    std::vector<NodeState> nodes() const;

    void update_map_info(const std::string& machine_key, const std::string& node_key,
                         const std::string& disco_key, const std::string& hostname,
                         const std::vector<std::string>& endpoints);
    void set_online(const std::string& machine_key, bool online);

    void persist();

    std::string dump_json() const;
    void load_json(const std::string& json);
    void set_persist_hook(std::function<void(const std::string& json)> hook);

private:
    void load_or_init();
    void save_locked();
    nlohmann::json snapshot_locked() const;
    void apply_snapshot_locked(const nlohmann::json& j);

    std::function<void(const std::string&)> persist_hook_;

    mutable std::mutex mu_;
    std::string path_;
    IpAllocator alloc_;
    Bytes32 noise_private_{};
    std::uint64_t next_node_id_ = 1;
    std::uint32_t next_ip_index_ = 1;
    std::vector<PreauthKey> keys_;
    std::vector<NodeState> nodes_;
};

nlohmann::json user_profile();
nlohmann::json login_profile();

}  // namespace wirebone
