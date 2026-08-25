#include "state.hpp"

#include <fstream>
#include <optional>
#include <random>
#include <sstream>
#include <stdexcept>

namespace wirebone {
namespace {

std::string random_token() {
    Bytes32 raw{};
    random_bytes(raw);
    return "wbkey-" + hex_encode(raw);
}

std::int64_t now_unix() {
    return std::chrono::duration_cast<std::chrono::seconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

PreauthKey key_from_json(const nlohmann::json& k) {
    PreauthKey p;
    p.key = k.value("key", "");
    p.reusable = k.value("reusable", true);
    p.ephemeral = k.value("ephemeral", false);
    p.used = k.value("used", false);
    p.expires_unix = k.value("expires_unix", 0);
    p.token = k.value("token", "");
    p.shared = k.value("shared", p.token.empty());
    return p;
}

bool resolve_shared(const std::string& token, std::optional<bool> shared) {
    return shared.value_or(token.empty());
}

}  // namespace

nlohmann::json user_profile() {
    return nlohmann::json{
        {"ID", 1},
        {"DisplayName", "wirebone"},
        {"ProfilePicURL", ""},
    };
}

nlohmann::json login_profile() {
    return nlohmann::json{
        {"ID", 1},
        {"Provider", "wirebone"},
        {"LoginName", "wirebone@local"},
        {"DisplayName", "wirebone"},
        {"ProfilePicURL", ""},
    };
}

Store::Store(std::string path, std::string ipv4_cidr, std::string ipv6_cidr)
    : path_(std::move(path)), alloc_(std::move(ipv4_cidr), std::move(ipv6_cidr)) {
    load_or_init();
}

void Store::load_or_init() {
    std::lock_guard<std::mutex> lock(mu_);
    if (!path_.empty()) {
        std::ifstream in(path_);
        if (in) {
            nlohmann::json j;
            in.seekg(0, std::ios::end);
            if (in.tellg() <= 0) {
                // empty file from mktemp / first create
            } else {
                in.seekg(0);
                in >> j;
                apply_snapshot_locked(j);
            }
        }
    }
    if (noise_private_ == Bytes32{}) {
        noise_private_ = generate_x25519_private();
        save_locked();
    }
}

nlohmann::json Store::snapshot_locked() const {
    nlohmann::json j;
    j["noise_private"] = hex_encode(noise_private_);
    j["next_node_id"] = next_node_id_;
    j["next_ip_index"] = next_ip_index_;
    j["preauth_keys"] = nlohmann::json::array();
    for (const auto& k : keys_) {
        j["preauth_keys"].push_back({
            {"key", k.key},
            {"reusable", k.reusable},
            {"ephemeral", k.ephemeral},
            {"used", k.used},
            {"expires_unix", k.expires_unix},
            {"token", k.token},
            {"shared", k.shared},
        });
    }
    j["nodes"] = nlohmann::json::array();
    for (const auto& n : nodes_) {
        j["nodes"].push_back({
            {"id", n.id},
            {"stable_id", n.stable_id},
            {"hostname", n.hostname},
            {"machine_key", n.machine_key},
            {"node_key", n.node_key},
            {"disco_key", n.disco_key},
            {"ipv4", n.ipv4},
            {"ipv6", n.ipv6},
            {"endpoints", n.endpoints},
            {"ephemeral", n.ephemeral},
            {"online", n.online},
            {"token", n.token},
            {"shared", n.shared},
        });
    }
    return j;
}

void Store::apply_snapshot_locked(const nlohmann::json& j) {
    Bytes32 priv{};
    if (j.contains("noise_private") && hex_decode(j["noise_private"].get<std::string>(), priv)) {
        noise_private_ = priv;
    }
    next_node_id_ = j.value("next_node_id", 1);
    next_ip_index_ = j.value("next_ip_index", 1);
    keys_.clear();
    if (j.contains("preauth_keys")) {
        for (const auto& k : j["preauth_keys"]) {
            keys_.push_back(key_from_json(k));
        }
    }
    nodes_.clear();
    if (j.contains("nodes")) {
        for (const auto& n : j["nodes"]) {
            NodeState node;
            node.id = n.value("id", 0);
            node.stable_id = n.value("stable_id", "");
            node.hostname = n.value("hostname", "");
            node.machine_key = n.value("machine_key", "");
            node.node_key = n.value("node_key", "");
            node.disco_key = n.value("disco_key", "");
            node.ipv4 = n.value("ipv4", "");
            node.ipv6 = n.value("ipv6", "");
            node.ephemeral = n.value("ephemeral", false);
            node.online = n.value("online", false);
            node.token = n.value("token", "");
            node.shared = n.value("shared", node.token.empty());
            if (n.contains("endpoints")) {
                node.endpoints = n["endpoints"].get<std::vector<std::string>>();
            }
            nodes_.push_back(std::move(node));
        }
    }
}

void Store::save_locked() {
    const auto j = snapshot_locked();
    if (!path_.empty()) {
        const std::string tmp = path_ + ".tmp";
        {
            std::ofstream out(tmp, std::ios::trunc);
            if (!out) {
                throw std::runtime_error("cannot write state file " + tmp);
            }
            out << j.dump(2) << '\n';
        }
        if (std::rename(tmp.c_str(), path_.c_str()) != 0) {
            throw std::runtime_error("cannot replace state file " + path_);
        }
    }
    if (persist_hook_) {
        persist_hook_(j.dump());
    }
}

std::string Store::dump_json() const {
    std::lock_guard<std::mutex> lock(mu_);
    return snapshot_locked().dump();
}

void Store::load_json(const std::string& json) {
    const auto j = nlohmann::json::parse(json.empty() ? "{}" : json);
    std::lock_guard<std::mutex> lock(mu_);
    apply_snapshot_locked(j);
}

void Store::set_persist_hook(std::function<void(const std::string& json)> hook) {
    std::lock_guard<std::mutex> lock(mu_);
    persist_hook_ = std::move(hook);
}

void Store::persist() {
    std::lock_guard<std::mutex> lock(mu_);
    save_locked();
}

Bytes32 Store::noise_private() const {
    std::lock_guard<std::mutex> lock(mu_);
    return noise_private_;
}

std::string Store::noise_public_text() const {
    std::lock_guard<std::mutex> lock(mu_);
    return format_key(KeyKind::Machine, x25519_public(noise_private_));
}

std::string Store::create_preauth_key(bool reusable, bool ephemeral,
                                      std::chrono::seconds expiration, std::string token,
                                      std::optional<bool> shared) {
    std::lock_guard<std::mutex> lock(mu_);
    PreauthKey k;
    k.key = random_token();
    k.reusable = reusable;
    k.ephemeral = ephemeral;
    k.token = std::move(token);
    k.shared = resolve_shared(k.token, shared);
    if (expiration.count() > 0) {
        k.expires_unix = now_unix() + expiration.count();
    }
    keys_.push_back(k);
    save_locked();
    return k.key;
}

std::vector<PreauthKey> Store::preauth_keys() const {
    std::lock_guard<std::mutex> lock(mu_);
    return keys_;
}

void Store::reload_keys_from_disk() {
    if (path_.empty()) {
        return;
    }
    std::ifstream in(path_);
    if (!in) {
        return;
    }
    nlohmann::json j;
    try {
        in >> j;
    } catch (...) {
        return;
    }
    if (!j.contains("preauth_keys")) {
        return;
    }
    std::lock_guard<std::mutex> lock(mu_);
    keys_.clear();
    for (const auto& k : j["preauth_keys"]) {
        keys_.push_back(key_from_json(k));
    }
}

bool Store::consume_preauth(const std::string& key, bool& ephemeral) {
    PreauthClaim claim;
    if (!consume_preauth(key, claim)) {
        return false;
    }
    ephemeral = claim.ephemeral;
    return true;
}

bool Store::consume_preauth(const std::string& key, PreauthClaim& claim) {
    reload_keys_from_disk();
    std::lock_guard<std::mutex> lock(mu_);
    const auto now = now_unix();
    for (auto& k : keys_) {
        if (k.key != key) {
            continue;
        }
        if (k.expires_unix != 0 && now > k.expires_unix) {
            return false;
        }
        if (!k.reusable && k.used) {
            return false;
        }
        k.used = true;
        claim.ephemeral = k.ephemeral;
        claim.token = k.token;
        claim.shared = k.shared;
        save_locked();
        return true;
    }
    return false;
}

NodeState Store::register_node(const std::string& machine_key, const std::string& node_key,
                               const std::string& hostname, bool ephemeral, std::string token,
                               bool shared) {
    std::lock_guard<std::mutex> lock(mu_);
    for (auto& n : nodes_) {
        if (n.machine_key == machine_key) {
            n.node_key = node_key;
            if (!hostname.empty()) {
                n.hostname = hostname;
            }
            n.ephemeral = ephemeral;
            save_locked();
            return n;
        }
    }
    NodeState n;
    n.id = next_node_id_++;
    n.stable_id = std::to_string(n.id);
    n.hostname = hostname.empty() ? ("node-" + n.stable_id) : hostname;
    n.machine_key = machine_key;
    n.node_key = node_key;
    n.ephemeral = ephemeral;
    n.token = std::move(token);
    n.shared = shared;
    const auto [v4, v6] = alloc_.address_for(next_ip_index_++);
    n.ipv4 = v4;
    n.ipv6 = v6;
    nodes_.push_back(n);
    save_locked();
    return n;
}

std::optional<NodeState> Store::find_by_machine(const std::string& machine_key) const {
    std::lock_guard<std::mutex> lock(mu_);
    for (const auto& n : nodes_) {
        if (n.machine_key == machine_key) {
            return n;
        }
    }
    return std::nullopt;
}

std::optional<NodeState> Store::find_by_node(const std::string& node_key) const {
    std::lock_guard<std::mutex> lock(mu_);
    for (const auto& n : nodes_) {
        if (n.node_key == node_key) {
            return n;
        }
    }
    return std::nullopt;
}

std::vector<NodeState> Store::nodes() const {
    std::lock_guard<std::mutex> lock(mu_);
    return nodes_;
}

void Store::update_map_info(const std::string& machine_key, const std::string& node_key,
                            const std::string& disco_key, const std::string& hostname,
                            const std::vector<std::string>& endpoints) {
    std::lock_guard<std::mutex> lock(mu_);
    for (auto& n : nodes_) {
        if (n.machine_key != machine_key) {
            continue;
        }
        if (!node_key.empty()) {
            n.node_key = node_key;
        }
        if (!disco_key.empty()) {
            n.disco_key = disco_key;
        }
        if (!hostname.empty()) {
            n.hostname = hostname;
        }
        n.endpoints = endpoints;
        n.online = true;
        save_locked();
        return;
    }
}

void Store::set_online(const std::string& machine_key, bool online) {
    std::lock_guard<std::mutex> lock(mu_);
    for (auto& n : nodes_) {
        if (n.machine_key == machine_key) {
            n.online = online;
            return;
        }
    }
}

}  // namespace wirebone
