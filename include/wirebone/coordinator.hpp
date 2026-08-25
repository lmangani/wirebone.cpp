#pragma once

#include <chrono>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace wirebone {

struct Config {
    std::string listen = "0.0.0.0:8080";
    std::string server_url = "http://127.0.0.1:8080";
    std::string ip_prefix = "100.64.0.0/16";
    std::string ipv6_prefix = "fd7a:115c:a1e0::/48";
    std::string state_path;
    std::string domain = "wirebone.local";
    // UDP MagicDNS listener (empty disables). Answers A/AAAA for
    // hostname, hostname.domain, and FQDN from the node registry.
    std::string dns_listen = "0.0.0.0:5353";
    std::chrono::seconds keepalive{50};
};

struct PreauthOptions {
    bool reusable = true;
    bool ephemeral = false;
    std::chrono::seconds expiration{0};
    std::string token;
    // nullopt: shared when token is empty (hub / untagged keys).
    std::optional<bool> shared;
};

struct NodeInfo {
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
    std::string token;
    bool shared = false;
};

struct PreauthInfo {
    std::string key;
    bool reusable = true;
    bool ephemeral = false;
    bool used = false;
    std::string token;
    bool shared = false;
};

class Coordinator {
public:
    explicit Coordinator(Config cfg);
    ~Coordinator();

    Coordinator(const Coordinator&) = delete;
    Coordinator& operator=(const Coordinator&) = delete;

    std::string create_preauth_key(PreauthOptions opts = {});
    std::string bootstrap_preauth_key() const;
    std::vector<PreauthInfo> list_preauth_keys() const;
    std::vector<NodeInfo> list_nodes() const;
    std::string noise_public_key() const;

    void run();
    void run_async();
    void stop();
    bool running() const;

    // Bound listen address after run()/run_async() (host:port).
    std::string bound_address() const;

    std::string export_state() const;
    void import_state(std::string_view json);
    void set_persist_hook(std::function<void(std::string_view json)> hook);
    void persist();

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

}  // namespace wirebone
