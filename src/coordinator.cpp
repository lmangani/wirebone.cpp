#include "wirebone/coordinator.hpp"

#include "crypto.hpp"
#include "dns.hpp"
#include "http1.hpp"
#include "http2_session.hpp"
#include "keys.hpp"
#include "netmap.hpp"
#include "noise.hpp"
#include "state.hpp"

#include <nlohmann/json.hpp>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <atomic>
#include <chrono>
#include <cstring>
#include <iostream>
#include <mutex>
#include <stdexcept>
#include <thread>
#include <utility>

namespace wirebone {
namespace {

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

int listen_tcp(const std::string& spec, std::string& bound) {
    std::string host;
    std::uint16_t port = 8080;
    parse_hostport(spec, host, port);
    const int fd = ::socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        throw std::runtime_error("socket");
    }
    int yes = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
#ifdef SO_NOSIGPIPE
    setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &yes, sizeof(yes));
#endif
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    if (inet_pton(AF_INET, host.c_str(), &addr.sin_addr) != 1) {
        addr.sin_addr.s_addr = INADDR_ANY;
    }
    if (bind(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
        ::close(fd);
        throw std::runtime_error("bind failed on " + spec);
    }
    if (listen(fd, 128) != 0) {
        ::close(fd);
        throw std::runtime_error("listen");
    }
    sockaddr_in b{};
    socklen_t blen = sizeof(b);
    getsockname(fd, reinterpret_cast<sockaddr*>(&b), &blen);
    char ip[INET_ADDRSTRLEN]{};
    inet_ntop(AF_INET, &b.sin_addr, ip, sizeof(ip));
    bound = std::string(ip) + ":" + std::to_string(ntohs(b.sin_port));
    return fd;
}

std::string hostname_from_hostinfo(const nlohmann::json& req) {
    if (req.contains("Hostinfo") && req["Hostinfo"].is_object()) {
        return req["Hostinfo"].value("Hostname", "");
    }
    return {};
}

std::vector<std::string> endpoints_from_req(const nlohmann::json& req) {
    std::vector<std::string> out;
    if (req.contains("Endpoints") && req["Endpoints"].is_array()) {
        for (const auto& e : req["Endpoints"]) {
            if (e.is_string()) {
                out.push_back(e.get<std::string>());
            }
        }
    }
    return out;
}

struct LiveMap {
    int32_t stream_id = 0;
    std::string machine;
    bool zstd = false;
    std::uint64_t last_gen = 0;
    std::chrono::steady_clock::time_point last_send{};
};

}  // namespace

class Coordinator::Impl {
public:
    explicit Impl(Config cfg)
        : cfg_(std::move(cfg)), store_(cfg_.state_path, cfg_.ip_prefix, cfg_.ipv6_prefix) {
        if (store_.preauth_keys().empty()) {
            bootstrap_key_ = store_.create_preauth_key(true, false, std::chrono::seconds{0});
        }
    }

    ~Impl() { stop(); }

    std::string create_preauth_key(PreauthOptions opts) {
        return store_.create_preauth_key(opts.reusable, opts.ephemeral, opts.expiration, opts.token,
                                         opts.shared);
    }

    std::vector<PreauthInfo> list_preauth_keys() const {
        std::vector<PreauthInfo> out;
        for (const auto& k : store_.preauth_keys()) {
            out.push_back(PreauthInfo{k.key, k.reusable, k.ephemeral, k.used, k.token, k.shared});
        }
        return out;
    }

    std::vector<NodeInfo> list_nodes() const {
        std::vector<NodeInfo> out;
        for (const auto& n : store_.nodes()) {
            NodeInfo i;
            i.id = n.id;
            i.stable_id = n.stable_id;
            i.hostname = n.hostname;
            i.machine_key = n.machine_key;
            i.node_key = n.node_key;
            i.disco_key = n.disco_key;
            i.ipv4 = n.ipv4;
            i.ipv6 = n.ipv6;
            i.endpoints = n.endpoints;
            i.online = n.online;
            i.token = n.token;
            i.shared = n.shared;
            out.push_back(std::move(i));
        }
        return out;
    }

    std::string noise_public_key() const { return store_.noise_public_text(); }
    std::string bootstrap_key() const { return bootstrap_key_; }

    std::string export_state() const { return store_.dump_json(); }

    void import_state(std::string_view json) {
        store_.load_json(std::string(json));
        const auto keys = store_.preauth_keys();
        bootstrap_key_ = keys.empty() ? std::string() : keys.front().key;
    }

    void set_persist_hook(std::function<void(std::string_view)> hook) {
        store_.set_persist_hook([h = std::move(hook)](const std::string& json) {
            if (h) {
                h(json);
            }
        });
    }

    void persist() { store_.persist(); }

    void run() {
        start_listen();
        accept_loop();
    }

    void run_async() {
        start_listen();
        accept_thread_ = std::thread([this] { accept_loop(); });
    }

    void stop() {
        stop_ = true;
        if (listen_fd_ >= 0) {
            ::shutdown(listen_fd_, SHUT_RDWR);
            ::close(listen_fd_);
            listen_fd_ = -1;
        }
        if (dns_) {
            dns_->stop();
            dns_.reset();
        }
        if (accept_thread_.joinable()) {
            accept_thread_.join();
        }
        running_ = false;
    }

    bool running() const { return running_; }
    std::string bound() const { return bound_; }

    void bump_map() {
        std::lock_guard<std::mutex> g(map_mu_);
        ++map_gen_;
    }

    std::uint64_t map_gen() const {
        std::lock_guard<std::mutex> g(map_mu_);
        return map_gen_;
    }

private:
    void start_listen() {
        if (running_.exchange(true)) {
            throw std::runtime_error("coordinator already running");
        }
        stop_ = false;
        listen_fd_ = listen_tcp(cfg_.listen, bound_);
        if (!cfg_.dns_listen.empty()) {
            dns_ = std::make_unique<MagicDns>(store_, cfg_.domain, cfg_.dns_listen);
            dns_->start();
        }
    }

    void accept_loop() {
        while (!stop_) {
            sockaddr_in peer{};
            socklen_t plen = sizeof(peer);
            const int cfd = ::accept(listen_fd_, reinterpret_cast<sockaddr*>(&peer), &plen);
            if (cfd < 0) {
                if (stop_) {
                    break;
                }
                continue;
            }
            std::thread(&Impl::client_thread, this, cfd).detach();
        }
    }

    void client_thread(int fd) {
        bool close_fd = true;
        try {
            close_fd = handle_client(fd);
        } catch (const std::exception& ex) {
            std::cerr << "wirebone: client error: " << ex.what() << '\n';
        }
        if (close_fd && fd >= 0) {
            ::close(fd);
        }
    }

    // Returns true if the caller still owns fd.
    bool handle_client(int fd) {
        HttpRequest req;
        std::string extra;
        if (!read_http_request(fd, req, extra)) {
            return true;
        }
        if (req.path == "/key") {
            const auto body = nlohmann::json{
                {"legacyPublicKey", zero_machine_key()},
                {"publicKey", store_.noise_public_text()},
            }.dump();
            write_http_response(fd, 200, "OK", "application/json", body);
            return true;
        }
        if (req.path == "/healthz") {
            write_http_response(fd, 200, "OK", "text/plain", "ok\n");
            return true;
        }
        if (req.path == "/ts2021") {
            handle_ts2021(fd, req);
            return false;
        }
        write_http_response(fd, 404, "Not Found", "text/plain", "not found\n");
        return true;
    }

    void handle_ts2021(int fd, const HttpRequest& req) {
        const std::string upgrade = header_get(req, "upgrade");
        if (upgrade != "tailscale-control-protocol") {
            write_http_response(fd, 400, "Bad Request", "text/plain", "missing upgrade\n");
            ::close(fd);
            return;
        }
        const std::string init_b64 = header_get(req, "x-tailscale-handshake");
        if (init_b64.empty()) {
            write_http_response(fd, 400, "Bad Request", "text/plain", "missing handshake\n");
            ::close(fd);
            return;
        }
        std::vector<std::uint8_t> init;
        try {
            init = b64_decode(init_b64);
        } catch (...) {
            write_http_response(fd, 400, "Bad Request", "text/plain", "bad handshake\n");
            ::close(fd);
            return;
        }
        const std::string switching =
            "HTTP/1.1 101 Switching Protocols\r\n"
            "Upgrade: tailscale-control-protocol\r\n"
            "Connection: upgrade\r\n\r\n";
        if (!write_all(fd, switching)) {
            ::close(fd);
            return;
        }
        std::vector<std::uint8_t> resp;
        NoiseResult nr;
        std::string err;
        if (!noise_server_handshake(store_.noise_private(), init, resp, nr, err)) {
            ::close(fd);
            return;
        }
        if (!write_all(fd, std::string_view(reinterpret_cast<const char*>(resp.data()), resp.size()))) {
            ::close(fd);
            return;
        }

        const std::string machine = format_key(KeyKind::Machine, nr.peer_machine_public);
        NoiseConn nconn(fd, nr.tx_key, nr.rx_key);
        serve_h2(nconn, machine);
    }

    void serve_h2(NoiseConn& nconn, const std::string& machine_key) {
        H2Server h2(nconn);
        std::mutex live_mu;
        std::vector<LiveMap> live;

        h2.run(
            [&](int32_t sid, const std::string& method, const std::string& path,
                const std::string& body) {
                if (method != "POST") {
                    const std::string m = "method not allowed";
                    h2.reply(sid, 405, "text/plain", {m.begin(), m.end()});
                    return;
                }
                if (path == "/machine/register") {
                    on_register(sid, h2, machine_key, body);
                    return;
                }
                if (path == "/machine/map") {
                    on_map(sid, h2, machine_key, body, live, live_mu);
                    return;
                }
                const std::string m = "not found";
                h2.reply(sid, 404, "text/plain", {m.begin(), m.end()});
            },
            -1, {},
            [&] {
                const auto now = std::chrono::steady_clock::now();
                const auto gen = map_gen();
                std::lock_guard<std::mutex> g(live_mu);
                for (auto& m : live) {
                    if (gen != m.last_gen) {
                        auto self = store_.find_by_machine(m.machine);
                        if (self) {
                            h2.push_data(m.stream_id,
                                         encode_map_frame(build_full_map(*self, store_.nodes(),
                                                                         cfg_.domain),
                                                          m.zstd));
                        }
                        m.last_gen = gen;
                        m.last_send = now;
                        continue;
                    }
                    if (now - m.last_send >= cfg_.keepalive) {
                        h2.push_data(m.stream_id, encode_map_frame(build_keepalive(), m.zstd));
                        m.last_send = now;
                    }
                }
            });
        store_.set_online(machine_key, false);
        bump_map();
    }

    void on_register(int32_t sid, H2Server& h2, const std::string& machine_key,
                     const std::string& body) {
        nlohmann::json req;
        try {
            req = nlohmann::json::parse(body.empty() ? "{}" : body);
        } catch (...) {
            h2.reply(sid, 400, "application/json", {'{', '}'});
            return;
        }
        const std::string node_key = req.value("NodeKey", "");
        const std::string host = hostname_from_hostinfo(req);
        std::string auth;
        if (req.contains("Auth")) {
            if (req["Auth"].is_object()) {
                auth = req["Auth"].value("AuthKey", "");
                if (auth.empty()) {
                    auth = req["Auth"].value("authKey", "");
                }
            } else if (req["Auth"].is_string()) {
                auth = req["Auth"].get<std::string>();
            }
        }
        if (auth.empty()) {
            auth = req.value("AuthKey", "");
        }
        bool ephemeral = req.value("Ephemeral", false);
        PreauthClaim claim;
        if (!store_.find_by_machine(machine_key)) {
            if (auth.empty() || !store_.consume_preauth(auth, claim)) {
                const auto denied = nlohmann::json{
                    {"User", user_profile()},
                    {"Login", login_profile()},
                    {"MachineAuthorized", false},
                    {"Error", "invalid or missing preauth key"},
                }.dump();
                h2.reply(sid, 200, "application/json", {denied.begin(), denied.end()});
                return;
            }
            ephemeral = claim.ephemeral;
        }
        const auto node =
            store_.register_node(machine_key, node_key, host, ephemeral, claim.token, claim.shared);
        bump_map();
        std::cerr << "wirebone: register " << host << " " << node.ipv4;
        if (!node.token.empty()) {
            std::cerr << " token=" << node.token;
        }
        if (node.shared) {
            std::cerr << " shared";
        }
        std::cerr << '\n';
        const auto ok = build_register_response().dump();
        h2.reply(sid, 200, "application/json", {ok.begin(), ok.end()});
    }

    void on_map(int32_t sid, H2Server& h2, const std::string& machine_key, const std::string& body,
                std::vector<LiveMap>& live, std::mutex& live_mu) {
        nlohmann::json req;
        try {
            req = nlohmann::json::parse(body.empty() ? "{}" : body);
        } catch (...) {
            h2.reply(sid, 400, "application/json", {'{', '}'});
            return;
        }
        const int version = req.value("Version", 0);
        const bool stream = req.value("Stream", false);
        const bool omit_peers = req.value("OmitPeers", false);
        const bool zstd = req.value("Compress", "") == "zstd";
        const std::string node_key = req.value("NodeKey", "");
        const std::string disco_key = req.value("DiscoKey", "");
        const std::string host = hostname_from_hostinfo(req);
        const bool readonly = stream && version >= 68;
        if (!readonly) {
            store_.update_map_info(machine_key, node_key, disco_key, host, endpoints_from_req(req));
            bump_map();
        }
        store_.set_online(machine_key, true);

        if (omit_peers && !stream) {
            h2.reply(sid, 200, "application/json", {});
            return;
        }

        auto self = store_.find_by_machine(machine_key);
        if (!self) {
            const std::string m = "unauthorized";
            h2.reply(sid, 401, "text/plain", {m.begin(), m.end()});
            return;
        }
        const auto first = encode_map_frame(build_full_map(*self, store_.nodes(), cfg_.domain), zstd);
        std::cerr << "wirebone: map stream=" << stream << " omit=" << omit_peers
                  << " zstd=" << zstd << " host=" << self->hostname
                  << " bytes=" << first.size() << '\n';
        // One-shot framed body. A long-poll with no END_STREAM is a follow-up;
        // tsnet.Up only needs the first MapResponse to learn its 100.x address.
        if (!stream) {
            h2.reply(sid, 200, "application/json", first);
            return;
        }
        h2.reply_stream_start(sid, 200, first);
        std::lock_guard<std::mutex> g(live_mu);
        live.push_back(LiveMap{sid, machine_key, zstd, map_gen(), std::chrono::steady_clock::now()});
    }

    Config cfg_;
    Store store_;
    std::string bootstrap_key_;
    std::string bound_;
    int listen_fd_ = -1;
    std::atomic<bool> running_{false};
    std::atomic<bool> stop_{false};
    std::thread accept_thread_;
    std::unique_ptr<MagicDns> dns_;
    mutable std::mutex map_mu_;
    std::uint64_t map_gen_ = 1;
};

Coordinator::Coordinator(Config cfg) : impl_(std::make_unique<Impl>(std::move(cfg))) {}
Coordinator::~Coordinator() = default;

std::string Coordinator::create_preauth_key(PreauthOptions opts) {
    return impl_->create_preauth_key(opts);
}
std::string Coordinator::bootstrap_preauth_key() const { return impl_->bootstrap_key(); }
std::vector<PreauthInfo> Coordinator::list_preauth_keys() const {
    return impl_->list_preauth_keys();
}
std::vector<NodeInfo> Coordinator::list_nodes() const { return impl_->list_nodes(); }
std::string Coordinator::noise_public_key() const { return impl_->noise_public_key(); }
void Coordinator::run() { impl_->run(); }
void Coordinator::run_async() { impl_->run_async(); }
void Coordinator::stop() { impl_->stop(); }
bool Coordinator::running() const { return impl_->running(); }
std::string Coordinator::bound_address() const { return impl_->bound(); }

std::string Coordinator::export_state() const { return impl_->export_state(); }
void Coordinator::import_state(std::string_view json) { impl_->import_state(json); }
void Coordinator::set_persist_hook(std::function<void(std::string_view)> hook) {
    impl_->set_persist_hook(std::move(hook));
}
void Coordinator::persist() { impl_->persist(); }

}  // namespace wirebone
