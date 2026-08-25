#include "wirebone/coordinator.hpp"

#include <cstdlib>
#include <cstring>
#include <iostream>
#include <string>

namespace {

void usage() {
    std::cerr <<
        "wirebone — embeddable Tailscale/Headscale-compatible coordinator\n"
        "\n"
        "Usage:\n"
        "  wirebone serve [--listen HOST:PORT] [--url URL] [--state PATH]\n"
        "                 [--domain NAME] [--dns HOST:PORT]\n"
        "  wirebone preauth create [--state PATH] [--one-shot] [--ephemeral]\n"
        "                          [--token ID] [--shared|--no-shared]\n"
        "  wirebone nodes list [--state PATH]\n";
}

std::string opt(int argc, char** argv, const char* name, const char* def) {
    for (int i = 0; i < argc - 1; ++i) {
        if (std::strcmp(argv[i], name) == 0) {
            return argv[i + 1];
        }
    }
    return def;
}

bool flag(int argc, char** argv, const char* name) {
    for (int i = 0; i < argc; ++i) {
        if (std::strcmp(argv[i], name) == 0) {
            return true;
        }
    }
    return false;
}

wirebone::Config cfg_from_args(int argc, char** argv) {
    wirebone::Config c;
    c.listen = opt(argc, argv, "--listen", "0.0.0.0:8080");
    c.server_url = opt(argc, argv, "--url", "http://127.0.0.1:8080");
    c.state_path = opt(argc, argv, "--state", "wirebone.state.json");
    c.domain = opt(argc, argv, "--domain", "wirebone.local");
    c.dns_listen = opt(argc, argv, "--dns", "0.0.0.0:5353");
    return c;
}

}  // namespace

int main(int argc, char** argv) {
    if (argc < 2) {
        usage();
        return 2;
    }
    const std::string cmd = argv[1];
    if (cmd == "serve") {
        auto cfg = cfg_from_args(argc, argv);
        wirebone::Coordinator coord(cfg);
        std::cout << "wirebone listening on http://" << cfg.listen << '\n';
        std::cout << "control_url  " << cfg.server_url << '\n';
        std::cout << "magicdns     " << cfg.domain << " via udp " << cfg.dns_listen << '\n';
        std::cout << "noise key    " << coord.noise_public_key() << '\n';
        const auto boot = coord.bootstrap_preauth_key();
        if (!boot.empty()) {
            std::cout << "preauth key  " << boot << '\n';
        } else if (!coord.list_preauth_keys().empty()) {
            std::cout << "preauth key  " << coord.list_preauth_keys().front().key << '\n';
        }
        std::cout << "QuackScale:\n"
                  << "  CALL quackscale_serve(...)  -- coordinator + client in one process\n"
                  << "  CALL tailscale_up(control_url => '" << cfg.server_url
                  << "', authkey => '<preauth>', hostname => 'node-a');\n";
        coord.run();
        return 0;
    }
    if (cmd == "preauth" && argc >= 3 && std::string(argv[2]) == "create") {
        auto cfg = cfg_from_args(argc, argv);
        wirebone::Coordinator coord(cfg);
        wirebone::PreauthOptions opts;
        opts.reusable = !flag(argc, argv, "--one-shot");
        opts.ephemeral = flag(argc, argv, "--ephemeral");
        opts.token = opt(argc, argv, "--token", "");
        if (flag(argc, argv, "--shared")) {
            opts.shared = true;
        } else if (flag(argc, argv, "--no-shared")) {
            opts.shared = false;
        }
        const auto key = coord.create_preauth_key(opts);
        std::cout << key << '\n';
        return 0;
    }
    if (cmd == "nodes" && argc >= 3 && std::string(argv[2]) == "list") {
        auto cfg = cfg_from_args(argc, argv);
        wirebone::Coordinator coord(cfg);
        for (const auto& n : coord.list_nodes()) {
            std::cout << n.id << '\t' << n.hostname << '\t' << n.ipv4 << '\t' << n.ipv6 << '\t'
                      << n.node_key << '\t' << n.token << '\t' << (n.shared ? "shared" : "") << '\n';
        }
        return 0;
    }
    usage();
    return 2;
}
