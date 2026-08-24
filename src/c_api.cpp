#include "wirebone/wirebone.h"

#include "wirebone/coordinator.hpp"

#include <cstdlib>
#include <cstring>
#include <string>

namespace {

char* dup_str(const std::string& s) {
    char* p = static_cast<char*>(std::malloc(s.size() + 1));
    if (!p) {
        return nullptr;
    }
    std::memcpy(p, s.c_str(), s.size() + 1);
    return p;
}

const char* or_def(const char* v, const char* d) { return v && v[0] ? v : d; }

}  // namespace

struct wirebone_coordinator {
    wirebone::Coordinator impl;
    explicit wirebone_coordinator(wirebone::Config cfg) : impl(std::move(cfg)) {}
};

wirebone_coordinator* wirebone_create(const wirebone_config* cfg) {
    wirebone::Config c;
    if (cfg) {
        c.listen = or_def(cfg->listen, "0.0.0.0:8080");
        c.server_url = or_def(cfg->server_url, "http://127.0.0.1:8080");
        c.ip_prefix = or_def(cfg->ip_prefix, "100.64.0.0/16");
        c.ipv6_prefix = or_def(cfg->ipv6_prefix, "fd7a:115c:a1e0::/48");
        c.state_path = cfg->state_path ? cfg->state_path : "";
        c.domain = or_def(cfg->domain, "wirebone.local");
        c.dns_listen = cfg->dns_listen ? cfg->dns_listen : "0.0.0.0:5353";
    }
    try {
        return new wirebone_coordinator(std::move(c));
    } catch (...) {
        return nullptr;
    }
}

void wirebone_destroy(wirebone_coordinator* c) { delete c; }

int wirebone_start(wirebone_coordinator* c) {
    if (!c) {
        return -1;
    }
    try {
        c->impl.run_async();
        return 0;
    } catch (...) {
        return -1;
    }
}

void wirebone_stop(wirebone_coordinator* c) {
    if (c) {
        c->impl.stop();
    }
}

int wirebone_running(const wirebone_coordinator* c) { return c && c->impl.running() ? 1 : 0; }

char* wirebone_bound_address(const wirebone_coordinator* c) {
    return c ? dup_str(c->impl.bound_address()) : nullptr;
}
char* wirebone_bootstrap_key(const wirebone_coordinator* c) {
    return c ? dup_str(c->impl.bootstrap_preauth_key()) : nullptr;
}
char* wirebone_create_preauth_key(wirebone_coordinator* c, int reusable, int ephemeral) {
    if (!c) {
        return nullptr;
    }
    try {
        return dup_str(c->impl.create_preauth_key({reusable != 0, ephemeral != 0, {}}));
    } catch (...) {
        return nullptr;
    }
}
char* wirebone_noise_public_key(const wirebone_coordinator* c) {
    return c ? dup_str(c->impl.noise_public_key()) : nullptr;
}

wirebone_node_info* wirebone_list_nodes(const wirebone_coordinator* c, size_t* count) {
    if (count) {
        *count = 0;
    }
    if (!c || !count) {
        return nullptr;
    }
    const auto nodes = c->impl.list_nodes();
    if (nodes.empty()) {
        return nullptr;
    }
    auto* out = static_cast<wirebone_node_info*>(std::calloc(nodes.size(), sizeof(wirebone_node_info)));
    if (!out) {
        return nullptr;
    }
    for (size_t i = 0; i < nodes.size(); ++i) {
        out[i].id = nodes[i].id;
        out[i].hostname = dup_str(nodes[i].hostname);
        out[i].ipv4 = dup_str(nodes[i].ipv4);
        out[i].ipv6 = dup_str(nodes[i].ipv6);
        out[i].node_key = dup_str(nodes[i].node_key);
        out[i].online = nodes[i].online ? 1 : 0;
    }
    *count = nodes.size();
    return out;
}

char* wirebone_export_state(const wirebone_coordinator* c) {
    return c ? dup_str(c->impl.export_state()) : nullptr;
}

int wirebone_import_state(wirebone_coordinator* c, const char* json) {
    if (!c) {
        return -1;
    }
    try {
        c->impl.import_state(json ? json : "{}");
        return 0;
    } catch (...) {
        return -1;
    }
}

int wirebone_persist(wirebone_coordinator* c) {
    if (!c) {
        return -1;
    }
    try {
        c->impl.persist();
        return 0;
    } catch (...) {
        return -1;
    }
}

void wirebone_set_persist_callback(wirebone_coordinator* c, wirebone_persist_cb cb, void* user) {
    if (!c) {
        return;
    }
    if (!cb) {
        c->impl.set_persist_hook(nullptr);
        return;
    }
    c->impl.set_persist_hook([cb, user](std::string_view json) {
        std::string owned(json);
        cb(owned.c_str(), user);
    });
}

void wirebone_free_nodes(wirebone_node_info* nodes, size_t count) {
    if (!nodes) {
        return;
    }
    for (size_t i = 0; i < count; ++i) {
        std::free(nodes[i].hostname);
        std::free(nodes[i].ipv4);
        std::free(nodes[i].ipv6);
        std::free(nodes[i].node_key);
    }
    std::free(nodes);
}
