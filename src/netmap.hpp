#pragma once

#include "state.hpp"

#include <nlohmann/json.hpp>

#include <string>
#include <string_view>
#include <vector>

namespace wirebone {

nlohmann::json node_to_tailcfg(const NodeState& node, const std::string& domain, bool self);
nlohmann::json build_register_response();
nlohmann::json build_full_map(const NodeState& self, const std::vector<NodeState>& all,
                              const std::string& domain);
nlohmann::json build_keepalive();

// Hub (shared) sees every node. A token group only sees the same token plus shared nodes.
bool node_visible_to(const NodeState& self, const NodeState& peer);

std::vector<std::uint8_t> encode_map_frame(const nlohmann::json& msg, bool zstd);

std::string rfc3339_now();

}  // namespace wirebone
