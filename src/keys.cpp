#include "keys.hpp"

namespace wirebone {
namespace {

const char* prefix_for(KeyKind kind) {
    switch (kind) {
        case KeyKind::Machine:
            return "mkey:";
        case KeyKind::Node:
            return "nodekey:";
        case KeyKind::Disco:
            return "discokey:";
    }
    return "";
}

}  // namespace

std::string format_key(KeyKind kind, const Bytes32& raw) {
    return std::string(prefix_for(kind)) + hex_encode(raw);
}

bool parse_key(KeyKind kind, std::string_view text, Bytes32& out) {
    const std::string_view prefix = prefix_for(kind);
    if (text.size() < prefix.size() || text.substr(0, prefix.size()) != prefix) {
        return false;
    }
    return hex_decode(text.substr(prefix.size()), out);
}

std::string zero_machine_key() {
    return format_key(KeyKind::Machine, Bytes32{});
}

}  // namespace wirebone
