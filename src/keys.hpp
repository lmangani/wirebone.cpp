#pragma once

#include "crypto.hpp"

#include <string>
#include <string_view>

namespace wirebone {

enum class KeyKind { Machine, Node, Disco };

std::string format_key(KeyKind kind, const Bytes32& raw);
bool parse_key(KeyKind kind, std::string_view text, Bytes32& out);
std::string zero_machine_key();

}  // namespace wirebone
