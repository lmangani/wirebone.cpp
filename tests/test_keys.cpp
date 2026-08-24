#include "keys.hpp"
#include "test_assert.hpp"

int main() {
    using namespace wirebone;
    Bytes32 raw{};
    raw[0] = 0xab;
    raw[31] = 0xcd;
    const auto s = format_key(KeyKind::Machine, raw);
    WB_CHECK(s.substr(0, 5) == "mkey:");
    Bytes32 back{};
    WB_CHECK(parse_key(KeyKind::Machine, s, back));
    WB_CHECK(back == raw);
    WB_CHECK(!parse_key(KeyKind::Node, s, back));
    WB_CHECK(zero_machine_key().size() == 5 + 64);
    return 0;
}
