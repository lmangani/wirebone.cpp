#include "crypto.hpp"
#include "test_assert.hpp"

int main() {
    using namespace wirebone;
    const char hello[] = "abc";
    auto h = blake2s256({reinterpret_cast<const std::uint8_t*>(hello), 3});
    WB_CHECK(hex_encode(h) == "508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982");

    Bytes32 priv = generate_x25519_private();
    Bytes32 pub = x25519_public(priv);
    Bytes32 priv2 = generate_x25519_private();
    Bytes32 pub2 = x25519_public(priv2);
    WB_CHECK(x25519_shared(priv, pub2) == x25519_shared(priv2, pub));

    Bytes32 key{};
    random_bytes(key);
    std::uint8_t nonce[12]{};
    const std::uint8_t msg[] = {'h', 'i'};
    auto ct = aead_seal(key, nonce, {}, msg);
    WB_CHECK(ct.size() == 18);
    std::vector<std::uint8_t> pt;
    WB_CHECK(aead_open(key, nonce, {}, ct, pt));
    WB_CHECK(pt.size() == 2 && pt[0] == 'h' && pt[1] == 'i');

    Bytes32 out{};
    WB_CHECK(hex_decode(hex_encode(key), out));
    WB_CHECK(out == key);
    return 0;
}
