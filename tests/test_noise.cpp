#include "noise.hpp"
#include "test_assert.hpp"

int main() {
    using namespace wirebone;
    const Bytes32 server_priv = generate_x25519_private();
    const Bytes32 server_pub = x25519_public(server_priv);
    const Bytes32 client_priv = generate_x25519_private();

    Bytes32 eph{}, h{}, ck{};
    auto init = noise_client_init(client_priv, server_pub, 131, eph, h, ck);
    WB_CHECK(init.size() == 101);

    std::vector<std::uint8_t> resp;
    NoiseResult srv;
    std::string err;
    WB_CHECK(noise_server_handshake(server_priv, init, resp, srv, err));
    WB_CHECK(resp.size() == 51);
    WB_CHECK(srv.peer_machine_public == x25519_public(client_priv));

    NoiseResult cli;
    WB_CHECK(noise_client_finish(client_priv, eph, server_pub, resp, h, ck, cli, err));
    WB_CHECK(cli.tx_key == srv.rx_key);
    WB_CHECK(cli.rx_key == srv.tx_key);
    return 0;
}
