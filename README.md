# wirebone.cpp

Embeddable Tailscale/Headscale-compatible **control plane** for C++ 

## What it does

- `GET /key?v=` — Noise public key
- `POST /ts2021` — HTTP upgrade, Noise IK, HTTP/2
- `POST /machine/register` — preauth keys, `100.64.0.0/10` (+ IPv6) allocation
- `POST /machine/map` — netmap long-poll, keepalives, **token-grouped** peer fan-out
- MagicDNS — `DNSConfig.Proxied` plus an optional UDP resolver

Tested against capability versions **106–131** (libtailscale / Tailscale 1.94).

## Build

```sh
cmake -S . -B build
cmake --build build -j
ctest --test-dir build --output-on-failure
```

Needs OpenSSL 3, nghttp2, libzstd (pkg-config).

## CLI

```sh
./build/wirebone serve --listen 0.0.0.0:8080 --url http://10.0.0.5:8080 --state /var/lib/wirebone/state.json
./build/wirebone preauth create --state /var/lib/wirebone/state.json --token analytics
./build/wirebone nodes list --state /var/lib/wirebone/state.json
```

## QuackScale

Check out this repo next to `quackscale` (or pass `-DQUACKSCALE_WIREBONE_DIR`) and rebuild. Operators learn two SQL verbs:

| Job | Call |
|-----|------|
| This node is the hub | `CALL quackscale_hub(...)` |
| This node is a peer | `CALL tailscale_up(...)` |

```sql
LOAD quackscale;

CALL quackscale_hub(
    hostname   => 'duckdb-coord',
    listen     => '0.0.0.0:8080',
    server_url => 'http://10.0.0.5:8080',
    state_dir  => '/var/lib/duckdb/tailscale'
);
CALL quackscale_preauth(reusable => true, token => 'analytics');
SELECT * FROM quackscale.nodes;
```

Peers only join (same `token` = one mesh group; the hub is visible to every group):

```sql
CALL tailscale_up(
    hostname    => 'duckdb-node-b',
    control_url => 'http://10.0.0.5:8080',
    authkey     => 'wbkey-…',
    state_dir   => '/var/lib/duckdb/tailscale'
);
```

One hub can host several isolated groups: mint a key per `token` (the same string as `QUACK_TAILNET_TOKEN` is the intended model). Nodes that join with different tokens never appear in each other's netmap. Untagged keys (no `token`) stay on the shared hub plane — do not hand the bootstrap key to clients if you want isolation.

MagicDNS names are `hostname.quackscale.local`. `CALL quackscale_hub(..., join => false)` is control plane only.

C ABI: [`include/wirebone/wirebone.h`](include/wirebone/wirebone.h). SQL lives in QuackScale (`docs/REFERENCE.md`, `examples/wirebone/`).

## Proof

```sh
cmake --build build -j
./examples/quackscale-e2e/run.sh
```

That script starts Wirebone and runs two [tsnet](https://pkg.go.dev/tailscale.com/tsnet) nodes (the same stack QuackScale embeds).
