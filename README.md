# wirebone.cpp

Embeddable Tailscale/Headscale-compatible **control plane** for C++ (and DuckDB via [QuackScale](https://github.com/Query-farm/quackscale)).

Existing clients stay unchanged: QuackScale already embeds libtailscale/tsnet. Point `control_url` at this process instead of Tailscale SaaS or a Headscale process.

## What it does

- `GET /key?v=` — Noise public key
- `POST /ts2021` — HTTP upgrade, Noise IK, HTTP/2
- `POST /machine/register` — preauth keys, `100.64.0.0/10` (+ IPv6) allocation
- `POST /machine/map` — netmap long-poll, keepalives, peer fan-out
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
./build/wirebone preauth create --state /var/lib/wirebone/state.json
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
SELECT * FROM quackscale.nodes;
```

Peers only join:

```sql
CALL tailscale_up(
    hostname    => 'duckdb-node-b',
    control_url => 'http://10.0.0.5:8080',
    authkey     => 'wbkey-…',
    state_dir   => '/var/lib/duckdb/tailscale'
);
```

MagicDNS names are `hostname.quackscale.local`. `CALL quackscale_hub(..., join => false)` is control plane only.

C ABI: [`include/wirebone/wirebone.h`](include/wirebone/wirebone.h). SQL lives in QuackScale (`docs/REFERENCE.md`, `examples/wirebone/`).

## Proof

```sh
cmake --build build -j
./examples/quackscale-e2e/run.sh
```

That script starts Wirebone and runs two [tsnet](https://pkg.go.dev/tailscale.com/tsnet) nodes (the same stack QuackScale embeds). If `duckdb` + quackscale are installed it also runs `CALL tailscale_up`.
