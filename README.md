# wirebone.cpp

Embeddable Tailscale/Headscale-compatible **control plane** for C++ (and DuckDB via [QuackScale](https://github.com/Query-farm/quackscale)).

Existing clients stay unchanged: QuackScale already embeds libtailscale/tsnet. Point `control_url` at a Wirebone coordinator instead of Tailscale SaaS or a Headscale process.

One database node hosts the coordinator. That same process can also join the mesh as a client.

## What it does

- `GET /key?v=` — Noise public key
- `POST /ts2021` — HTTP upgrade, Noise IK, HTTP/2
- `POST /machine/register` — preauth keys, `100.64.0.0/10` (+ IPv6) allocation
- `POST /machine/map` — netmap long-poll, keepalives, peer fan-out
- MagicDNS — `DNSConfig.Proxied` plus a UDP resolver (`hostname.wirebone.local`)

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

## QuackScale: coordinator and client

On the coordinator node, start Wirebone then join as a client:

```sql
LOAD quackscale;

-- control plane + client in this process
CALL quackscale_serve(
    hostname          => 'duckdb-coord',
    listen            => '0.0.0.0:8080',
    server_url        => 'http://10.0.0.5:8080',
    state_dir         => '/var/lib/duckdb/tailscale',
    domain            => 'wirebone.local'
);
```

Or two calls: `CALL wirebone_serve(...)` then `CALL tailscale_up(control_url => 'http://127.0.0.1:8080', authkey => wirebone_bootstrap_key(), ...)`.

Peers only join:

```sql
CALL tailscale_up(
    hostname    => 'duckdb-node-b',
    control_url => 'http://10.0.0.5:8080',
    authkey     => 'wbkey-...',
    state_dir   => '/var/lib/duckdb/tailscale'
);
```

MagicDNS names are `hostname.wirebone.local` (and the short hostname via search domain). QuackScale can `ATTACH 'quack:duckdb-coord.wirebone.local:9494'`.

C ABI for embedding: [`include/wirebone/wirebone.h`](include/wirebone/wirebone.h). SQL (`wirebone_serve`, `quackscale_serve`, …) lives in [QuackScale](https://github.com/Query-farm/quackscale): check out this repo next to `quackscale` (or set `QUACKSCALE_WIREBONE_DIR`) and rebuild the extension.

## Proof

```sh
cmake --build build -j
./examples/quackscale-e2e/run.sh
```

That script starts Wirebone and runs two [tsnet](https://pkg.go.dev/tailscale.com/tsnet) nodes (the same stack QuackScale embeds). If `duckdb` + quackscale are installed it also runs `CALL tailscale_up`.
