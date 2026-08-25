# QuackScale SQL

The hub SQL surface (`quackscale_hub`, `quackscale_status`, `quackscale_preauth`, …) is implemented in the [QuackScale](https://github.com/Query-farm/quackscale) extension, not in this directory.

1. Check out `wirebone.cpp` next to `quackscale` (or pass `-DQUACKSCALE_WIREBONE_DIR`).
2. Rebuild QuackScale with OpenSSL, nghttp2, and libzstd available to pkg-config.
3. `CALL quackscale_hub(...)` to be the hub (control plane + client). Peers only `CALL tailscale_up(...)`.

On the QuackScale `wirebone-coordinator` branch:

- Front door: `README.md` (control plane table + `quackscale_hub` quick start)
- Auth and SQL: `docs/AUTHENTICATION.md`, `docs/REFERENCE.md`
- Two-process walkthrough: `examples/wirebone/`
