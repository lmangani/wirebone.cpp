# QuackScale SQL

The coordinator SQL surface (`wirebone_serve`, `quackscale_serve`, `wirebone_nodes`, …) is implemented in the [QuackScale](https://github.com/Query-farm/quackscale) extension, not in this directory.

1. Check out `wirebone.cpp` next to `quackscale` (or pass `-DQUACKSCALE_WIREBONE_DIR`).
2. Rebuild QuackScale with OpenSSL, nghttp2, and libzstd available to pkg-config.
3. `CALL quackscale_serve(...)` to be coordinator and client, or `CALL wirebone_serve(...)` then `CALL tailscale_up(...)`.

See QuackScale `docs/REFERENCE.md` and `docs/AUTHENTICATION.md`.
