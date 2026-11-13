# gfopenkeys

gfopenkeys.library: the GFOS system keystore (Argon2id + ChaCha20-Poly1305)

Part of GFOS (AmiCradle). Design: [DESIGN.md](DESIGN.md); where GFOS programs keep secrets today: [docs/SURVEY-20261113.md](docs/SURVEY-20261113.md).

## Layout

- `include/libraries/gfopenkeys.h`: error codes, flags, limits and the service names, for every program that keeps a secret.
- `src/gk_store.c`, `src/gk_store.h`: the keystore's core in plain C. The file system, random source and clock come in through `gk_env`, so the host tests build exactly the code the library runs.
- `tests/test_store.c`: host tests, with an in-memory file system that can fail at any write, rename or remove.

## Tests

`sh ci/run_tests.sh` builds the core against gfopencrypto's C (openamigatls, at the commit the script pins) and runs the tests plain and under ASan and UBSan. `OPENAMIGATLS=<path>` uses a checkout already on disk.

Rules: commits are authored and committed by SacredTrees; draw through GFOpenLayout; third-party code keeps its own licence and goes in `third_party/` with its notice (BSD-3-Clause libtorrent is allowed; no GPL, LGPL or MPL code).
