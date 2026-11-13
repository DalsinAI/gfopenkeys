# gfopenkeys

gfopenkeys.library: the GFOS system keystore (Argon2id + ChaCha20-Poly1305)

Part of GFOS (AmiCradle). Design: [DESIGN.md](DESIGN.md); where GFOS programs keep secrets today: [docs/SURVEY-20261113.md](docs/SURVEY-20261113.md).

## Layout

- `include/libraries/gfopenkeys.h`: error codes, flags, limits and the service names, for every program that keeps a secret.
- `src/gk_store.c`, `src/gk_store.h`: the keystore's core in plain C. The file system, random source and clock come in through `gk_env`, so the host tests build exactly the code the library runs.
- `src/gk_lib.c`, `src/gk_lib.h`: what the library does on top of the store: asking (never with `GKF_NOPROMPT`), the wait after wrong passphrases, the owner tag, the rollback check, read-only after an older passphrase, and asking for the current passphrase before a change. The requester is a `gk_ui`, so the host tests script it.
- `tests/test_store.c`, `tests/test_lib.c`: host tests, with an in-memory file system (`tests/fake_env.h`) that can fail at any write, rename or remove.
- `docs/PR3B-AMIGA.md`: what the Amiga library and its requester need (files, build, lab steps).

## Tests

`sh ci/run_tests.sh` builds the core against gfopencrypto's C (openamigatls, at the commit the script pins) and runs the tests plain and under ASan and UBSan. `OPENAMIGATLS=<path>` uses a checkout already on disk.

Rules: commits are authored and committed by SacredTrees; draw through GFOpenLayout; third-party code keeps its own licence and goes in `third_party/` with its notice (BSD-3-Clause libtorrent is allowed; no GPL, LGPL or MPL code).
