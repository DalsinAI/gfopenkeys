# gfopenkeys

gfopenkeys.library: the GFOS system keystore (Argon2id + ChaCha20-Poly1305)

Part of GFOS (AmiCradle). Design: [DESIGN.md](DESIGN.md); where GFOS programs keep secrets today: [docs/SURVEY-20261113.md](docs/SURVEY-20261113.md).

## Layout

- `include/libraries/gfopenkeys.h`: error codes, flags, limits and the service names, for every program that keeps a secret.
- `src/gk_store.c`, `src/gk_store.h`: the keystore's core in plain C. The file system, random source and clock come in through `gk_env`, so the host tests build exactly the code the library runs.
- `src/gk_lib.c`, `src/gk_lib.h`: what the library does on top of the store: asking (never with `GKF_NOPROMPT`), the wait after wrong passphrases, the owner tag, the rollback check, read-only after an older passphrase, and asking for the current passphrase before a change. The requester is a `gk_ui`, so the host tests script it.
- `src/gk_prefs.c`, `src/gk_prefs.h`: what the Keys prefs editor does that isn't drawing: its ARexx commands, the `service/host/user` names and the "kept elsewhere" list.
- `prefs/keys_prefs.c`: `SYS:Prefs/Keys`, the prefs window (GadTools, drawn by GFOpenLayout) and its ARexx port. `prefs/arexx/apphost.h` comes from gfopensdk (see `prefs/arexx/FROM`).
- `tests/test_store.c`, `tests/test_lib.c`, `tests/test_prefs.c`: host tests, with an in-memory file system (`tests/fake_env.h`) that can fail at any write, rename or remove.
- `docs/PR3B-AMIGA.md`: what the Amiga library and its requester need (files, build, lab steps).

## ARexx: `GFOPENKEYS.1` (SYS:Prefs/Keys)

No command returns a secret, and none opens a requester: when the keys are locked, `LIST` and `DELETE` answer RC 10.

| Command | Template | Does |
|---|---|---|
| `STATUS` | | RESULT `exists 1 unlocked 1 readonly 0 count 3 left 840` (`left`: seconds until it locks, or `none`) |
| `LOCK` | | Locks the keys now |
| `LIST` | `SERVICE` | RESULT the names, one a line, as `service/host/user` with `/`, `%` and control bytes as `%XX` |
| `DELETE` | `NAME/A` | Deletes the key of that name, as `LIST` gives it (RC 5 when there is none) |
| `TIMEOUT` | `SECONDS/N/A` | Locks after that many seconds without use; 0 keeps the keys open until reboot |
| `FAULT` | `CODE/N/A` | RESULT the text of a gfopenkeys error code (`-3` and `3` are the same) |
| `QUIT`, `ACTIVATE`, `DEACTIVATE`, `VERSION`, `HELP` | | As every port (ARexx-RULE.md); `DEACTIVATE` answers 5, as there is no icon |

`tests/arexx.rexx` checks them; `Rexx/KeysStatus.rexx` is the example.

## Tests

`sh ci/run_tests.sh` builds the core against gfopencrypto's C (openamigatls, at the commit the script pins) and runs the tests plain and under ASan and UBSan. `OPENAMIGATLS=<path>` uses a checkout already on disk.

Rules: commits are authored and committed by SacredTrees; draw through GFOpenLayout; third-party code keeps its own licence and goes in `third_party/` with its notice (BSD-3-Clause libtorrent is allowed; no GPL, LGPL or MPL code).
