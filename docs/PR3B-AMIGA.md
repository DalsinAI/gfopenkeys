# PR 3b: the Amiga library and the unlock requester

PR 3a put everything the library decides into plain C (`src/gk_store.c`, `src/gk_lib.c`), tested on the host. PR 3b is the Amiga glue around it.

**State (13 Nov 2026, 20:50):**
- The C below is written.
- It compiles with `-Wall -Wextra -Werror` on the os32-gcc16 compiler (GFOpenAmigaGCC 16.2.0-open6, the toolchain.lock release, SHA-256 checked).
- That check used stand-in NDK headers, because the NDK isn't in the release.
- A link with the crypto C left only `OT_Random` unresolved, and `libgfopentls.a` gives that.
- **Not yet done:** a build against the real NDK and a lab run. Both need the stove on daletop: `sh build-amiga.sh` and the lab steps below.

**One thing to watch:** the passphrase field masks what is typed with a GadTools `GTST_EditHook`. If gfopengadtools doesn't honour that tag, the field would show the passphrase. Lab step 3 checks it before anything else.

## Files

| File | What it holds |
|---|---|
| `library/gfopenkeys_lib.c` | The library base, `LibInit`/`LibOpen`/`LibClose`/`LibExpunge` and the LVO table for the calls in DESIGN.md section 2, after openamigatls `library/opencrypto_lib.c`. It has one `SignalSemaphore` round every call. It opens `gfopencrypto.library` 2.4 and `gfopentls.library` 1.5 and fails `LibOpen` without them. The store path is `ENVARC:GFOpenKeys/<user>.keys`, with `<user>` from the GFOS login or `Default` |
| `library/gk_amiga_env.c` | A `gk_env` on dos.library: `Open`/`Read`/`Write`/`Close` (MODE_NEWFILE, then the read-back), `Rename`, `DeleteFile` (a missing file returns an error, and the core allows for that), `OT_Random`, the clock from `DateStamp` in seconds, and `AllocVec(MEMF_ANY)`/`FreeVec` for Argon2id (which wipes its area itself). It also makes `ENVARC:GFOpenKeys` on first use |
| `library/gk_amiga_ui.c` | A `gk_ui` on a GFOpenLayout requester (UI-LAYER-RULE.md). It is described below |
| `include/fd/gfopenkeys_lib.fd`, `include/clib/gfopenkeys_protos.h`, `include/proto/gfopenkeys.h`, `include/inline/gfopenkeys.h` | The call table, in the order of DESIGN.md section 2. Add `GK_Status` (`struct GKStatus`, as `gk_status`) and `GK_ErrorString` |
| `tools/gen_headers.py` | Writes the fd, clib, proto and inline headers from one table |
| `build-amiga.sh` | The build, below. The link stub `libgfopenkeys.a` for programs comes with PR 5 (gfopenputty), its first user |
| `tests/amiga_try.c` | `GFOpenKeysTry`, the lab's driver: one library call per run, on the service `gfopenkeys-try` only |
| `library/gk_amiga.h` | What the Amiga files share |

### The requester (`gk_amiga_ui.c`)

- **Text.** It says "A program calling itself *owner* asks for your keys". The owner comes from `gkl_owner(FindTask(0)->tc_Node.ln_Name)`, copied under `Forbid()`.
- **The passphrase field** shows `*`, never what is typed (a `GTST_EditHook` keeps the real text in the library's buffer). Its buffer and UndoBuffer are wiped (`OC_Cleanse`) when the requester closes, whether it was OK or Cancel.
- **`confirm`:** a second field. If the two differ or are empty, the requester says so and stays open. A strength hint is for later.
- **`warn`:** an `EasyRequest`. gfopengadtools draws EasyRequest in the theme on GFOpenLayout (REQUESTERS.md section 3), so it is no exception to UI-LAYER-RULE.
  - `GKW_OLDER_COPY`: "An older copy of your keys was opened. The last change may be missing."
  - `GKW_ROLLED_BACK`: "These keys are older than ones used before on this Amiga (count *a*, seen *b*)."
  - `GKW_READONLY`: "Opened with an older passphrase. Nothing can be saved: lock the keys, then unlock them with the newer passphrase."
  - `GKW_NO_COUNT`: "The keys' counter file was missing or unreadable. An older copy of the keys can't be told this time."
- **`wait`:** `Delay(50 * seconds)` before the next requester opens.
- **Never with `GKF_NOPROMPT`.** gk_lib doesn't call it then.

## Build (on daletop, the os32-gcc16 stove)

```
OPENAMIGATLS=<openamigatls, built with its own build-amiga.sh> sh build-amiga.sh
```

This uses the same flags as gfopencrypto's build. It links `libgfopencrypto.a` and `libgfopentls.a` (the oc_* calls and `OT_Random` through their libraries), and fails if `m68k-amigaos-nm -u` shows anything unresolved. The outputs are `build-amiga/lib/gfopenkeys.library` and `build-amiga/tests/GFOpenKeysTry`.

## Lab steps (an Instance-32 lab copy; never Instance-40)

1. Copy `gfopenkeys.library` to `LIBS:` of the lab copy (`cradle.py` lab copy plus `install_agent`). gfopencrypto 2.4 and gfopentls 1.5 must be there.
   - **Shipping:** Instance-32 today has gfopencrypto 2.2 and gfopentls 1.3, and the library won't open on those. The package (and GFOpenUp) must ship gfopencrypto.library 2.4 and gfopentls.library 1.5 with it (Franklin, #4).
2. Run `GFOpenKeysTry STATUS`, then `NOPROMPT` (answers -5, no store, and opens no window), `STORE` (asks for a new passphrase twice), `FIND` ("matches"), `LOCK`, `NOPROMPT` (answers -2, locked, no window), `FIND` (asks), `DELETE` and `CHANGE` (asks for the current passphrase first). `GFOpenKeysTry` never prints a secret.
3. **The requester, by hand on the lab screen:**
   - The first `GK_Store` asks for a new passphrase twice.
   - A wrong passphrase 6 times shows the waits of 2 s then 4 s.
   - Cancel answers `GKE_CANCEL`.
   - The field shows dots.
   - After closing, a scan of the lab copy's memory finds no copy of the typed passphrase.
4. **ARexx:** a call with `GKF_NOPROMPT` while locked returns `GKE_LOCKED` at once and opens no window (ARexx-RULE.md rule 4).
   - **While a requester is open (Agnus, row 101):** start an unlock from the Shell (`GFOpenKeysTry FIND`) and leave its requester open. Then `rx "address GFOPENKEYS.1 STATUS"` must answer at once (RC 5, "Busy"), the Keys window must say "Waiting" and keep redrawing, and `GFOpenKeysTry LOCK` from a second Shell must return at once; once the passphrase is typed, the keys end up locked.
5. **Timeout:** with `GK_SetTimeout(60)`, after 61 s with no use, `GK_Status` shows locked.
   - **Low memory (Agnus, #4):** unlock, then `Avail FLUSH` while a program still has the library open. The keys must stay unlocked straight after the flush, and STATUS must say locked once TIMEOUT 60 has passed (the timeout process is still there).
   - **Unloading:** quit every program that has it open, then `Avail FLUSH`; `GFOpenKeysLoaded` (built with the rest) must say "not in memory" and "timeout process: gone" (RC 0). The first flush only asks the timeout process to go (it writes and wipes the store first, within a second); the library leaves at the next flush, as with any library that keeps a process. It looks at exec's library list without opening the library.
6. **Recovery:**
   - Damage the last byte of `Default.keys`. The unlock opens `.bak`, warns, and leaves `Default.keys.bad`.
   - Then the half-done passphrase change: the old passphrase opens `.bak` read-only, with the warning.
7. Record the times for unlocking at 8 MiB/t=2 and at 64 MiB/t=3 for DESIGN.md section 4.

The lab is needed only for what a unit test can't reach: the requester, real DOS, real memory and the timer.
