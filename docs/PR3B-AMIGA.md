# PR 3b: the Amiga library and the unlock requester (what it needs)

PR 3a put everything the library decides into plain C (`src/gk_store.c`, `src/gk_lib.c`), tested on the host. PR 3b is the Amiga glue around it. It needs the os32-gcc16 stove, which is on daletop, so it is built and lab-tested there.

## Files

| File | What it holds |
|---|---|
| `library/gfopenkeys_lib.c` | The library base, `LibInit`/`LibOpen`/`LibClose`/`LibExpunge` and the LVO table for the calls in DESIGN.md section 2, after openamigatls `library/opencrypto_lib.c`. It has one `SignalSemaphore` round every call. It opens `gfopencrypto.library` 2.4 and `gfopentls.library` 1.5 and fails `LibOpen` without them. The store path is `ENVARC:GFOpenKeys/<user>.keys`, with `<user>` from the GFOS login or `Default` |
| `library/gk_amiga_env.c` | A `gk_env` on dos.library: `Open`/`Read`/`Write`/`Close` (MODE_NEWFILE, then the read-back), `Rename`, `DeleteFile` (a missing file returns an error, and the core allows for that), `OT_Random`, the clock from `DateStamp` in seconds, and `AllocVec(MEMF_ANY)`/`FreeVec` for Argon2id (which wipes its area itself). It also makes `ENVARC:GFOpenKeys` on first use |
| `library/gk_amiga_ui.c` | A `gk_ui` on a GFOpenLayout requester (UI-LAYER-RULE.md). It is described below |
| `library/gk_magic.c` | The magic tags, as `oc_magic.c` (no LTO) |
| `include/fd/gfopenkeys_lib.fd`, `include/clib/gfopenkeys_protos.h`, `include/proto/gfopenkeys.h`, `include/inline/gfopenkeys.h` | The call table, in the order of DESIGN.md section 2. Add `GK_Status` (`struct GKStatus`, as `gk_status`) and `GK_ErrorString` |
| `stub/gfopenkeys_stub.c` | The link stub `libgfopenkeys.a` for programs, as `stub/gfopencrypto_stub.c` |
| `build-amiga.sh` | The build, below |
| `tests/GFOpenKeysLibTest.c` | An Amiga test that runs `tests/test_lib.c`'s cases against the real library and the real file system in `T:` (a store path under `T:`) |

### The requester (`gk_amiga_ui.c`)

- **Text.** It says "A program calling itself *owner* asks for your keys". The owner comes from `gkl_owner(FindTask(0)->tc_Node.ln_Name)`, copied under `Forbid()`.
- **The passphrase field** shows dots, never what is typed. Its buffer and UndoBuffer are wiped (`OC_Cleanse`) when the requester closes, whether it was OK or Cancel.
- **`confirm`:** a second field, plus a strength hint. OK stays off until both fields match.
- **`warn`:** one line in the next requester, or an `EasyRequest` when none follows.
  - `GKW_OLDER_COPY`: "An older copy of your keys was opened. The last change may be missing."
  - `GKW_ROLLED_BACK`: "These keys are older than ones used before on this Amiga (count *a*, seen *b*)."
  - `GKW_READONLY`: "Opened with an older passphrase. Nothing can be saved until you use the newer one."
- **`wait`:** `Delay(50 * seconds)`, with the window showing "Wait *n* s".
- **Never with `GKF_NOPROMPT`.** gk_lib doesn't call it then.

## Build (on daletop, the os32-gcc16 stove)

```
STOVE=~/AmiCradle/stoves/os32-gcc16 OPENAMIGATLS=<openamigatls at 28b5bf59 or later> sh build-amiga.sh
```

The library line follows openamigatls `build-amiga.sh`, with the same CFLAGS: `-m68040 -specs=m68k-soft-m68040.specs -O2 -fno-tree-loop-distribute-patterns -fno-delete-null-pointer-checks -fomit-frame-pointer -Wall -Wextra -Werror`.

```
"$CC" $CFLAGS -mcrt=nix20 -fno-toplevel-reorder -nostartfiles -o "$OUT/lib/gfopenkeys.library" \
  library/gfopenkeys_lib.c library/gk_amiga_env.c library/gk_amiga_ui.c src/gk_store.c src/gk_lib.c \
  "$OUT/obj/gk_magic.o" -L"$OPENAMIGATLS/build-amiga/lib" -lgfopencrypto -lgfopentls -lamiga -lgcc
```

Then check `m68k-amigaos-nm -u` shows nothing from libc's stdio.

## Lab steps (an Instance-32 lab copy; never Instance-40)

1. Copy `gfopenkeys.library` to `LIBS:` of the lab copy (`cradle.py` lab copy plus `install_agent`). gfopencrypto 2.4 and gfopentls 1.5 must be there.
2. Run `GFOpenKeysLibTest`. Every case passes.
3. **The requester, by hand on the lab screen:**
   - The first `GK_Store` asks for a new passphrase twice.
   - A wrong passphrase 6 times shows the waits of 2 s then 4 s.
   - Cancel answers `GKE_CANCEL`.
   - The field shows dots.
   - After closing, a scan of the lab copy's memory finds no copy of the typed passphrase.
4. **ARexx:** a call with `GKF_NOPROMPT` while locked returns `GKE_LOCKED` at once and opens no window (ARexx-RULE.md rule 4).
5. **Timeout:** with `GK_SetTimeout(60)`, after 61 s with no use, `GK_Status` shows locked.
6. **Recovery:**
   - Damage the last byte of `Default.keys`. The unlock opens `.bak`, warns, and leaves `Default.keys.bad`.
   - Then the half-done passphrase change: the old passphrase opens `.bak` read-only, with the warning.
7. Record the times for unlocking at 8 MiB/t=2 and at 64 MiB/t=3 for DESIGN.md section 4.

The lab is needed only for what a unit test can't reach: the requester, real DOS, real memory and the timer.
