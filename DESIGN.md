# gfopenkeys.library: the GFOS keystore, design (version 1, 13 Nov 2026)

Dale decided between 18:10 and 18:13 on 13 Nov 2026 that the keystore is a system library for every app.
- It has its own prefs.
- It uses Argon2id and ChaCha20-Poly1305 from gfopencrypto.
- There is one store file per user.
- Entries are named `service/host/user`.
- The user unlocks it once per session, and it locks again after a timeout.
- The prefs show what is stored, never the secrets.
- Each app imports its old secrets once and then empties its old store.

gfopenputty moves first. The survey of today's secrets is in [docs/SURVEY-20261113.md](docs/SURVEY-20261113.md).

## 1. What it protects, and what it can't

- **It protects** secrets at rest. The store file, a backup, a copied ENVARC: drawer or a stolen card shows nothing without the master passphrase, because every byte of it is sealed, the entry names too.
  - Today, by contrast, gfopenftp's key file sits beside its passwords, and gfopenmail's password is only XOR-obscured.
- **It can't protect** a secret from another program on a running, unlocked Amiga. Classic AmigaOS has no memory protection, and any task can read any memory. So:
  - the unlocked data key lives in one place, the library's own memory, with a timeout;
  - secrets are handed to apps only through calls;
  - every buffer is wiped with `OC_Cleanse` when it is finished with. That names three in particular: the master key, wiped as soon as the data key is unwrapped; Argon2id's work area (64 MiB on AC090), wiped before it is freed, because a block of passphrase-derived state left in Fast RAM is the likeliest leak on a machine with no memory protection; and the passphrase, including the requester's string gadget buffer and its UndoBuffer.

  On AC090 a later version can keep the data key on the host behind a hostlib call (section 9).
- **No secret ever goes** to ARexx, a log, ENV:, the clipboard or a requester's default text.
- **It can't stop a rollback** by someone who can write ENVARC:. They can put an older `.keys` back, and it opens with the passphrase that was current then. The library notices when it can (section 4, "Rolling back"), but it can't prevent it.
- **Argon2id at 8 MiB and t = 2** (the setting for a real 68040, section 4) is weak against an offline attack on a stolen file. The prefs say so while m is below 64 MiB, and "Stronger" raises it.

## 2. The library

`gfopenkeys.library` version 1, in LIBS:. It opens `gfopencrypto.library` 2.4 (Argon2id, ChaCha20, Poly1305, HKDF-SHA256, `OC_CtEqual`, `OC_Cleanse`) and `gfopentls.library` (`OT_Random`, its seeded random number generator).

| Call | What it does |
|---|---|
| `LONG GK_Find(CONST_STRPTR service, CONST_STRPTR host, CONST_STRPTR user, UBYTE *buf, ULONG *len, ULONG flags)` | Copies the secret into the caller's buffer. If the store is locked, it asks for the passphrase, unless `GKF_NOPROMPT` is set (then `GKE_LOCKED`). Returns `GKE_NOTFOUND` or `GKE_SHORT` (with `*len` set to the size needed) |
| `LONG GK_Store(service, host, user, const UBYTE *secret, ULONG len, CONST_STRPTR label, ULONG flags)` | Adds or replaces an entry, then writes the store (section 4). `label` is shown in the prefs, for example "PuTTY: Kim's server" |
| `LONG GK_Delete(service, host, user, ULONG flags)` | Removes one entry |
| `LONG GK_List(struct Hook *hook, CONST_STRPTR service, ULONG flags)` | Calls the hook once for each entry (a `struct GKEntryInfo`: service, host, user, label, the owning program, created, last used). It never passes the secret. It needs the store unlocked |
| `LONG GK_Unlock(struct Window *parent, ULONG flags)` / `void GK_Lock(void)` | Asks for the passphrase through a GFOpenLayout requester on `parent`'s screen; locking wipes the data key |
| `LONG GK_Status(struct GKStatus *st)` | Exists, locked or unlocked, entry count and seconds left before it locks. Nothing secret |
| `LONG GK_SetTimeout(ULONG seconds)` | 0 means never lock by itself (until Lock or a reboot). Kept across reboots. The default is 900 (15 minutes) after the last use |
| `LONG GK_ChangePassphrase(struct Window *parent)` | Asks for the current passphrase first (an unlocked store is not enough, or any program could lock the user out), then re-wraps the data key under a new passphrase; the entries aren't re-sealed (section 4) |
| `LONG GK_Import(const struct GKImport *list, ULONG count, CONST_STRPTR from, ULONG flags)` | One write for an app's migration. Entries that already exist are skipped unless `GKF_REPLACE` is set. It returns how many were added, so the app clears its old store only after this succeeds |
| `CONST_STRPTR GK_ErrorString(LONG err)` | The error's text |

**Rules:**
- **Unlock prompts.**
  - With `GKF_NOPROMPT`, the library never opens a requester. ARexx-driven calls must pass it, under rule 4 of ARexx-RULE.md (no requester may block an ARexx command).
  - A cancelled prompt returns `GKE_CANCEL`.
  - After 5 wrong passphrases, the prompt waits 2, 4, 8 seconds and so on. The prompt is the library's own.
- **Lengths.** Secrets are at most 4096 bytes, so a private-key blob fits later. Each name part is at most 255 bytes, and a label at most 127.
- **Concurrency.** The library is reentrant, with one semaphore round the store. Programs on other Amigas (ARexxNet) never see it. While the passphrase requester is open it holds the semaphore, so another program's call that may ask waits until the user answers: one unlock serves everyone, and no call sees a half-unlocked store. A call with `GKF_NOPROMPT`, `GK_Status` and `GK_SetTimeout` never wait: they answer `GKE_BUSY` at once (ARexx-RULE.md rule 4). A `GK_Lock` that comes then is done when the requester's call finishes.
- **Owner tag.** Each entry records the owning program's name (`FindTask(0)->tc_Node.ln_Name` at store time) for the prefs. It is a label, not access control: on AmigaOS any program can call the library. The name can be NULL or a string that is about to go, so the library copies it under `Forbid()`, at most 63 bytes, and uses "(unnamed)" for NULL. Any program can set its own name, so the unlock requester says "a program calling itself ...".

## 3. Naming: `service/host/user`

- **service** is a short lowercase word from a fixed registry in `include/libraries/gfopenkeys.h`, so apps share entries:

  | service | Used by |
  |---|---|
  | `ssh` | SSH login passwords (gfopenputty, gfopenftp's SFTP) |
  | `ssh-key` | SSH private-key passphrases |
  | `ftp`, `ftps`, `sftp` | FTP sites (gfopenftp, FileZilla) |
  | `mail-imap`, `mail-smtp`, `mail-oauth` | gfopenmail |
  | `nntp` | GFOpenNews |
  | `irc-sasl`, `irc-server`, `irc-nickserv` | GFOpenIRC |
  | `rdp` | GFAmigaRDP |
  | `http`, `http-proxy` | GFOpenBrowser |
  | `telegram-api` | gfopentelegram |

  A new app adds its word with a PR to the header.
- **host** is the host name in lowercase, with `:port` only when the port isn't the service's usual one. It is empty for a secret that isn't tied to a host. For `ssh-key`, host is empty and user is the key's fingerprint (`SHA256:...`). A fingerprint, not the file's path, so moving the key file keeps its passphrase.
- **user** is the login name, as typed (case kept). It is empty when there is none.
- **Escaping.** `/`, `%` and control characters in any part are written as `%XX`, so the three parts always split cleanly. `GK_*` calls take the three parts separately, so the escaping is only for display and for the ARexx `LIST` text.

## 4. The store file

**Where.** Each user has one file, `ENVARC:GFOpenKeys/<user>.keys`.
- `<user>` is the GFOS login name when a login is in use, otherwise `Default`.
- There is no ENV: copy, so it is never in RAM: and never copied at boot.
- The drawer also holds `<user>.keys.bak`, the previous good file.

**Layout** (big-endian, version 1):

```
"GFKS" 0x01 0x00 0x00 0x00               magic, version 1, reserved
kdf:   type (2 = Argon2id), passes, m_kib, lanes, salt[16]
wrap:  nonce[8], data key sealed: ciphertext[32] + tag[16]
count: the write counter (64 bits)
body:  salt[32], length, ciphertext[length] + tag[16]
```

- **The master key** comes from Argon2id(passphrase, salt, passes, m_kib, lanes) and is 32 bytes. It is used only to unwrap the random 32-byte data key.
- **The data key** is made once, when the store is created. A passphrase change re-wraps only this key.
- **Every wrap draws a new KDF salt and a new wrap nonce**: at creation, at `GK_ChangePassphrase`, and at "Stronger" (even with the same passphrase). The library then writes the store twice, so `.bak` is under the new passphrase too and an old passphrase that leaked opens no copy.
- **Sealing** is ChaCha20-Poly1305 in the 64-bit-nonce construction gfopencrypto's `OC_ChaCha20` gives (draft-agl-tls-chacha20poly1305, the same as libsodium's original `crypto_aead_chacha20poly1305`):
  - the Poly1305 key is block 0's key stream;
  - the data is encrypted from block 1;
  - the tag covers the associated data, its 64-bit length, the ciphertext and its 64-bit length.

  The tests check it against the published vectors.
- **The body key** is HKDF-SHA256(data key, the body's fresh random 32-byte salt, "gfopenkeys body v1"). **The body nonce is the write counter**, which goes up by one on every write. Every write therefore has a new key from the new salt, and also a new nonce under the same data key. Even if the random source repeated a salt (section 4a), the key and nonce pair would still not repeat.
- **Associated data** is the file header up to the body (magic, kdf, wrap, write counter). Changing the KDF settings, swapping the wrapped key or changing the counter breaks the tag.
- **The body, once opened,** is "GKB1", the entry count, then each entry as length-prefixed fields: service, host, user, label, owner, created, last-used and secret.
- **Writing.** The library writes `<user>.keys.new`, flushes it and reads it back to check it opens, then renames it over the old file. The old file becomes `.bak` first. A crash at any step leaves a good `.keys` or `.bak`, and the library opens `.bak` when `.keys` is damaged. The damaged file is then set aside as `.keys.bad`, so the good `.bak` is kept.
- **Rolling back.** Opening `.bak` means the newest change may be gone. The unlock requester says "an older copy was opened" (with `GKF_NOPROMPT`, `GK_Status` reports it), and the prefs show it until the next write. The library also keeps the highest counter it has seen in `ENVARC:GFOpenKeys/<user>.count` (not secret) and warns when a store opens with a lower one. That catches an older whole file copied over `.keys`. An unlock from `.new` is checked the same way. Someone who can also edit `.count` can still roll back (section 1).
- **Argon2id settings are chosen when the store is made** and kept in the header, so a store moved to another machine still opens, only slower or faster:
  - AC090 and native: m = 65536 KiB (64 MiB), t = 3;
  - a real 68040 or 68060: m = 8192 KiB, t = 2, aiming at about a second there;
  - the prefs' "Stronger" button raises them with `GK_ChangePassphrase`.
- **A store made with 64 MiB may not open on a real 68040** that has less free memory. The library then returns `GKE_NOMEM` and says plainly "this store needs 64 MiB free to open". It never falls back to weaker settings.

### 4a. Randomness

The body's salt, the KDF salt, the wrap nonce and the data key all come from `OT_Random` (gfopentls). The write counter means a repeated body salt can't reuse a nonce, but the data key and the KDF salt still have to be unpredictable. So:
- **What `OT_Random` is today** (openamigatls `src/opentls/ot_random.c`) is an HMAC-DRBG (SHA-256). On every Amiga, 68k, AC090 and native alike, it is seeded from 512 samples, hashed, of the jitter between the E-clock and the scheduler, plus the idle and dispatch counts, free memory and the DateStamp. Each call mixes in 4 fresh samples and a call counter.
- **AC090 and native** add host entropy. A hostlib call that returns the host's `getrandom()` is mixed into the first seed. It is asked of Team 5 as a gfopentls item, and gfopenkeys works without it.
- **A real 68k** has only the jitter, and on a cold boot that is weakest. The library keeps a 32-byte seed file, `ENVARC:GFOpenKeys/seed`. It is mixed in through `OT_Random`'s update and replaced after every use, so two cold boots never start from the same state. The file is not secret on its own, because it is mixed with the jitter. The library refuses to create a store (`GKE_CRYPTO`) when `OT_Random` reports that it couldn't gather (no timer.device), rather than make keys from a weak seed.
## 5. Unlocking and the timeout

- **The first `GK_Find`/`GK_List` after boot** (or after locking) opens one requester: "Unlock your keys", with the passphrase and the owning program's name, so the user knows who is asking.
- **One unlock serves every program** until the timeout. It is measured from the last use, 15 minutes by default, and set in the prefs (or `GK_SetTimeout`, or ARexx `TIMEOUT`). The library keeps it beside the store in `<store>.timeout` (decimal seconds, not secret) and reads it when it starts, so it holds across reboots.
- **What counts as use** (restarts the timer): unlocking, `GK_Find`, `GK_Store`, `GK_Delete`, `GK_Import` and `GK_ChangePassphrase`. `GK_Status` and `GK_List` do not, so a prefs window left open never keeps the store unlocked.
- **Locking happens on**:
  - the timeout;
  - `GK_Lock` (the prefs' Lock button, the ARexx `LOCK`);
  - and, if ticked, the screen blanker starting.
- **There is no store yet the first time a program calls `GK_Store`.** The library then makes one: the user chooses a passphrase, typed twice, with a strength hint. With no passphrase there's no keystore. That is on purpose, because a machine key beside the file is what gfopenftp does today.
- **Forgotten passphrase.** The store can't be opened. The prefs' "Start again" moves the old file to `<user>.keys.old-<date>` and nothing is deleted.

## 6. The prefs: `SYS:Prefs/Keys`

The prefs editor is drawn through GFOpenLayout, like every prefs editor (UI-LAYER-RULE.md).
- **The list.** It shows service, host, user, label, the program, and the date of last use. It never shows the secret, and there is no "show password" button. The list needs the store unlocked.
- **Buttons:**
  - Delete (with a check) and Delete all for one service;
  - Lock now;
  - Change passphrase, Stronger;
  - the timeout and the blanker setting.
- **"Kept elsewhere" section,** read-only. It lists:
  - network shares from the host's `/api/shares` (`password: set` or `not set`);
  - Wi-Fi networks the card knows (names only);
  - each app not yet moved over, with how it keeps its secrets (from the survey).
- **ARexx port `GFOPENKEYS.1`:**
  - STATUS, LOCK, LIST [SERVICE], DELETE, TIMEOUT, plus the built-ins (ARexx-RULE.md);
  - LIST returns names only;
  - there is no command that returns a secret.

## 7. Moving each app over (migration)

Every app follows the same steps:
1. It reads its old store.
2. It calls `GK_Import` once with every entry.
3. Only if that succeeds, it empties the old store: it blanks the secret fields, deletes key files, and keeps the rest of its settings.
4. It writes a marker (`ENVARC:<App>/KeysMoved`) so it never imports again.
5. From then on it calls `GK_Find` before asking, and offers "Remember in the keystore" when it asks.

Each app's migration PR carries a host unit test:
- import once;
- the old store is empty afterwards;
- a second run imports nothing;
- an import that fails leaves the old store untouched.

**Order:**
1. **gfopenputty** (Dale, 18:13): no old secret store exists (survey row 1), so its test covers this:
   - a `Password` line in a session file copied from another PuTTY is imported once and stripped;
   - after a run with "remember" ticked, no file in `ENVARC:GFOpenPuTTY/` holds the secret;
   - HostKeys is byte-for-byte unchanged.

   PuTTY asks the keystore before the terminal prompt, and for key passphrases it uses `ssh-key//<fingerprint>`. `-pw` and `-pwfile` keep working as PuTTY's own options.
2. **gfopenftp:** sealed site passwords are imported, then `sealed` is emptied and `Key` deleted.
3. **gfopenmail:** the obscured password and the token file are imported, then `secret` is blanked and the token file deleted after asking.
4. **gfopentelegram:** `api_hash` is imported, then removed from `API`.
5. **FileZilla:** a patch to its login manager, then its XML passwords are stripped.
6. **New apps** (GFOpenNews, GFOpenIRC, GFOpenTorrent) use it from the start.

## 8. Tests

- **Host unit tests** (`tests/`, run by `ci/run_tests.sh`), built against a host copy of the gfopencrypto calls:
  - the AEAD against draft-agl and libsodium vectors;
  - Argon2id against RFC 9106 vectors (gfopencrypto's own tests; the store uses its code as it is);
  - store, find, list, delete and import round trips;
  - a wrong passphrase gives `GKE_BADPASS`;
  - a header, wrap or body with one bit flipped is refused;
  - a cut-off write, with a reset at each step, recovers from `.bak`, and opening `.bak` is reported;
  - a write that stores bad bytes is caught by the read-back;
  - the body nonce is the write counter, and a repeated random salt still gives a new nonce;
  - a passphrase change draws a new salt and wrap nonce and leaves no copy that the old passphrase opens;
  - escaping of every reserved character;
  - the timeout, using a fake clock;
  - `GKF_NOPROMPT` never prompts.
- **A lab run on Instance-32 copies,** only for what a unit test can't reach: the requester and the prefs editor.

## 9. Later

- **On AC090,** keep the unwrapped data key on the host with hostlib calls, so the Amiga's memory never holds it; apps still receive the secrets they ask for.
- **Pass-through** to the PC's own keyring (Secret Service, Windows Credential Manager) as an option, for Cradle on a desktop.
- **SSH agent:** keep private keys themselves, and do the signing through a GFOpenPuTTY agent, so the keys never leave the library.

## 10. Order of work (one PR each)

1. This design and the survey (no code).
2. The library core with its host tests: the store format, AEAD, KDF, find, store, list, delete, import, and recovery from `.bak`.
3. The unlock requester and the timeout, then the Amiga library build.
4. The Keys prefs editor and its ARexx port.
5. gfopenputty moved onto it, with the migration test.
6. gfopenftp, gfopenmail, gfopentelegram and FileZilla, one PR each.

Team 2
