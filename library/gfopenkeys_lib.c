/* gfopenkeys.library 1.0: the GFOS keystore (DESIGN.md).
 * The decisions are src/gk_store.c and src/gk_lib.c (tested on the host);
 * this file is the library around them: the base, one semaphore round every
 * call, the owner tag, and a small process that locks the store when its
 * timeout passes, so the data key doesn't wait in memory for the next call.
 * MIT, Copyright (c) 2026 AmiCradle Team. */
#include <exec/types.h>
#include <exec/resident.h>
#include <exec/libraries.h>
#include <exec/execbase.h>
#include <exec/memory.h>
#include <exec/semaphores.h>
#include <dos/dos.h>
#include <dos/dosextens.h>
#include <dos/dostags.h>
#include <utility/hooks.h>
#include <proto/exec.h>
#include <proto/dos.h>
#include <proto/utility.h>

#include <string.h>

#include "../include/libraries/gfopenkeys.h"
#include "gfopencrypto/gfopencrypto.h"
#include "gk_amiga.h"

#define REG(r, decl) register decl __asm(#r)
#define LIB_VERSION  GFOPENKEYS_VERSION
#define LIB_REVISION 0
#define DRAWER  "ENVARC:GFOpenKeys"
#define STORE   DRAWER "/Default.keys"   /* <user>.keys once GFOS has logins (DESIGN.md section 4) */
#define TICK_S  10                       /* how often the timeout process looks */

struct GFOpenKeysBase {
    struct Library lib;
    BPTR seglist;
};

struct ExecBase *SysBase;
struct DosLibrary *DOSBase;
struct IntuitionBase *IntuitionBase;
struct Library *GadToolsBase, *UtilityBase;
extern struct Library *OpenCryptoBase, *OpenTLSBase;   /* defined by libgfopencrypto.a and libgfopentls.a */

/* The link stubs open their library from an ADD2INIT list, through
 * gfopen_stub_open, which ends the program (exit()) when it fails. A library
 * has no startup code, so those lists never run and there is no exit():
 * this one stands in for the stubs' stub_open.o, so that member isn't
 * linked. lib_init opens both bases itself. Never called. */
struct Library *gfopen_stub_open(const char *name, ULONG version, UWORD revision);
struct Library *gfopen_stub_open(const char *name, ULONG version, UWORD revision)
{
    (void)name; (void)version; (void)revision;
    return NULL;
}

static struct SignalSemaphore sem;
static gk_lib *keys;
static struct Window *parent;            /* the window the next requester opens over */
static struct Process *ticker;           /* the timeout process; NULL once it has gone */

int start(void) { return -1; }

static const char lib_name[] = GFOPENKEYS_NAME;
static const char lib_id[] = "gfopenkeys.library 1.0 (13.11.2026) GFOS keystore, AmiCradle Team\r\n";
static const char lib_ver[] __attribute__((used)) = "$VER: gfopenkeys.library 1.0 (13.11.2026) GFOS keystore, AmiCradle Team";

static struct Library *lib_init(REG(d0, struct GFOpenKeysBase *base), REG(a0, BPTR seglist), REG(a6, struct ExecBase *sys));
static struct Library *lib_open(REG(a6, struct GFOpenKeysBase *base));
static BPTR lib_close(REG(a6, struct GFOpenKeysBase *base));
static BPTR lib_expunge(REG(a6, struct GFOpenKeysBase *base));
static ULONG lib_null(void);

#define B REG(a6, struct GFOpenKeysBase *base)
static ULONG GK_Version(B);
static LONG GK_Find(REG(a0, CONST_STRPTR service), REG(a1, CONST_STRPTR host), REG(a2, CONST_STRPTR user),
                    REG(a3, UBYTE *buf), REG(d0, ULONG *len), REG(d1, ULONG flags), B);
static LONG GK_Store(REG(a0, CONST_STRPTR service), REG(a1, CONST_STRPTR host), REG(a2, CONST_STRPTR user),
                     REG(a3, CONST UBYTE *secret), REG(d0, ULONG len), REG(d1, CONST_STRPTR label), REG(d2, ULONG flags), B);
static LONG GK_Delete(REG(a0, CONST_STRPTR service), REG(a1, CONST_STRPTR host), REG(a2, CONST_STRPTR user),
                      REG(d0, ULONG flags), B);
static LONG GK_List(REG(a0, struct Hook *hook), REG(a1, CONST_STRPTR service), REG(d0, ULONG flags), B);
static LONG GK_Unlock(REG(a0, struct Window *win), REG(d0, ULONG flags), B);
static void GK_Lock(B);
static LONG GK_Status(REG(a0, struct GKStatus *st), B);
static LONG GK_SetTimeout(REG(d0, ULONG seconds), B);
static LONG GK_ChangePassphrase(REG(a0, struct Window *win), REG(d0, ULONG flags), B);
static LONG GK_Import(REG(a0, CONST struct GKImport *list), REG(d0, ULONG count), REG(a1, CONST_STRPTR from),
                      REG(d1, ULONG flags), B);
static CONST_STRPTR GK_ErrorString(REG(d0, LONG error), B);

/* The order is tools/gen_headers.py's table */
static const APTR lib_vectors[] = {
    (APTR)lib_open, (APTR)lib_close, (APTR)lib_expunge, (APTR)lib_null,
    (APTR)GK_Version, (APTR)GK_Find, (APTR)GK_Store, (APTR)GK_Delete, (APTR)GK_List,
    (APTR)GK_Unlock, (APTR)GK_Lock, (APTR)GK_Status, (APTR)GK_SetTimeout,
    (APTR)GK_ChangePassphrase, (APTR)GK_Import, (APTR)GK_ErrorString,
    (APTR)-1
};

static const struct {
    ULONG size;
    const APTR *vectors;
    APTR data;
    APTR init;
} lib_inittable = { sizeof(struct GFOpenKeysBase), lib_vectors, NULL, (APTR)lib_init };

const struct Resident lib_romtag = {
    RTC_MATCHWORD, (struct Resident *)&lib_romtag, (APTR)(&lib_romtag + 1),
    RTF_AUTOINIT, LIB_VERSION, NT_LIBRARY, 0,
    (char *)lib_name, (char *)lib_id, (APTR)&lib_inittable
};

/* ---- the timeout process --------------------------------------------------- */

static void ticker_main(void)
{
    for (;;) {
        if (CheckSignal(SIGBREAKF_CTRL_C)) break;
        Delay(50 * TICK_S);
        ObtainSemaphore(&sem);
        gk_is_unlocked(gkl_store(keys));   /* locks (and wipes) when the timeout has passed */
        ReleaseSemaphore(&sem);
    }
    ObtainSemaphore(&sem);
    gkl_lock(keys);                        /* written and wiped here, in a process, before expunge */
    ReleaseSemaphore(&sem);
    Forbid();                              /* held until this process has gone: the code can't be unloaded under it */
    ticker = NULL;
}

/* ---- the library ------------------------------------------------------------- */

static void close_all(void)
{
    if (OpenTLSBase) CloseLibrary(OpenTLSBase);
    if (OpenCryptoBase) CloseLibrary(OpenCryptoBase);
    if (UtilityBase) CloseLibrary(UtilityBase);
    if (GadToolsBase) CloseLibrary(GadToolsBase);
    if (IntuitionBase) CloseLibrary((struct Library *)IntuitionBase);
    if (DOSBase) CloseLibrary((struct Library *)DOSBase);
}

static struct Library *lib_init(REG(d0, struct GFOpenKeysBase *base), REG(a0, BPTR seglist), REG(a6, struct ExecBase *sys))
{
    static gk_env env;
    static gk_ui ui;
    gk_kdf kdf;
    SysBase = sys;
    base->seglist = seglist;
    base->lib.lib_Revision = LIB_REVISION;
    InitSemaphore(&sem);
    /* LibInit runs in ramlib's process, so disk libraries can be opened here */
    DOSBase = (struct DosLibrary *)OpenLibrary((CONST_STRPTR)"dos.library", 37);
    IntuitionBase = (struct IntuitionBase *)OpenLibrary((CONST_STRPTR)"intuition.library", 37);
    GadToolsBase = OpenLibrary((CONST_STRPTR)"gadtools.library", 37);
    UtilityBase = OpenLibrary((CONST_STRPTR)"utility.library", 37);
    OpenCryptoBase = OpenLibrary((CONST_STRPTR)"gfopencrypto.library", 2);
    OpenTLSBase = OpenLibrary((CONST_STRPTR)"gfopentls.library", 1);
    if (!DOSBase || !IntuitionBase || !GadToolsBase || !UtilityBase || !OpenCryptoBase || !OpenTLSBase
        || (OpenCryptoBase->lib_Version == 2 && OpenCryptoBase->lib_Revision < 4)
        || (OpenTLSBase->lib_Version == 1 && OpenTLSBase->lib_Revision < 5))
        goto fail;
    /* DESIGN.md section 4: 64 MiB and t = 3 where there is room (AC090, native), else 8 MiB and t = 2 */
    if (AvailMem(MEMF_ANY | MEMF_LARGEST) > 512UL * 1024 * 1024) { kdf.passes = 3; kdf.m_kib = 65536; }
    else { kdf.passes = 2; kdf.m_kib = 8192; }
    kdf.lanes = 1;
    gk_amiga_env(&env);
    gk_amiga_ui(&ui, &parent);
    gk_amiga_make_drawer(DRAWER);
    if (gkl_open(&keys, &env, &ui, STORE, &kdf)) goto fail;
    ticker = CreateNewProcTags(NP_Entry, (ULONG)ticker_main, NP_Name, (ULONG)"gfopenkeys timeout",
                               NP_Priority, 0, TAG_END);
    if (!ticker) { gkl_close(keys); keys = NULL; goto fail; }
    return &base->lib;
fail:
    close_all();
    FreeMem((UBYTE *)base - base->lib.lib_NegSize, base->lib.lib_NegSize + base->lib.lib_PosSize);
    return NULL;
}

static struct Library *lib_open(REG(a6, struct GFOpenKeysBase *base))
{
    base->lib.lib_OpenCnt++;
    base->lib.lib_Flags &= ~LIBF_DELEXP;
    return &base->lib;
}

static BPTR lib_close(REG(a6, struct GFOpenKeysBase *base))
{
    base->lib.lib_OpenCnt--;
    if (base->lib.lib_OpenCnt == 0 && (base->lib.lib_Flags & LIBF_DELEXP))
        return lib_expunge(base);
    return 0;
}

/* Under Forbid: no DOS here. The timeout process writes and wipes the store
 * on its way out; expunge waits for it to have gone. */
static BPTR lib_expunge(REG(a6, struct GFOpenKeysBase *base))
{
    BPTR seglist;
    if (base->lib.lib_OpenCnt || ticker) {
        if (ticker) Signal(&ticker->pr_Task, SIGBREAKF_CTRL_C);
        base->lib.lib_Flags |= LIBF_DELEXP;
        return 0;
    }
    gkl_close(keys);                     /* already locked: frees memory only */
    keys = NULL;
    close_all();
    seglist = base->seglist;
    Remove(&base->lib.lib_Node);
    FreeMem((UBYTE *)base - base->lib.lib_NegSize, base->lib.lib_NegSize + base->lib.lib_PosSize);
    return seglist;
}

static ULONG lib_null(void) { return 0; }

/* ---- the calls ------------------------------------------------------------- */

/* Every call that may touch the file or a window comes from a process */
static int is_process(void)
{
    return FindTask(NULL)->tc_Node.ln_Type == NT_PROCESS;
}

/* The caller's name, copied under Forbid: ln_Name may be NULL or about to go */
static void owner_of_caller(char out[GK_MAX_OWNER + 1])
{
    char raw[GK_MAX_OWNER + 1];
    const char *n;
    Forbid();
    n = FindTask(NULL)->tc_Node.ln_Name;
    if (n) { strncpy(raw, n, GK_MAX_OWNER); raw[GK_MAX_OWNER] = 0; }
    Permit();
    gkl_owner(out, n ? raw : NULL);
}

#define ENTER(win) \
    char owner[GK_MAX_OWNER + 1]; LONG r; \
    (void)base; \
    if (!is_process()) return GKE_IO; \
    owner_of_caller(owner); \
    ObtainSemaphore(&sem); \
    parent = (win)
#define LEAVE() parent = NULL; ReleaseSemaphore(&sem); return r

static ULONG GK_Version(B) { (void)base; return (LIB_VERSION << 16) | LIB_REVISION; }

static LONG GK_Find(REG(a0, CONST_STRPTR service), REG(a1, CONST_STRPTR host), REG(a2, CONST_STRPTR user),
                    REG(a3, UBYTE *buf), REG(d0, ULONG *len), REG(d1, ULONG flags), B)
{
    size_t n;
    ENTER(NULL);
    if (!len) { r = GKE_SHORT; LEAVE(); }
    n = *len;
    r = gkl_find(keys, owner, (const char *)service, (const char *)host, (const char *)user, buf, &n, flags);
    if (!r || r == GKE_SHORT) *len = (ULONG)n;
    LEAVE();
}

static LONG GK_Store(REG(a0, CONST_STRPTR service), REG(a1, CONST_STRPTR host), REG(a2, CONST_STRPTR user),
                     REG(a3, CONST UBYTE *secret), REG(d0, ULONG len), REG(d1, CONST_STRPTR label), REG(d2, ULONG flags), B)
{
    ENTER(NULL);
    r = gkl_store_entry(keys, owner, (const char *)service, (const char *)host, (const char *)user,
                        secret, len, (const char *)label, flags);
    LEAVE();
}

static LONG GK_Delete(REG(a0, CONST_STRPTR service), REG(a1, CONST_STRPTR host), REG(a2, CONST_STRPTR user),
                      REG(d0, ULONG flags), B)
{
    ENTER(NULL);
    r = gkl_delete(keys, owner, (const char *)service, (const char *)host, (const char *)user, flags);
    LEAVE();
}

static int list_one(void *c, const gk_info *in)
{
    struct Hook *hook = c;
    struct GKEntryInfo e;
    e.ge_Service = (CONST_STRPTR)in->service; e.ge_Host = (CONST_STRPTR)in->host; e.ge_User = (CONST_STRPTR)in->user;
    e.ge_Label = (CONST_STRPTR)in->label; e.ge_Owner = (CONST_STRPTR)in->owner;
    e.ge_CreatedHi = (ULONG)(in->created >> 32); e.ge_CreatedLo = (ULONG)in->created;
    e.ge_LastUsedHi = (ULONG)(in->last_used >> 32); e.ge_LastUsedLo = (ULONG)in->last_used;
    return CallHookPkt(hook, NULL, &e) != 0;
}

static LONG GK_List(REG(a0, struct Hook *hook), REG(a1, CONST_STRPTR service), REG(d0, ULONG flags), B)
{
    ENTER(NULL);
    if (!hook) { r = GKE_NOTFOUND; LEAVE(); }
    if (!(r = gkl_unlock(keys, owner, flags)))
        r = gk_list(gkl_store(keys), (const char *)service, list_one, hook);
    LEAVE();
}

static LONG GK_Unlock(REG(a0, struct Window *win), REG(d0, ULONG flags), B)
{
    ENTER(win);
    r = gkl_unlock(keys, owner, flags);
    LEAVE();
}

static void GK_Lock(B)
{
    (void)base;
    if (!is_process()) return;           /* writing last-used times needs DOS */
    ObtainSemaphore(&sem);
    gkl_lock(keys);
    ReleaseSemaphore(&sem);
}

static LONG GK_Status(REG(a0, struct GKStatus *st), B)
{
    gk_status s;
    (void)base;
    if (!st) return GKE_NOTFOUND;
    if (!is_process()) return GKE_IO;
    ObtainSemaphore(&sem);
    gkl_status(keys, &s);
    ReleaseSemaphore(&sem);
    st->gs_Exists = s.exists; st->gs_Unlocked = s.unlocked; st->gs_ReadOnly = s.readonly;
    st->gs_RolledBack = s.rolled_back; st->gs_OpenedFrom = s.opened_from; st->gs_Count = (ULONG)s.count;
    st->gs_SecondsLeft = s.seconds_left;
    st->gs_CounterHi = (ULONG)(s.counter >> 32); st->gs_CounterLo = (ULONG)s.counter;
    return GKE_OK;
}

static LONG GK_SetTimeout(REG(d0, ULONG seconds), B)
{
    (void)base;
    ObtainSemaphore(&sem);
    gk_set_timeout(gkl_store(keys), seconds);
    ReleaseSemaphore(&sem);
    return GKE_OK;
}

static LONG GK_ChangePassphrase(REG(a0, struct Window *win), REG(d0, ULONG flags), B)
{
    ENTER(win);
    r = gkl_change_pass(keys, owner, NULL, flags);
    LEAVE();
}

/* Answers how many were added, or an error (below 0) */
static LONG GK_Import(REG(a0, CONST struct GKImport *list), REG(d0, ULONG count), REG(a1, CONST_STRPTR from),
                      REG(d1, ULONG flags), B)
{
    gk_import_item *items;
    size_t added = 0;
    ULONG i;
    char tag[GK_MAX_OWNER + 1];
    ENTER(NULL);
    if (count > GK_MAX_ENTRIES) { r = GKE_TOOBIG; LEAVE(); }
    if (!count) { r = 0; LEAVE(); }
    if (!(items = AllocVec(count * sizeof *items, MEMF_ANY))) { r = GKE_NOMEM; LEAVE(); }
    for (i = 0; i < count; i++) {
        items[i].service = (const char *)list[i].gi_Service; items[i].host = (const char *)list[i].gi_Host;
        items[i].user = (const char *)list[i].gi_User; items[i].label = (const char *)list[i].gi_Label;
        items[i].secret = list[i].gi_Secret; items[i].secret_len = list[i].gi_SecretLen;
    }
    if (from) gkl_owner(tag, (const char *)from);
    r = gkl_import(keys, from ? tag : owner, items, count, flags, &added);
    FreeVec(items);
    if (!r) r = (LONG)added;
    LEAVE();
}

static CONST_STRPTR GK_ErrorString(REG(d0, LONG error), B)
{
    static const char *const text[] = {
        "OK", "No such entry", "The keys are locked", "Wrong passphrase", "No copy of the keys opens",
        "No keys yet", "Already there", "The buffer is too small", "A service, host or user that breaks the naming rule",
        "Too big", "The keys file couldn't be read or written", "Not enough memory", "Cancelled",
        "The crypto or the random source failed",
        "An older copy is open: nothing can be saved until the newer passphrase is used"
    };
    (void)base;
    if (error > 0 || error < GKE_READONLY) return (CONST_STRPTR)"Unknown error";
    return (CONST_STRPTR)text[-error];
}
