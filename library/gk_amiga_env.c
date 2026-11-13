/* gk_amiga_env.c: gk_env on dos.library, and the C memory calls the core
 * uses, on exec (a library has no libnix start-up to set up malloc).
 * MIT, Copyright (c) 2026 AmiCradle Team. */
#include <exec/types.h>
#include <exec/memory.h>
#include <dos/dos.h>
#include <dos/dosextens.h>
#include <proto/exec.h>
#include <proto/dos.h>
#include <proto/gfopentls.h>

#include <string.h>

#include "gk_amiga.h"

#define READ_MAX (32UL * 1024 * 1024)   /* bigger than any store GK_MAX_ENTRIES allows */

/* ---- malloc and friends: AllocVec-like, with the size kept in front -------- */

void *malloc(size_t n)
{
    ULONG *p = AllocMem(n + 8, MEMF_ANY);   /* 8 in front keeps the 8-byte alignment */
    if (!p) return NULL;
    p[0] = n + 8;
    return p + 2;
}

void *calloc(size_t a, size_t b)
{
    size_t n = a * b;
    ULONG *p;
    if (b && n / b != a) return NULL;
    if (!(p = AllocMem(n + 8, MEMF_ANY | MEMF_CLEAR))) return NULL;
    p[0] = n + 8;
    return p + 2;
}

void free(void *q)
{
    ULONG *p;
    if (!q) return;
    p = (ULONG *)q - 2;
    FreeMem(p, p[0]);
}

void *realloc(void *q, size_t n)
{
    void *r;
    size_t old;
    if (!q) return malloc(n);
    old = ((ULONG *)q - 2)[0] - 8;
    if (!(r = malloc(n))) return NULL;
    memcpy(r, q, old < n ? old : n);
    free(q);
    return r;
}

/* ---- gk_env ------------------------------------------------------------------ */

static int e_read(void *u, const char *name, uint8_t **data, size_t *len)
{
    BPTR fh = Open((CONST_STRPTR)name, MODE_OLDFILE);
    LONG size, got;
    (void)u;
    if (!fh) return IoErr() == ERROR_OBJECT_NOT_FOUND ? GKE_NOTFOUND : GKE_IO;
    Seek(fh, 0, OFFSET_END);
    size = Seek(fh, 0, OFFSET_BEGINNING);
    if (size < 0 || (ULONG)size > READ_MAX || !(*data = malloc(size ? size : 1))) { Close(fh); return GKE_IO; }
    got = size ? Read(fh, *data, size) : 0;
    Close(fh);
    if (got != size) { free(*data); *data = NULL; return GKE_IO; }
    *len = (size_t)size;
    return GKE_OK;
}

static int e_write(void *u, const char *name, const uint8_t *data, size_t len)
{
    BPTR fh = Open((CONST_STRPTR)name, MODE_NEWFILE);
    LONG put;
    (void)u;
    if (!fh) return GKE_IO;
    put = len ? Write(fh, (APTR)data, (LONG)len) : 0;
    if (!Close(fh) || put != (LONG)len) return GKE_IO;   /* Close flushes: its answer counts */
    return GKE_OK;
}

static int e_rename(void *u, const char *from, const char *to)
{
    (void)u;
    return Rename((CONST_STRPTR)from, (CONST_STRPTR)to) ? GKE_OK : GKE_IO;
}

static int e_remove(void *u, const char *name)
{
    (void)u;
    if (DeleteFile((CONST_STRPTR)name)) return GKE_OK;
    return IoErr() == ERROR_OBJECT_NOT_FOUND ? GKE_OK : GKE_IO;
}

static int e_random(void *u, uint8_t *out, size_t len)
{
    (void)u;
    return OT_Random(out, (LONG)len) == OTERR_OK ? GKE_OK : GKE_CRYPTO;
}

static uint64_t e_now(void *u)
{
    struct DateStamp ds;
    (void)u;
    DateStamp(&ds);
    return (uint64_t)ds.ds_Days * 86400u + (uint64_t)ds.ds_Minute * 60u + (uint64_t)(ds.ds_Tick / TICKS_PER_SECOND);
}

/* Argon2id's area: AllocMem keeps the 8-byte alignment it asks for. Argon2
 * wipes it itself before answering; FreeMem gives it back. */
static void *e_alloc(void *u, size_t len) { (void)u; return AllocMem(len, MEMF_ANY); }
static void e_release(void *u, void *p, size_t len) { (void)u; if (p) FreeMem(p, len); }

void gk_amiga_env(gk_env *e)
{
    e->read = e_read; e->write = e_write; e->rename = e_rename; e->remove = e_remove;
    e->random = e_random; e->now = e_now; e->alloc = e_alloc; e->release = e_release;
    e->u = NULL;
}

/* ENVARC:GFOpenKeys on first use */
void gk_amiga_make_drawer(const char *drawer)
{
    BPTR l = Lock((CONST_STRPTR)drawer, SHARED_LOCK);
    if (!l) l = CreateDir((CONST_STRPTR)drawer);
    if (l) UnLock(l);
}
