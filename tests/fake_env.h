/* fake_env.h: an in-memory file system, clock and random source for the
 * host tests; any write, rename or remove can be made to fail ("crash").
 * MIT, Copyright (c) 2026 AmiCradle Team. */
#ifndef FAKE_ENV_H
#define FAKE_ENV_H
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "gk_store.h"

static int fails, checks;
#define CHECK(c) do { checks++; if (!(c)) { fails++; printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #c); } } while (0)

/* ---- an in-memory file system --------------------------------------------- */

#define FILES 8
typedef struct mfile { char name[64]; uint8_t *data; size_t len; int used; } mfile;
typedef struct fs {
    mfile f[FILES];
    long ops;          /* write/rename/remove calls so far */
    long crash_at;     /* the op that "loses power" (and every one after it); -1 none */
    int corrupt_write; /* flip a bit in what the next write stores */
    uint64_t clock;
    uint32_t rng;
} fs;

static mfile *fs_get(fs *x, const char *name)
{
    int i;
    for (i = 0; i < FILES; i++) if (x->f[i].used && !strcmp(x->f[i].name, name)) return &x->f[i];
    return NULL;
}

static int dead(fs *x) { return x->crash_at >= 0 && x->ops++ >= x->crash_at; }

static int m_read(void *u, const char *name, uint8_t **data, size_t *len)
{
    mfile *m = fs_get(u, name);
    if (!m) return GKE_NOTFOUND;
    *data = malloc(m->len ? m->len : 1);
    if (!*data) return GKE_IO;
    memcpy(*data, m->data, m->len);
    *len = m->len;
    return 0;
}

static int m_write(void *u, const char *name, const uint8_t *data, size_t len)
{
    fs *x = u;
    mfile *m;
    int i;
    if (dead(x)) return GKE_IO;
    if (!(m = fs_get(x, name)))
        for (i = 0; i < FILES && !m; i++) if (!x->f[i].used) { m = &x->f[i]; m->used = 1; strcpy(m->name, name); m->data = NULL; }
    if (!m) return GKE_IO;
    free(m->data);
    m->data = malloc(len ? len : 1);
    memcpy(m->data, data, len);
    m->len = len;
    if (x->corrupt_write && len > 100) { m->data[len - 20] ^= 1; x->corrupt_write = 0; }
    return 0;
}

static int m_rename(void *u, const char *from, const char *to)
{
    fs *x = u;
    mfile *m;
    if (dead(x)) return GKE_IO;
    if (fs_get(x, to) || !(m = fs_get(x, from))) return GKE_IO;
    strcpy(m->name, to);
    return 0;
}

static int m_remove(void *u, const char *name)
{
    fs *x = u;
    mfile *m;
    if (dead(x)) return GKE_IO;
    if ((m = fs_get(x, name))) { free(m->data); memset(m, 0, sizeof *m); }
    return 0;
}

/* remove() as AmigaOS DeleteFile() does it: a missing file is an error.
 * Every test uses it, so the store never relies on the kinder answer. */
static int m_remove_strict(void *u, const char *name) { return fs_get(u, name) ? m_remove(u, name) : GKE_IO; }

static int m_random(void *u, uint8_t *out, size_t len)
{
    fs *x = u;
    while (len--) { x->rng = x->rng * 1103515245u + 12345u; *out++ = (uint8_t)(x->rng >> 16); }
    return 0;
}

static uint64_t m_now(void *u) { return ((fs *)u)->clock; }
static void *m_alloc(void *u, size_t len) { (void)u; return malloc(len); }
static void m_release(void *u, void *p, size_t len) { (void)u; (void)len; free(p); }

static void fs_init(fs *x, gk_env *e)
{
    memset(x, 0, sizeof *x);
    x->crash_at = -1;
    x->clock = 1000;
    x->rng = 42;
    e->read = m_read; e->write = m_write; e->rename = m_rename; e->remove = m_remove_strict;
    e->random = m_random; e->now = m_now; e->alloc = m_alloc; e->release = m_release; e->u = x;
}

static void fs_free(fs *x) { int i; for (i = 0; i < FILES; i++) free(x->f[i].data); memset(x->f, 0, sizeof x->f); }

static void fs_copy(fs *to, const fs *from)
{
    int i;
    fs_free(to);
    for (i = 0; i < FILES; i++) {
        to->f[i] = from->f[i];
        if (from->f[i].used) { to->f[i].data = malloc(from->f[i].len ? from->f[i].len : 1); memcpy(to->f[i].data, from->f[i].data, from->f[i].len); }
    }
}

#endif
