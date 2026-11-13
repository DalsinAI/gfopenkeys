/* gk_lib.c: gfopenkeys.library's calls on top of gk_store (gk_lib.h).
 * MIT, Copyright (c) 2026 AmiCradle Team. */
#include "gk_lib.h"

#include <stdlib.h>
#include <string.h>

#include "gfopencrypto/gfopencrypto.h"

#define BACKOFF_AFTER 5          /* wrong passphrases before the waits start */
#define BACKOFF_MAX   64         /* seconds */

struct gk_lib {
    gk_store *s;
    gk_env env;
    gk_ui ui;
    gk_kdf kdf;
    char *count_path;            /* "<store>.count": the highest write counter seen (not secret) */
    unsigned fails;              /* wrong passphrases in a row */
    int rolled_back;
};

void gkl_owner(char out[GK_MAX_OWNER + 1], const char *raw)
{
    size_t o = 0;
    if (raw)
        for (; *raw && o < GK_MAX_OWNER; raw++)
            if ((unsigned char)*raw >= 0x20 && *raw != 0x7f) out[o++] = *raw;
    out[o] = 0;
    if (!o) strcpy(out, "(unnamed)");
}

int gkl_open(gk_lib **out, const gk_env *env, const gk_ui *ui, const char *path, const gk_kdf *kdf)
{
    gk_lib *l = calloc(1, sizeof *l);
    size_t n = strlen(path);
    int r;
    *out = NULL;
    if (!l) return GKE_NOMEM;
    l->env = *env; l->ui = *ui; l->kdf = *kdf;
    if (!(l->count_path = malloc(n + 7))) { free(l); return GKE_NOMEM; }
    memcpy(l->count_path, path, n); memcpy(l->count_path + n, ".count", 7);
    if ((r = gk_open(&l->s, env, path))) { free(l->count_path); free(l); return r; }
    *out = l;
    return GKE_OK;
}

void gkl_close(gk_lib *l)
{
    if (!l) return;
    gk_close(l->s);
    free(l->count_path);
    free(l);
}

gk_store *gkl_store(gk_lib *l) { return l->s; }

/* ---- the write counter seen before (DESIGN.md section 4, "Rolling back") -- */

static uint64_t seen_counter(gk_lib *l)
{
    uint8_t *p;
    size_t n, i;
    uint64_t v = 0;
    if (l->env.read(l->env.u, l->count_path, &p, &n)) return 0;
    for (i = 0; i < n && i < 16; i++) {
        uint8_t c = p[i];
        if (c >= '0' && c <= '9') v = v << 4 | (uint64_t)(c - '0');
        else if (c >= 'a' && c <= 'f') v = v << 4 | (uint64_t)(c - 'a' + 10);
        else break;
    }
    free(p);
    return v;
}

static void note_counter(gk_lib *l)
{
    static const char hex[] = "0123456789abcdef";
    uint64_t gen = gk_generation(l->s), seen = seen_counter(l);
    uint8_t t[16];
    int i;
    if (gen <= seen || gk_is_readonly(l->s)) return;
    for (i = 15; i >= 0; i--) { t[i] = (uint8_t)hex[gen & 15]; gen >>= 4; }
    l->env.write(l->env.u, l->count_path, t, sizeof t);
}

static void warn(gk_lib *l, int what, uint64_t a, uint64_t b) { if (l->ui.warn) l->ui.warn(l->ui.u, what, a, b); }

static void after_open(gk_lib *l)
{
    uint64_t gen = gk_generation(l->s), seen = seen_counter(l);
    l->rolled_back = gen < seen;
    if (gk_opened_from(l->s) > 0) warn(l, GKW_OLDER_COPY, gen, seen);
    if (gk_is_readonly(l->s)) warn(l, GKW_READONLY, gen, seen);
    if (l->rolled_back) warn(l, GKW_ROLLED_BACK, gen, seen);
    else note_counter(l);
}

/* ---- asking ----------------------------------------------------------------- */

static void backoff(gk_lib *l)
{
    uint32_t w;
    if (l->fails < BACKOFF_AFTER || !l->ui.wait) return;
    w = l->fails - BACKOFF_AFTER < 5 ? 2u << (l->fails - BACKOFF_AFTER) : BACKOFF_MAX;
    if (w > BACKOFF_MAX) w = BACKOFF_MAX;
    l->ui.wait(l->ui.u, w);
}

/* Ask until check() takes it or the user cancels. check gets the passphrase. */
static int ask_until(gk_lib *l, const char *owner, int (*check)(gk_lib *, const char *, size_t))
{
    char buf[GK_PASS_MAX];
    size_t len;
    int r;
    for (;;) {
        backoff(l);
        len = 0;
        r = l->ui.ask(l->ui.u, owner, l->fails, 0, buf, sizeof buf, &len);
        if (!r) r = check(l, buf, len < sizeof buf ? len : sizeof buf);
        oc_cleanse(buf, sizeof buf);
        if (r != GKE_BADPASS) break;
        l->fails++;
    }
    if (!r) l->fails = 0;
    return r;
}

static int try_unlock(gk_lib *l, const char *p, size_t n) { return gk_unlock(l->s, p, n); }
static int try_current(gk_lib *l, const char *p, size_t n) { return gk_check_pass(l->s, p, n); }

int gkl_unlock(gk_lib *l, const char *owner, unsigned long flags)
{
    int r;
    if (gk_is_unlocked(l->s)) return GKE_OK;
    if (!gk_exists(l->s)) return GKE_NOSTORE;
    if (flags & GKF_NOPROMPT) return GKE_LOCKED;
    if ((r = ask_until(l, owner, try_unlock))) return r;
    after_open(l);
    return GKE_OK;
}

void gkl_lock(gk_lib *l) { gk_lock(l->s); }

/* A new store: the passphrase typed twice (the requester compares them) */
static int create(gk_lib *l, const char *owner, unsigned long flags)
{
    char buf[GK_PASS_MAX];
    size_t len = 0;
    int r;
    if (flags & GKF_NOPROMPT) return GKE_NOSTORE;
    r = l->ui.ask(l->ui.u, owner, 0, 1, buf, sizeof buf, &len);
    if (!r) r = gk_create(l->s, buf, len < sizeof buf ? len : sizeof buf, &l->kdf);
    oc_cleanse(buf, sizeof buf);
    if (!r) note_counter(l);
    return r;
}

int gkl_find(gk_lib *l, const char *owner, const char *service, const char *host, const char *user,
             uint8_t *buf, size_t *len, unsigned long flags)
{
    int r;
    if (gk_check_name(service, host, user)) return GKE_BADNAME;   /* before any requester */
    if ((r = gkl_unlock(l, owner, flags))) return r;
    return gk_find(l->s, service, host, user, buf, len);
}

static int writable(gk_lib *l, const char *owner, unsigned long flags)
{
    int r;
    if (!gk_is_unlocked(l->s) && !gk_exists(l->s)) return create(l, owner, flags);
    if ((r = gkl_unlock(l, owner, flags))) return r;
    return gk_is_readonly(l->s) ? GKE_READONLY : GKE_OK;
}

int gkl_store_entry(gk_lib *l, const char *owner, const char *service, const char *host, const char *user,
                    const uint8_t *secret, size_t len, const char *label, unsigned long flags)
{
    int r;
    if (gk_check_name(service, host, user)) return GKE_BADNAME;
    if (len > GK_MAX_SECRET) return GKE_TOOBIG;
    if ((r = writable(l, owner, flags))) return r;
    r = gk_put(l->s, service, host, user, secret, len, label, owner, flags);
    if (!r) note_counter(l);
    return r;
}

int gkl_delete(gk_lib *l, const char *owner, const char *service, const char *host, const char *user, unsigned long flags)
{
    int r;
    if (gk_check_name(service, host, user)) return GKE_BADNAME;
    if (!gk_exists(l->s)) return GKE_NOTFOUND;
    if ((r = writable(l, owner, flags))) return r;
    r = gk_delete(l->s, service, host, user);
    if (!r) note_counter(l);
    return r;
}

int gkl_import(gk_lib *l, const char *owner, const gk_import_item *list, size_t count, unsigned long flags, size_t *added)
{
    int r;
    *added = 0;
    if ((r = writable(l, owner, flags))) return r;
    r = gk_import(l->s, list, count, owner, flags, added);
    if (!r) note_counter(l);
    return r;
}

int gkl_change_pass(gk_lib *l, const char *owner, const gk_kdf *kdf, unsigned long flags)
{
    char buf[GK_PASS_MAX];
    size_t len = 0;
    int r;
    if (flags & GKF_NOPROMPT) return GKE_LOCKED;   /* it can only ask, so never from ARexx */
    if ((r = writable(l, owner, flags))) return r;
    /* the current passphrase first, even though the store is unlocked */
    if ((r = ask_until(l, owner, try_current))) return r;
    r = l->ui.ask(l->ui.u, owner, 0, 1, buf, sizeof buf, &len);
    if (!r) r = gk_change_pass(l->s, buf, len < sizeof buf ? len : sizeof buf, kdf ? kdf : &l->kdf);
    oc_cleanse(buf, sizeof buf);
    if (!r) note_counter(l);
    return r;
}

void gkl_status(gk_lib *l, gk_status *st)
{
    memset(st, 0, sizeof *st);
    st->exists = gk_exists(l->s);
    st->unlocked = gk_is_unlocked(l->s);
    st->readonly = gk_is_readonly(l->s);
    st->rolled_back = st->unlocked && l->rolled_back;
    st->opened_from = gk_opened_from(l->s);
    st->count = gk_count(l->s);
    st->seconds_left = gk_seconds_left(l->s);
    st->counter = gk_generation(l->s);
}
