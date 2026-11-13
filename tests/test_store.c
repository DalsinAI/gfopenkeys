/* test_store.c: host tests for gk_store (DESIGN.md section 9).
 * The file system is in memory and can be made to fail at any step, so a
 * crash at each point of a write can be checked. Argon2id runs small
 * (8 KiB, 1 pass) so the tests are quick; the format carries the settings.
 * MIT, Copyright (c) 2026 AmiCradle Team. */
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
    e->read = m_read; e->write = m_write; e->rename = m_rename; e->remove = m_remove;
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

static const gk_kdf KDF = { 1, 8, 1 };
#define PATH "ENVARC:GFOpenKeys/Default.keys"
#define PASS "correct horse"

static int has(gk_store *s, const char *svc, const char *host, const char *user, const char *want)
{
    uint8_t b[64];
    size_t n = sizeof b;
    if (gk_find(s, svc, host, user, b, &n)) return 0;
    return n == strlen(want) && !memcmp(b, want, n);
}

static int hexval(const char *h, uint8_t *out)
{
    size_t i, n = strlen(h) / 2;
    for (i = 0; i < n; i++) { unsigned v; sscanf(h + 2 * i, "%2x", &v); out[i] = (uint8_t)v; }
    return (int)n;
}

/* ---- the tests ------------------------------------------------------------ */

static void test_aead(void)
{
    /* libsodium's crypto_aead_chacha20poly1305 (original construction) */
    uint8_t key[32], nonce[8], ad[10], pt[10], want[26], ct[10], tag[16], back[10];
    hexval("4290bcb154173531f314af57f3be3b5006da371ece272afa1b5dbdd1100a1007", key);
    hexval("cd7cf67be39c794a", nonce);
    hexval("87e229d4500845a079c0", ad);
    hexval("86d09974840bded2a5ca", pt);
    hexval("e3e446f7ede9a19b62a4677dabf4e3d24b876bb284753896e1d6", want);
    gk_seal(ct, tag, pt, 10, ad, 10, key, nonce);
    CHECK(!memcmp(ct, want, 10));
    CHECK(!memcmp(tag, want + 10, 16));
    CHECK(gk_unseal(back, ct, 10, tag, ad, 10, key, nonce) == GKE_OK && !memcmp(back, pt, 10));
    ct[3] ^= 1;
    CHECK(gk_unseal(back, ct, 10, tag, ad, 10, key, nonce) == GKE_DAMAGED);
    ct[3] ^= 1; ad[0] ^= 1;
    CHECK(gk_unseal(back, ct, 10, tag, ad, 10, key, nonce) == GKE_DAMAGED);
}

static void test_names(void)
{
    char out[64];
    CHECK(gk_check_name("ssh", "example.org:22", "dale") == GKE_OK);
    CHECK(gk_check_name("ssh-key", "", "SHA256:abc/def") == GKE_OK);   /* '/' is fine in user */
    CHECK(gk_check_name("", "h", "u") == GKE_BADNAME);
    CHECK(gk_check_name("SSH", "h", "u") == GKE_BADNAME);
    CHECK(gk_check_name("a_b", "h", "u") == GKE_BADNAME);
    CHECK(gk_check_name("abcdefghijklmnopqrstuvwxyz012345", "h", "u") == GKE_BADNAME);   /* 32 */
    CHECK(gk_check_name("ftp", "a/b", "u") == GKE_BADNAME);
    CHECK(gk_check_name("ftp", "a\nb", "u") == GKE_BADNAME);
    CHECK(gk_check_name("ftp", "h", NULL) == GKE_BADNAME);
    CHECK(gk_escape("a/b%c\n", out, sizeof out) == 12 && !strcmp(out, "a%2Fb%25c%0A"));
    CHECK(gk_escape("abcdef", out, 4) == 3 && !strcmp(out, "abc"));
    CHECK(gk_escape("a/b", out, 4) == 1 && !strcmp(out, "a"));   /* never half an escape */
}

static void test_round_trip(void)
{
    fs x; gk_env e; gk_store *s;
    uint8_t b[8];
    size_t n;
    fs_init(&x, &e);
    CHECK(gk_open(&s, &e, PATH) == GKE_OK);
    CHECK(!gk_exists(s));
    CHECK(gk_unlock(s, PASS, strlen(PASS)) == GKE_NOSTORE);
    CHECK(gk_create(s, "", 0, &KDF) == GKE_BADPASS);
    CHECK(gk_create(s, PASS, strlen(PASS), &KDF) == GKE_OK);
    CHECK(gk_exists(s) && gk_is_unlocked(s));
    CHECK(gk_create(s, PASS, strlen(PASS), &KDF) == GKE_EXISTS);
    CHECK(gk_put(s, "ssh", "Example.ORG:22", "dale", (const uint8_t *)"hunter2", 7, "work", "GFOpenPuTTY", 0) == GKE_OK);
    CHECK(gk_put(s, "ssh", "example.org:22", "dale", (const uint8_t *)"x", 1, NULL, NULL, 0) == GKE_EXISTS);
    CHECK(gk_put(s, "ftp", "ftp.example.org:21", "anon", (const uint8_t *)"", 0, NULL, NULL, 0) == GKE_OK);
    CHECK(gk_put(s, "ftp", "h", "u", b, GK_MAX_SECRET + 1, NULL, NULL, 0) == GKE_TOOBIG);
    CHECK(gk_put(s, "Bad", "h", "u", b, 1, NULL, NULL, 0) == GKE_BADNAME);
    CHECK(gk_count(s) == 2);
    gk_lock(s);
    CHECK(!gk_is_unlocked(s) && gk_count(s) == 0);
    CHECK(gk_find(s, "ssh", "example.org:22", "dale", b, &n) == GKE_LOCKED);
    CHECK(gk_unlock(s, "wrong", 5) == GKE_BADPASS);
    CHECK(gk_unlock(s, PASS, strlen(PASS)) == GKE_OK);
    CHECK(has(s, "ssh", "EXAMPLE.org:22", "dale", "hunter2"));   /* host matched in any case */
    CHECK(!has(s, "ssh", "example.org:22", "Dale", "hunter2"));  /* user is exact */
    n = 3;
    CHECK(gk_find(s, "ssh", "example.org:22", "dale", b, &n) == GKE_SHORT && n == 7);
    n = 0;
    CHECK(gk_find(s, "ftp", "ftp.example.org:21", "anon", NULL, &n) == GKE_OK && n == 0);
    CHECK(gk_put(s, "ssh", "example.org:22", "dale", (const uint8_t *)"newpass", 7, NULL, NULL, GKF_REPLACE) == GKE_OK);
    CHECK(gk_delete(s, "ftp", "ftp.example.org:21", "anon") == GKE_OK);
    CHECK(gk_delete(s, "ftp", "ftp.example.org:21", "anon") == GKE_NOTFOUND);
    gk_close(s);
    CHECK(gk_open(&s, &e, PATH) == GKE_OK);
    CHECK(gk_unlock(s, PASS, strlen(PASS)) == GKE_OK);
    CHECK(gk_count(s) == 1 && has(s, "ssh", "example.org:22", "dale", "newpass"));
    gk_close(s);
    fs_free(&x);
}

static int lister(void *ctx, const gk_info *in)
{
    int *seen = ctx;
    CHECK(in->service && in->host && in->user && in->label && in->owner);
    if (!strcmp(in->user, "dale")) CHECK(!strcmp(in->label, "work") && !strcmp(in->owner, "GFOpenPuTTY") && in->created == 1000);
    (*seen)++;
    return *seen == 2;   /* stop after two */
}

static void test_list(void)
{
    fs x; gk_env e; gk_store *s;
    int seen = 0;
    fs_init(&x, &e);
    gk_open(&s, &e, PATH);
    gk_create(s, PASS, strlen(PASS), &KDF);
    gk_put(s, "ssh", "a", "dale", (const uint8_t *)"1", 1, "work", "GFOpenPuTTY", 0);
    gk_put(s, "ssh", "b", "x", (const uint8_t *)"2", 1, NULL, NULL, 0);
    gk_put(s, "ftp", "c", "y", (const uint8_t *)"3", 1, NULL, NULL, 0);
    gk_put(s, "ssh", "d", "z", (const uint8_t *)"4", 1, NULL, NULL, 0);
    CHECK(gk_list(s, "ssh", lister, &seen) == GKE_OK && seen == 2);
    seen = -10;
    CHECK(gk_list(s, NULL, lister, &seen) == GKE_OK && seen == -6);
    gk_lock(s);
    CHECK(gk_list(s, NULL, lister, &seen) == GKE_LOCKED);
    gk_close(s);
    fs_free(&x);
}

static void test_tamper(void)
{
    fs x; gk_env e; gk_store *s;
    mfile *m;
    size_t i, len;
    int ok = 1;
    fs_init(&x, &e);
    gk_open(&s, &e, PATH);
    gk_create(s, PASS, strlen(PASS), &KDF);
    gk_put(s, "ssh", "h", "u", (const uint8_t *)"secret", 6, NULL, NULL, 0);
    gk_lock(s);
    m = fs_get(&x, PATH);
    len = m->len;
    CHECK(fs_get(&x, PATH ".bak") != NULL);
    m_remove(&x, PATH ".bak");          /* only the one copy, so a flip can't be rescued */
    for (i = 0; i < len; i++) {
        int r;
        m->data[i] ^= 0x10;
        r = gk_unlock(s, PASS, strlen(PASS));
        if (r == GKE_OK) { ok = 0; printf("byte %lu flipped and still opened\n", (unsigned long)i); }
        gk_lock(s);
        m = fs_get(&x, PATH);
        m->data[i] ^= 0x10;
    }
    CHECK(ok);
    m->len = len - 1;
    CHECK(gk_unlock(s, PASS, strlen(PASS)) == GKE_DAMAGED);
    m->len = len;
    CHECK(gk_unlock(s, PASS, strlen(PASS)) == GKE_OK);
    /* no secret or passphrase in the file's bytes */
    for (i = 0; i + 7 <= len; i++) if (!memcmp(m->data + i, "secret", 6) || !memcmp(m->data + i, "correct", 7)) ok = 0;
    CHECK(ok);
    gk_close(s);
    fs_free(&x);
}

/* A crash at every write, rename and remove of a save: afterwards the store
 * opens with the passphrase and holds either the old or the new entry, never
 * neither, and a save that reported success is never lost. */
static void test_crash(void)
{
    fs base, x; gk_env e, be; gk_store *s;
    long at;
    int saw_new = 0, saw_old = 0;
    fs_init(&base, &be);
    gk_open(&s, &be, PATH);
    gk_create(s, PASS, strlen(PASS), &KDF);
    gk_put(s, "ssh", "h", "u", (const uint8_t *)"old", 3, NULL, NULL, 0);
    gk_close(s);
    fs_init(&x, &e);
    for (at = 0; at < 8; at++) {
        int r;
        fs_copy(&x, &base);
        gk_open(&s, &e, PATH);
        CHECK(gk_unlock(s, PASS, strlen(PASS)) == GKE_OK);
        x.ops = 0; x.crash_at = at;
        r = gk_put(s, "ssh", "h", "u", (const uint8_t *)"new", 3, NULL, NULL, GKF_REPLACE);
        if (r) CHECK(!gk_is_unlocked(s) || has(s, "ssh", "h", "u", "old"));  /* memory goes back too */
        gk_close(s);
        x.crash_at = -1;
        gk_open(&s, &e, PATH);
        CHECK(gk_unlock(s, PASS, strlen(PASS)) == GKE_OK);
        if (has(s, "ssh", "h", "u", "new")) saw_new = 1;
        else { CHECK(r != GKE_OK); CHECK(has(s, "ssh", "h", "u", "old")); saw_old = 1; }
        CHECK(fs_get(&x, PATH) != NULL);   /* the name is put back by the unlock */
        gk_close(s);
    }
    CHECK(saw_new && saw_old);
    /* a write that stores bad bytes is caught by the read-back */
    fs_copy(&x, &base);
    gk_open(&s, &e, PATH);
    gk_unlock(s, PASS, strlen(PASS));
    x.corrupt_write = 1;
    CHECK(gk_put(s, "ssh", "h", "u", (const uint8_t *)"new", 3, NULL, NULL, GKF_REPLACE) == GKE_IO);
    CHECK(fs_get(&x, PATH ".new") == NULL);
    CHECK(has(s, "ssh", "h", "u", "old"));
    gk_close(s);
    fs_free(&x); fs_free(&base);
}

static void test_recover(void)
{
    fs x; gk_env e; gk_store *s;
    mfile *m;
    uint64_t gen;
    fs_init(&x, &e);
    gk_open(&s, &e, PATH);
    gk_create(s, PASS, strlen(PASS), &KDF);
    gk_put(s, "ssh", "h", "u", (const uint8_t *)"one", 3, NULL, NULL, 0);
    gk_put(s, "ssh", "h", "u", (const uint8_t *)"two", 3, NULL, NULL, GKF_REPLACE);
    gk_lock(s);
    m = fs_get(&x, PATH);
    CHECK(gk_unlock(s, PASS, strlen(PASS)) == GKE_OK && gk_opened_from(s) == 0);
    gen = gk_generation(s);
    CHECK(gen == 3);                      /* create, put, put */
    gk_lock(s);
    m->data[m->len - 1] ^= 1;             /* the store is damaged: .bak still holds "one" */
    CHECK(gk_unlock(s, PASS, strlen(PASS)) == GKE_OK);
    CHECK(gk_opened_from(s) == 2 && has(s, "ssh", "h", "u", "one"));
    CHECK(gk_generation(s) == gen);       /* .bak was 2, saved again under the name as 3 */
    gk_lock(s);
    CHECK(gk_unlock(s, PASS, strlen(PASS)) == GKE_OK && gk_opened_from(s) == 0);  /* and was put back under the name */
    m = fs_get(&x, PATH);
    gk_lock(s);
    m->data[m->len - 1] ^= 1;
    m = fs_get(&x, PATH ".bak");          /* the damaged one from before */
    CHECK(m != NULL);
    if (m) m->len -= 1;
    m_remove(&x, PATH ".new");
    CHECK(gk_unlock(s, PASS, strlen(PASS)) == GKE_DAMAGED);
    gk_close(s);
    fs_free(&x);
}

static void test_timeout(void)
{
    fs x; gk_env e; gk_store *s;
    uint8_t b[8];
    size_t n = sizeof b;
    fs_init(&x, &e);
    gk_open(&s, &e, PATH);
    gk_create(s, PASS, strlen(PASS), &KDF);
    gk_put(s, "ssh", "h", "u", (const uint8_t *)"pw", 2, NULL, NULL, 0);
    CHECK(gk_seconds_left(s) == GK_DEFAULT_TIMEOUT);
    gk_set_timeout(s, 60);
    x.clock += 59;
    CHECK(gk_seconds_left(s) == 1);
    CHECK(gk_find(s, "ssh", "h", "u", b, &n) == GKE_OK);   /* a use restarts the clock */
    x.clock += 59;
    CHECK(gk_is_unlocked(s) && gk_seconds_left(s) == 1);
    { int seen = -100; CHECK(gk_list(s, NULL, lister, &seen) == GKE_OK); }   /* not a use */
    CHECK(gk_count(s) == 1 && gk_seconds_left(s) == 1);
    x.clock += 1;
    CHECK(!gk_is_unlocked(s) && gk_seconds_left(s) == 0);
    CHECK(gk_find(s, "ssh", "h", "u", b, &n) == GKE_LOCKED);
    gk_set_timeout(s, 0);
    gk_unlock(s, PASS, strlen(PASS));
    x.clock += 100000000;
    CHECK(gk_is_unlocked(s) && gk_seconds_left(s) == UINT32_MAX);
    gk_close(s);
    fs_free(&x);
}

static void test_import(void)
{
    fs x; gk_env e; gk_store *s;
    gk_import_item list[3];
    size_t added = 99;
    fs_init(&x, &e);
    gk_open(&s, &e, PATH);
    gk_create(s, PASS, strlen(PASS), &KDF);
    memset(list, 0, sizeof list);
    list[0].service = "ftp"; list[0].host = "a:21"; list[0].user = "u"; list[0].secret = (const uint8_t *)"p1"; list[0].secret_len = 2;
    list[1].service = "ftp"; list[1].host = "b:21"; list[1].user = "u"; list[1].secret = (const uint8_t *)"p2"; list[1].secret_len = 2; list[1].label = "B";
    list[2].service = "ftp"; list[2].host = "c/21"; list[2].user = "u"; list[2].secret = (const uint8_t *)"p3"; list[2].secret_len = 2;
    CHECK(gk_import(s, list, 3, "GFOpenFTP", 0, &added) == GKE_BADNAME && added == 0 && gk_count(s) == 0);  /* all or nothing */
    list[2].host = "c:21";
    CHECK(gk_import(s, list, 3, "GFOpenFTP", 0, &added) == GKE_OK && added == 3);
    CHECK(gk_import(s, list, 3, "GFOpenFTP", 0, &added) == GKE_OK && added == 0);     /* a second run adds nothing */
    list[0].secret = (const uint8_t *)"changed";
    list[0].secret_len = 7;
    CHECK(gk_import(s, list, 1, "GFOpenFTP", GKF_REPLACE, &added) == GKE_OK && added == 1);
    gk_close(s);
    gk_open(&s, &e, PATH);
    gk_unlock(s, PASS, strlen(PASS));
    CHECK(gk_count(s) == 3 && has(s, "ftp", "a:21", "u", "changed") && has(s, "ftp", "c:21", "u", "p3"));
    /* a failed save leaves memory as the file */
    x.ops = 0; x.crash_at = 0;
    list[0].host = "d:21";
    CHECK(gk_import(s, list, 1, "GFOpenFTP", 0, &added) == GKE_IO && added == 0);
    x.crash_at = -1;
    CHECK(gk_count(s) == 3);
    gk_close(s);
    fs_free(&x);
}

static void test_change_pass(void)
{
    fs x; gk_env e; gk_store *s;
    fs_init(&x, &e);
    gk_open(&s, &e, PATH);
    gk_create(s, PASS, strlen(PASS), &KDF);
    gk_put(s, "ssh", "h", "u", (const uint8_t *)"pw", 2, NULL, NULL, 0);
    CHECK(gk_change_pass(s, "", 0, &KDF) == GKE_BADPASS);
    {
        uint8_t before[96];
        memcpy(before, fs_get(&x, PATH)->data, 96);
        CHECK(gk_change_pass(s, "new pass", 8, &KDF) == GKE_OK);
        CHECK(memcmp(before + 24, fs_get(&x, PATH)->data + 24, 16));   /* a new Argon2id salt */
        CHECK(memcmp(before + 40, fs_get(&x, PATH)->data + 40, 8));    /* a new nonce */
    }
    gk_lock(s);
    CHECK(gk_unlock(s, PASS, strlen(PASS)) == GKE_BADPASS);   /* no copy, .bak included, opens with the old one */
    gk_lock(s);
    CHECK(gk_unlock(s, "new pass", 8) == GKE_OK && has(s, "ssh", "h", "u", "pw"));
    { gk_kdf bad = { 0, 8, 1 }; CHECK(gk_change_pass(s, "x", 1, &bad) == GKE_CRYPTO); }
    CHECK(has(s, "ssh", "h", "u", "pw"));
    gk_lock(s);
    CHECK(gk_unlock(s, "new pass", 8) == GKE_OK);
    gk_close(s);
    fs_free(&x);
}

/* The random source stuck on one value: every body salt is the same, but the
 * write counter is the nonce, so two saves never share key and nonce. */
static uint32_t stuck_rng;
static int m_random_stuck(void *u, uint8_t *out, size_t len) { (void)u; memset(out, (int)stuck_rng, len); return 0; }

static void test_counter_nonce(void)
{
    fs x; gk_env e; gk_store *s;
    uint8_t a[512], b[512];
    size_t la, lb;
    mfile *m;
    fs_init(&x, &e);
    e.random = m_random_stuck;
    gk_open(&s, &e, PATH);
    CHECK(gk_create(s, PASS, strlen(PASS), &KDF) == GKE_OK);
    CHECK(gk_put(s, "ssh", "h", "u", (const uint8_t *)"AAAA", 4, NULL, NULL, 0) == GKE_OK);
    m = fs_get(&x, PATH); la = m->len; CHECK(la <= sizeof a); memcpy(a, m->data, la);
    CHECK(gk_put(s, "ssh", "h", "u", (const uint8_t *)"BBBB", 4, NULL, NULL, GKF_REPLACE) == GKE_OK);
    m = fs_get(&x, PATH); lb = m->len; CHECK(lb <= sizeof b); memcpy(b, m->data, lb);
    CHECK(la == lb && !memcmp(a + 104, b + 104, 32));       /* the same salt both times */
    CHECK(memcmp(a + 96, b + 96, 8));                       /* but a new counter (the nonce) */
    {   /* XOR of the two bodies is not the XOR of the two plaintexts */
        size_t i, off = 104 + 32 + 4, same = 1;
        for (i = 0; i < la - 16 - off; i++) if (a[off + i] != b[off + i]) same = 0;
        CHECK(!same);
        /* the entry's secret is at the body's end: 'A'^'B' == 3 must not show there */
        for (i = 0, same = 1; i < 4; i++) if ((a[la - 20 + i] ^ b[la - 20 + i]) != 3) same = 0;
        CHECK(!same);
    }
    m->data[100] ^= 1;                                      /* the counter is in the AD */
    gk_lock(s);
    m_remove(&x, PATH ".bak");
    CHECK(gk_unlock(s, PASS, strlen(PASS)) == GKE_DAMAGED);
    gk_close(s);
    fs_free(&x);
}

int main(void)
{
    test_aead();
    test_names();
    test_round_trip();
    test_list();
    test_tamper();
    test_crash();
    test_recover();
    test_timeout();
    test_import();
    test_change_pass();
    test_counter_nonce();
    printf("%d/%d checks passed\n", checks - fails, checks);
    return fails != 0;
}
