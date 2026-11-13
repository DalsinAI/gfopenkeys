/* gk_store.c: the keystore's core (gk_store.h, DESIGN.md sections 3 to 5).
 *
 * The file, big-endian:
 *   "GFKS" 01 00 00 00                       magic and version
 *   type passes m_kib lanes (4 x 32 bits)    Argon2id's settings (type 2)
 *   salt[16]                                 Argon2id's salt
 *   nonce[8] key[32] tag[16]                 the data key, sealed under the master key
 *   salt[32] length(32 bits) body[length] tag[16]
 * The master key is Argon2id(passphrase); it only opens the data key. The
 * body is sealed under HKDF-SHA256(data key, the body's salt), a new salt
 * each write, so its zero nonce is never reused. The data key's seal covers
 * the 40 bytes before it, the body's seal the 96 bytes before the body salt.
 *
 * The body, once opened: "GKB1", the write counter (64 bits, one more each
 * save, so an older copy put back in place can be told), count, then each entry: service, host,
 * user, label, owner (16-bit length + bytes each), created, last used (64
 * bits each), the secret (16-bit length + bytes).
 *
 * MIT, Copyright (c) 2026 AmiCradle Team. */
#include "gk_store.h"

#include <stdlib.h>
#include <string.h>

#include "gfopencrypto/gfopencrypto.h"

#define HEAD_KDF   8
#define HEAD_WRAP  40          /* the data key's seal covers bytes 0..39 */
#define HEAD_BODY  96          /* the body's seal covers bytes 0..95 */
#define BODY_SALT  32
#define TAG        16
#define KEY        32

typedef struct entry {
    char *service, *host, *user, *label, *owner;
    uint64_t created, last_used;
    uint8_t *secret;
    size_t secret_len;
} entry;

struct gk_store {
    gk_env env;
    char *path, *path_new, *path_bak;
    int unlocked;
    uint8_t head[HEAD_BODY];   /* the file's header while unlocked (kdf and the sealed data key) */
    uint8_t dkey[KEY];
    entry *e;
    size_t n, cap;
    uint32_t timeout;
    uint64_t last_use;
    uint64_t gen;              /* the write counter of what is open */
    int from;                  /* which copy the last unlock opened: 0 the store, 1 .new, 2 .bak */
};

static const char *const BODY_INFO = "gfopenkeys body v1";

/* ---- bytes ---------------------------------------------------------------- */

static void be32(uint8_t *p, uint32_t v) { p[0] = (uint8_t)(v >> 24); p[1] = (uint8_t)(v >> 16); p[2] = (uint8_t)(v >> 8); p[3] = (uint8_t)v; }
static uint32_t rd32(const uint8_t *p) { return (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 | (uint32_t)p[2] << 8 | p[3]; }
static void le64(uint8_t *p, uint64_t v) { int i; for (i = 0; i < 8; i++) p[i] = (uint8_t)(v >> (8 * i)); }

typedef struct buf { uint8_t *p; size_t n, cap; int bad; } buf;

static void put(buf *b, const void *d, size_t n)
{
    if (b->bad) return;
    if (b->n + n > b->cap) {
        size_t c = b->cap ? b->cap * 2 : 1024;
        uint8_t *q;
        while (c < b->n + n) c *= 2;
        q = malloc(c);
        if (!q) { b->bad = 1; return; }
        if (b->p) { memcpy(q, b->p, b->n); oc_cleanse(b->p, b->cap); free(b->p); }
        b->p = q; b->cap = c;
    }
    memcpy(b->p + b->n, d, n);
    b->n += n;
}
static void put16s(buf *b, const void *d, size_t n) { uint8_t l[2] = { (uint8_t)(n >> 8), (uint8_t)n }; put(b, l, 2); put(b, d, n); }
static void put64(buf *b, uint64_t v) { uint8_t q[8]; be32(q, (uint32_t)(v >> 32)); be32(q + 4, (uint32_t)v); put(b, q, 8); }
static void buf_wipe(buf *b) { if (b->p) { oc_cleanse(b->p, b->cap); free(b->p); } b->p = NULL; b->n = b->cap = 0; }

typedef struct rd { const uint8_t *p; size_t n, at; int bad; } rd;
static const uint8_t *take(rd *r, size_t n) { const uint8_t *q; if (r->bad || r->n - r->at < n) { r->bad = 1; return NULL; } q = r->p + r->at; r->at += n; return q; }
static uint64_t take64(rd *r) { const uint8_t *q = take(r, 8); return q ? (uint64_t)rd32(q) << 32 | rd32(q + 4) : 0; }
static char *take_str(rd *r, size_t max)
{
    const uint8_t *l = take(r, 2), *q;
    size_t n;
    char *s;
    if (!l) return NULL;
    n = (size_t)l[0] << 8 | l[1];
    if (n > max || !(q = take(r, n)) || memchr(q, 0, n)) { r->bad = 1; return NULL; }
    if (!(s = malloc(n + 1))) { r->bad = 1; return NULL; }
    memcpy(s, q, n); s[n] = 0;
    return s;
}

static char *dup_s(const char *s) { size_t n = strlen(s ? s : ""); char *d = malloc(n + 1); if (d) memcpy(d, s ? s : "", n + 1); return d; }

/* ---- the AEAD ------------------------------------------------------------- */

static void mac(uint8_t tag[16], const uint8_t *ct, size_t len, const uint8_t *ad, size_t ad_len, const uint8_t pk[32])
{
    buf b = { 0 };
    uint8_t l[8];
    put(&b, ad, ad_len); le64(l, ad_len); put(&b, l, 8);
    put(&b, ct, len); le64(l, len); put(&b, l, 8);
    if (b.bad) { memset(tag, 0, 16); buf_wipe(&b); return; }   /* a wrong tag: never accepted */
    oc_poly1305(tag, b.p, b.n, pk);
    buf_wipe(&b);
}

void gk_seal(uint8_t *out, uint8_t tag[16], const uint8_t *in, size_t len,
             const uint8_t *ad, size_t ad_len, const uint8_t key[32], const uint8_t nonce[8])
{
    uint8_t pk[64];
    oc_chacha20_xor(pk, NULL, 64, key, nonce, 0);
    oc_chacha20_xor(out, in, len, key, nonce, 1);
    mac(tag, out, len, ad, ad_len, pk);
    oc_cleanse(pk, sizeof pk);
}

int gk_unseal(uint8_t *out, const uint8_t *in, size_t len, const uint8_t tag[16],
              const uint8_t *ad, size_t ad_len, const uint8_t key[32], const uint8_t nonce[8])
{
    uint8_t pk[64], t[16];
    int ok;
    oc_chacha20_xor(pk, NULL, 64, key, nonce, 0);
    mac(t, in, len, ad, ad_len, pk);
    oc_cleanse(pk, sizeof pk);
    ok = oc_ct_equal(t, tag, 16);
    oc_cleanse(t, sizeof t);
    if (!ok) return GKE_DAMAGED;
    oc_chacha20_xor(out, in, len, key, nonce, 1);
    return GKE_OK;
}

/* ---- names ---------------------------------------------------------------- */

int gk_check_name(const char *service, const char *host, const char *user)
{
    size_t i, n;
    if (!service || !host || !user) return GKE_BADNAME;
    n = strlen(service);
    if (!n || n > GK_MAX_SERVICE) return GKE_BADNAME;
    for (i = 0; i < n; i++)
        if (!((service[i] >= 'a' && service[i] <= 'z') || (service[i] >= '0' && service[i] <= '9') || service[i] == '-'))
            return GKE_BADNAME;
    if (strlen(host) > GK_MAX_PART || strlen(user) > GK_MAX_PART) return GKE_BADNAME;
    for (i = 0; host[i]; i++)
        if ((unsigned char)host[i] < 0x20 || host[i] == 0x7f || host[i] == '/') return GKE_BADNAME;
    return GKE_OK;
}

size_t gk_escape(const char *in, char *out, size_t cap)
{
    static const char hex[] = "0123456789ABCDEF";
    size_t o = 0;
    if (!cap) return 0;
    for (; in && *in; in++) {
        unsigned char c = (unsigned char)*in;
        if (c == '/' || c == '%' || c < 0x20 || c == 0x7f) {
            if (o + 4 > cap) break;
            out[o++] = '%'; out[o++] = hex[c >> 4]; out[o++] = hex[c & 15];
        } else {
            if (o + 2 > cap) break;
            out[o++] = (char)c;
        }
    }
    out[o] = 0;
    return o;
}

/* the host part as kept: ASCII letters in lower case */
static char *host_key(const char *host)
{
    char *h = dup_s(host);
    size_t i;
    if (h) for (i = 0; h[i]; i++) if (h[i] >= 'A' && h[i] <= 'Z') h[i] = (char)(h[i] + 32);
    return h;
}

/* ---- entries -------------------------------------------------------------- */

static void entry_free(entry *x)
{
    free(x->service); free(x->host); free(x->user); free(x->label); free(x->owner);
    if (x->secret) { oc_cleanse(x->secret, x->secret_len); free(x->secret); }
    memset(x, 0, sizeof *x);
}

static void entries_free(gk_store *s)
{
    size_t i;
    for (i = 0; i < s->n; i++) entry_free(&s->e[i]);
    free(s->e);
    s->e = NULL; s->n = s->cap = 0;
}

static long find_at(gk_store *s, const char *service, const char *host, const char *user)
{
    size_t i;
    for (i = 0; i < s->n; i++)
        if (!strcmp(s->e[i].service, service) && !strcmp(s->e[i].host, host) && !strcmp(s->e[i].user, user))
            return (long)i;
    return -1;
}

static int body_encode(gk_store *s, buf *b)
{
    size_t i;
    uint8_t c[4];
    put(b, "GKB1", 4);
    put64(b, s->gen);
    be32(c, (uint32_t)s->n); put(b, c, 4);
    for (i = 0; i < s->n; i++) {
        const entry *x = &s->e[i];
        put16s(b, x->service, strlen(x->service)); put16s(b, x->host, strlen(x->host));
        put16s(b, x->user, strlen(x->user)); put16s(b, x->label, strlen(x->label));
        put16s(b, x->owner, strlen(x->owner));
        put64(b, x->created); put64(b, x->last_used);
        put16s(b, x->secret, x->secret_len);
    }
    return b->bad ? GKE_NOMEM : GKE_OK;
}

static int body_decode(gk_store *s, const uint8_t *p, size_t n)
{
    rd r = { p, n, 0, 0 };
    const uint8_t *m = take(&r, 4), *c;
    uint64_t gen = take64(&r);
    uint32_t count, i;
    c = take(&r, 4);
    if (!m || !c || memcmp(m, "GKB1", 4)) return GKE_DAMAGED;
    s->gen = gen;
    count = rd32(c);
    if (count > GK_MAX_ENTRIES) return GKE_DAMAGED;
    if (count && !(s->e = calloc(count, sizeof *s->e))) return GKE_NOMEM;
    s->cap = count;
    for (i = 0; i < count; i++) {
        entry *x = &s->e[i];
        const uint8_t *l, *q;
        size_t sl;
        x->service = take_str(&r, GK_MAX_SERVICE); x->host = take_str(&r, GK_MAX_PART);
        x->user = take_str(&r, GK_MAX_PART); x->label = take_str(&r, GK_MAX_LABEL);
        x->owner = take_str(&r, GK_MAX_OWNER);
        x->created = take64(&r); x->last_used = take64(&r);
        s->n = i + 1;
        l = take(&r, 2);
        if (r.bad || !l) break;
        sl = (size_t)l[0] << 8 | l[1];
        if (sl > GK_MAX_SECRET || !(q = take(&r, sl))) { r.bad = 1; break; }
        if (!(x->secret = malloc(sl ? sl : 1))) { r.bad = 1; break; }
        memcpy(x->secret, q, sl); x->secret_len = sl;
        if (gk_check_name(x->service, x->host, x->user)) { r.bad = 1; break; }
    }
    if (r.bad || r.at != n) { entries_free(s); return GKE_DAMAGED; }
    return GKE_OK;
}

/* ---- keys ----------------------------------------------------------------- */

static int master_key(gk_store *s, uint8_t mk[KEY], const uint8_t *head, const char *pass, size_t pass_len)
{
    uint32_t type = rd32(head + HEAD_KDF), passes = rd32(head + HEAD_KDF + 4), m = rd32(head + HEAD_KDF + 8),
             lanes = rd32(head + HEAD_KDF + 12);
    size_t need;
    void *mem;
    int r;
    if (type != OC_ARGON2ID || !passes || passes > 64 || lanes != 1 || m < 8 || m > 4u * 1024 * 1024) return GKE_DAMAGED;
    need = oc_argon2_memory(m, lanes);
    if (!(mem = s->env.alloc(s->env.u, need))) return GKE_NOMEM;
    r = oc_argon2(OC_ARGON2ID, mk, KEY, pass, pass_len, head + HEAD_KDF + 16, 16, NULL, 0, NULL, 0, passes, m, lanes, mem);
    s->env.release(s->env.u, mem, need);
    return r ? GKE_CRYPTO : GKE_OK;
}

static int body_key(uint8_t bk[KEY], const uint8_t dkey[KEY], const uint8_t salt[BODY_SALT])
{
    return oc_hkdf_sha256(salt, BODY_SALT, dkey, KEY, BODY_INFO, strlen(BODY_INFO), bk, KEY) ? GKE_CRYPTO : GKE_OK;
}

/* ---- the file ------------------------------------------------------------- */

/* The whole file for the store as it is now: *out malloc'ed */
static int file_make(gk_store *s, uint8_t **out, size_t *len)
{
    buf body = { 0 }, f = { 0 };
    uint8_t salt[BODY_SALT], bk[KEY], tag[TAG], l[4], zero[8] = { 0 };
    uint8_t *ct;
    int r;
    if ((r = body_encode(s, &body))) { buf_wipe(&body); return r; }
    if (s->env.random(s->env.u, salt, sizeof salt)) { buf_wipe(&body); return GKE_CRYPTO; }
    if ((r = body_key(bk, s->dkey, salt))) { buf_wipe(&body); return r; }
    if (!(ct = malloc(body.n ? body.n : 1))) { buf_wipe(&body); oc_cleanse(bk, KEY); return GKE_NOMEM; }
    gk_seal(ct, tag, body.p, body.n, s->head, HEAD_BODY, bk, zero);
    oc_cleanse(bk, KEY);
    put(&f, s->head, HEAD_BODY); put(&f, salt, BODY_SALT);
    be32(l, (uint32_t)body.n); put(&f, l, 4);
    put(&f, ct, body.n); put(&f, tag, TAG);
    free(ct);
    buf_wipe(&body);
    if (f.bad) { buf_wipe(&f); return GKE_NOMEM; }
    *out = f.p; *len = f.n;            /* the file holds nothing secret: no wipe needed on free */
    return GKE_OK;
}

/* Open file bytes with the passphrase (pass) or with the data key we hold (pass NULL).
 * On success with pass: s->head and s->dkey set. Entries decoded into s when decode. */
static int file_open(gk_store *s, const uint8_t *p, size_t n, const char *pass, size_t pass_len, int decode)
{
    uint8_t mk[KEY], dk[KEY], bk[KEY], zero[8] = { 0 };
    uint32_t blen;
    uint8_t *pt;
    int r;
    if (n < HEAD_BODY + BODY_SALT + 4 + TAG || memcmp(p, "GFKS\x01\0\0\0", 8)) return GKE_DAMAGED;
    blen = rd32(p + HEAD_BODY + BODY_SALT);
    if ((size_t)blen != n - (HEAD_BODY + BODY_SALT + 4 + TAG)) return GKE_DAMAGED;
    if (pass) {
        if ((r = master_key(s, mk, p, pass, pass_len))) return r;
        r = gk_unseal(dk, p + HEAD_WRAP + 8, KEY, p + HEAD_WRAP + 8 + KEY, p, HEAD_WRAP, mk, p + HEAD_WRAP);
        oc_cleanse(mk, KEY);
        if (r) return GKE_BADPASS;
    } else {
        memcpy(dk, s->dkey, KEY);
    }
    if ((r = body_key(bk, dk, p + HEAD_BODY))) { oc_cleanse(dk, KEY); return r; }
    if (!(pt = malloc(blen ? blen : 1))) { oc_cleanse(dk, KEY); oc_cleanse(bk, KEY); return GKE_NOMEM; }
    r = gk_unseal(pt, p + HEAD_BODY + BODY_SALT + 4, blen, p + n - TAG, p, HEAD_BODY, bk, zero);
    oc_cleanse(bk, KEY);
    if (!r && decode) {
        entries_free(s);
        r = body_decode(s, pt, blen);
    }
    oc_cleanse(pt, blen); free(pt);
    if (!r && pass) { memcpy(s->head, p, HEAD_BODY); memcpy(s->dkey, dk, KEY); }
    oc_cleanse(dk, KEY);
    return r;
}

/* Write the store: .new, read back and opened, the old one to .bak, .new to the name */
static int file_save(gk_store *s)
{
    uint8_t *f, *back = NULL;
    size_t n, bn = 0;
    int r;
    s->gen++;
    if ((r = file_make(s, &f, &n))) { s->gen--; return r; }
    r = s->env.write(s->env.u, s->path_new, f, n);
    free(f);
    if (r) return GKE_IO;
    if (s->env.read(s->env.u, s->path_new, &back, &bn)) return GKE_IO;
    r = file_open(s, back, bn, NULL, 0, 0);
    free(back);
    if (r) { s->env.remove(s->env.u, s->path_new); return GKE_IO; }
    if (s->env.read(s->env.u, s->path, &back, &bn) == GKE_OK) {
        free(back);
        if (s->env.remove(s->env.u, s->path_bak) || s->env.rename(s->env.u, s->path, s->path_bak)) return GKE_IO;
    }
    if (s->env.rename(s->env.u, s->path_new, s->path)) return GKE_IO;
    return GKE_OK;
}

/* ---- the store ------------------------------------------------------------ */

static char *join(const char *a, const char *b)
{
    size_t x = strlen(a), y = strlen(b);
    char *p = malloc(x + y + 1);
    if (p) { memcpy(p, a, x); memcpy(p + x, b, y + 1); }
    return p;
}

int gk_open(gk_store **out, const gk_env *env, const char *path)
{
    gk_store *s = calloc(1, sizeof *s);
    *out = NULL;
    if (!s) return GKE_NOMEM;
    s->env = *env;
    s->path = dup_s(path); s->path_new = join(path, ".new"); s->path_bak = join(path, ".bak");
    s->timeout = GK_DEFAULT_TIMEOUT;
    if (!s->path || !s->path_new || !s->path_bak) { gk_close(s); return GKE_NOMEM; }
    *out = s;
    return GKE_OK;
}

void gk_close(gk_store *s)
{
    if (!s) return;
    gk_lock(s);
    free(s->path); free(s->path_new); free(s->path_bak);
    free(s);
}

int gk_exists(gk_store *s)
{
    const char *names[3];
    int i;
    names[0] = s->path; names[1] = s->path_new; names[2] = s->path_bak;
    for (i = 0; i < 3; i++) {
        uint8_t *p; size_t n;
        if (s->env.read(s->env.u, names[i], &p, &n) == GKE_OK) { free(p); return 1; }
    }
    return 0;
}

static void touch(gk_store *s) { s->last_use = s->env.now(s->env.u); }

static int new_head(gk_store *s, const gk_kdf *kdf, const char *pass, size_t pass_len)
{
    uint8_t h[HEAD_BODY], mk[KEY], nonce[8];
    int r;
    if (!kdf) return GKE_CRYPTO;
    memcpy(h, "GFKS\x01\0\0\0", 8);
    be32(h + HEAD_KDF, OC_ARGON2ID); be32(h + HEAD_KDF + 4, kdf->passes);
    be32(h + HEAD_KDF + 8, kdf->m_kib); be32(h + HEAD_KDF + 12, kdf->lanes);
    if (s->env.random(s->env.u, h + HEAD_KDF + 16, 16) || s->env.random(s->env.u, nonce, 8)) return GKE_CRYPTO;
    if ((r = master_key(s, mk, h, pass, pass_len))) return r == GKE_DAMAGED ? GKE_CRYPTO : r;   /* settings out of range */
    memcpy(h + HEAD_WRAP, nonce, 8);
    gk_seal(h + HEAD_WRAP + 8, h + HEAD_WRAP + 8 + KEY, s->dkey, KEY, h, HEAD_WRAP, mk, nonce);
    oc_cleanse(mk, KEY);
    memcpy(s->head, h, HEAD_BODY);
    return GKE_OK;
}

int gk_create(gk_store *s, const char *pass, size_t pass_len, const gk_kdf *kdf)
{
    int r;
    if (gk_exists(s)) return GKE_EXISTS;
    if (!pass_len) return GKE_BADPASS;
    gk_lock(s);
    if (s->env.random(s->env.u, s->dkey, KEY)) return GKE_CRYPTO;
    s->gen = 0; s->from = 0;
    if ((r = new_head(s, kdf, pass, pass_len)) || (r = file_save(s))) { gk_lock(s); return r; }
    s->unlocked = 1;
    touch(s);
    return GKE_OK;
}

int gk_unlock(gk_store *s, const char *pass, size_t pass_len)
{
    const char *names[3];
    int i, r, bad_pass = 0, any = 0;
    gk_lock(s);
    /* .new first after the name: it was read back and checked before the old file went to .bak */
    names[0] = s->path; names[1] = s->path_new; names[2] = s->path_bak;
    for (i = 0; i < 3; i++) {
        uint8_t *p; size_t n;
        if (s->env.read(s->env.u, names[i], &p, &n)) continue;
        any = 1;
        r = file_open(s, p, n, pass, pass_len, 1);
        free(p);
        if (!r) {
            s->unlocked = 1;
            s->from = i;
            touch(s);
            if (i) file_save(s);      /* put the good copy back under the name */
            return GKE_OK;
        }
        if (r == GKE_BADPASS) bad_pass = 1;
        else if (r == GKE_NOMEM || r == GKE_CRYPTO) return r;
    }
    if (!any) return GKE_NOSTORE;
    return bad_pass ? GKE_BADPASS : GKE_DAMAGED;
}

void gk_lock(gk_store *s)
{
    entries_free(s);
    oc_cleanse(s->dkey, KEY);
    oc_cleanse(s->head, sizeof s->head);
    s->unlocked = 0;
}

int gk_is_unlocked(gk_store *s)
{
    if (s->unlocked && s->timeout && s->env.now(s->env.u) - s->last_use >= s->timeout) gk_lock(s);
    return s->unlocked;
}

void gk_set_timeout(gk_store *s, uint32_t seconds) { s->timeout = seconds; }

uint32_t gk_seconds_left(gk_store *s)
{
    uint64_t gone;
    if (!gk_is_unlocked(s)) return 0;
    if (!s->timeout) return UINT32_MAX;
    gone = s->env.now(s->env.u) - s->last_use;
    return (uint32_t)(s->timeout - gone);
}

size_t gk_count(gk_store *s) { return gk_is_unlocked(s) ? s->n : 0; }

int gk_find(gk_store *s, const char *service, const char *host, const char *user, uint8_t *buf, size_t *len)
{
    char *h;
    long i;
    if (!gk_is_unlocked(s)) return GKE_LOCKED;
    if (gk_check_name(service, host, user)) return GKE_BADNAME;
    if (!(h = host_key(host))) return GKE_NOMEM;
    i = find_at(s, service, h, user);
    free(h);
    touch(s);
    if (i < 0) return GKE_NOTFOUND;
    if (*len < s->e[i].secret_len) { *len = s->e[i].secret_len; return GKE_SHORT; }
    if (s->e[i].secret_len) memcpy(buf, s->e[i].secret, s->e[i].secret_len);
    *len = s->e[i].secret_len;
    s->e[i].last_used = s->env.now(s->env.u);   /* kept in memory; written with the next change */
    return GKE_OK;
}

/* Into memory only; the caller saves */
static int put_one(gk_store *s, const char *service, const char *host, const char *user,
                   const uint8_t *secret, size_t secret_len, const char *label, const char *owner, unsigned long flags)
{
    entry x;
    char *h;
    long i;
    uint64_t now = s->env.now(s->env.u);
    if (gk_check_name(service, host, user)) return GKE_BADNAME;
    if (secret_len > GK_MAX_SECRET) return GKE_TOOBIG;
    if (!(h = host_key(host))) return GKE_NOMEM;
    i = find_at(s, service, h, user);
    if (i >= 0 && !(flags & GKF_REPLACE)) { free(h); return GKE_EXISTS; }
    memset(&x, 0, sizeof x);
    x.service = dup_s(service); x.host = h; x.user = dup_s(user);
    x.label = malloc(GK_MAX_LABEL + 1); x.owner = malloc(GK_MAX_OWNER + 1);
    x.secret = malloc(secret_len ? secret_len : 1);
    if (!x.service || !x.user || !x.label || !x.owner || !x.secret) { entry_free(&x); return GKE_NOMEM; }
    strncpy(x.label, label ? label : "", GK_MAX_LABEL); x.label[GK_MAX_LABEL] = 0;
    strncpy(x.owner, owner ? owner : "", GK_MAX_OWNER); x.owner[GK_MAX_OWNER] = 0;
    memcpy(x.secret, secret, secret_len); x.secret_len = secret_len;
    x.created = i >= 0 ? s->e[i].created : now;
    x.last_used = now;
    if (i >= 0) { entry_free(&s->e[i]); s->e[i] = x; return GKE_OK; }
    if (s->n >= GK_MAX_ENTRIES) { entry_free(&x); return GKE_TOOBIG; }
    if (s->n == s->cap) {
        size_t c = s->cap ? s->cap * 2 : 16;
        entry *e = realloc(s->e, c * sizeof *e);
        if (!e) { entry_free(&x); return GKE_NOMEM; }
        s->e = e; s->cap = c;
    }
    s->e[s->n++] = x;
    return GKE_OK;
}

/* After a failed save: back to what the file holds. If even that fails the
 * store locks, and the next unlock opens whichever copy is whole. */
static void reload(gk_store *s)
{
    uint8_t *p;
    size_t n;
    int r = GKE_IO;
    if (s->env.read(s->env.u, s->path, &p, &n) == GKE_OK) { r = file_open(s, p, n, NULL, 0, 1); free(p); }
    if (r) gk_lock(s);
}

/* Save, or on failure go back to what the file holds */
static int commit(gk_store *s)
{
    int r = file_save(s);
    if (r) reload(s);
    return r;
}

int gk_put(gk_store *s, const char *service, const char *host, const char *user,
           const uint8_t *secret, size_t secret_len, const char *label, const char *owner, unsigned long flags)
{
    int r;
    if (!gk_is_unlocked(s)) return GKE_LOCKED;
    touch(s);
    if ((r = put_one(s, service, host, user, secret, secret_len, label, owner, flags))) return r;
    return commit(s);
}

int gk_delete(gk_store *s, const char *service, const char *host, const char *user)
{
    char *h;
    long i;
    if (!gk_is_unlocked(s)) return GKE_LOCKED;
    if (gk_check_name(service, host, user)) return GKE_BADNAME;
    if (!(h = host_key(host))) return GKE_NOMEM;
    i = find_at(s, service, h, user);
    free(h);
    touch(s);
    if (i < 0) return GKE_NOTFOUND;
    entry_free(&s->e[i]);
    memmove(&s->e[i], &s->e[i + 1], (s->n - (size_t)i - 1) * sizeof *s->e);
    s->n--;
    return commit(s);
}

int gk_list(gk_store *s, const char *service, int (*fn)(void *ctx, const gk_info *info), void *ctx)
{
    size_t i;
    if (!gk_is_unlocked(s)) return GKE_LOCKED;   /* listing is not a use: the timer runs on */
    for (i = 0; i < s->n; i++) {
        gk_info in;
        const entry *x = &s->e[i];
        if (service && strcmp(service, x->service)) continue;
        in.service = x->service; in.host = x->host; in.user = x->user;
        in.label = x->label; in.owner = x->owner; in.created = x->created; in.last_used = x->last_used;
        if (fn(ctx, &in)) break;
    }
    return GKE_OK;
}

int gk_import(gk_store *s, const gk_import_item *list, size_t count, const char *from, unsigned long flags, size_t *added)
{
    size_t i, n = 0;
    int r;
    *added = 0;
    if (!gk_is_unlocked(s)) return GKE_LOCKED;
    touch(s);
    for (i = 0; i < count; i++) {          /* every name checked before anything changes */
        if (gk_check_name(list[i].service, list[i].host, list[i].user)) return GKE_BADNAME;
        if (list[i].secret_len > GK_MAX_SECRET) return GKE_TOOBIG;
    }
    for (i = 0; i < count; i++) {
        r = put_one(s, list[i].service, list[i].host, list[i].user, list[i].secret, list[i].secret_len,
                    list[i].label, from, flags);
        if (r == GKE_EXISTS) continue;
        if (r) { reload(s); return r; }    /* all or nothing */
        n++;
    }
    if (!n) return GKE_OK;
    if ((r = commit(s))) return r;
    *added = n;
    return GKE_OK;
}

int gk_change_pass(gk_store *s, const char *pass, size_t pass_len, const gk_kdf *kdf)
{
    uint8_t keep[HEAD_BODY];
    int r;
    if (!gk_is_unlocked(s)) return GKE_LOCKED;
    if (!pass_len) return GKE_BADPASS;
    touch(s);
    memcpy(keep, s->head, HEAD_BODY);
    if ((r = new_head(s, kdf, pass, pass_len)) || (r = file_save(s))) { memcpy(s->head, keep, HEAD_BODY); return r; }
    /* Again, so .bak is under the new passphrase too: an old passphrase that
     * leaked must not open any copy. A failure here leaves .bak under the old one. */
    file_save(s);
    return GKE_OK;
}

uint64_t gk_generation(gk_store *s) { return gk_is_unlocked(s) ? s->gen : 0; }
int gk_opened_from(gk_store *s) { return gk_is_unlocked(s) ? s->from : -1; }
