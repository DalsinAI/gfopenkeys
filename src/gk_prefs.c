/* gk_prefs: the Keys prefs editor's ARexx commands and "kept elsewhere" list
 * (DESIGN.md section 6). No command returns a secret, and none can open a
 * requester. MIT, Copyright (c) 2026 AmiCradle Team. */
#include <string.h>

#include "gk_prefs.h"

/* ---- small text helpers --------------------------------------------------- */

typedef struct outbuf { char *p; size_t cap, n; int full; } outbuf;

static void out_init(outbuf *o, char *p, size_t cap) { o->p = p; o->cap = cap; o->n = 0; o->full = 0; if (cap) p[0] = 0; }

static void out_s(outbuf *o, const char *s)
{
    size_t k = strlen(s);
    if (!o->cap) { o->full = 1; return; }
    if (o->n + k + 1 > o->cap) { k = o->cap - 1 - o->n; o->full = 1; }
    memcpy(o->p + o->n, s, k);
    o->n += k;
    o->p[o->n] = 0;
}

static void out_u(outbuf *o, unsigned long long v)
{
    char t[24], *e = t + sizeof t - 1;
    *e = 0;
    do { *--e = (char)('0' + v % 10); v /= 10; } while (v);
    out_s(o, e);
}

static int lower(int c) { return c >= 'A' && c <= 'Z' ? c + 32 : c; }

static int word_is(const char *w, size_t n, const char *name)
{
    size_t i;
    for (i = 0; i < n; i++) if (!name[i] || lower((unsigned char)w[i]) != lower((unsigned char)name[i])) return 0;
    return !name[n];
}

static const char *skip_sp(const char *s) { while (*s == ' ' || *s == '\t') s++; return s; }

/* the rest of the line: trimmed, and one pair of quotes round it taken off */
static size_t rest(const char *s, const char **start)
{
    size_t n;
    s = skip_sp(s);
    n = strlen(s);
    while (n && (s[n - 1] == ' ' || s[n - 1] == '\t' || s[n - 1] == '\n' || s[n - 1] == '\r')) n--;
    if (n >= 2 && s[0] == '"' && s[n - 1] == '"') { s++; n -= 2; }
    *start = s;
    return n;
}

/* a decimal number, the whole of s[0..n): 0, or -1 when it isn't one */
static int number(const char *s, size_t n, unsigned long long max, unsigned long long *v)
{
    size_t i;
    *v = 0;
    if (!n) return -1;
    for (i = 0; i < n; i++) {
        if (s[i] < '0' || s[i] > '9') return -1;
        *v = *v * 10 + (unsigned)(s[i] - '0');
        if (*v > max) return -1;
    }
    return 0;
}

/* ---- names ---------------------------------------------------------------- */

size_t gkp_name(const char *service, const char *host, const char *user, char *out, size_t cap)
{
    const char *part[3];
    size_t o = 0;
    int i;
    part[0] = service; part[1] = host; part[2] = user;
    if (!cap) return 0;
    out[0] = 0;
    for (i = 0; i < 3; i++) {
        if (i) {
            if (o + 2 > cap) return o;
            out[o++] = '/';
            out[o] = 0;
        }
        o += gk_escape(part[i], out + o, cap - o);
    }
    return o;
}

static int hexval(int c)
{
    if (c >= '0' && c <= '9') return c - '0';
    c = lower(c);
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    return -1;
}

/* one part of name[0..n) into out (cap bytes with the 0) */
static int unescape(const char *s, size_t n, char *out, size_t cap)
{
    size_t i, o = 0;
    for (i = 0; i < n; i++) {
        int c = (unsigned char)s[i];
        if (c == '%') {
            int h, l;
            if (i + 2 >= n) return GKE_BADNAME;
            h = hexval((unsigned char)s[i + 1]);
            l = hexval((unsigned char)s[i + 2]);
            if (h < 0 || l < 0 || !(h | l)) return GKE_BADNAME;   /* %00 would cut the part short */
            c = h * 16 + l;
            i += 2;
        }
        if (o + 1 >= cap) return GKE_BADNAME;
        out[o++] = (char)c;
    }
    out[o] = 0;
    return 0;
}

static int split_n(const char *name, size_t n, char *service, char *host, char *user)
{
    const char *a, *b;
    a = memchr(name, '/', n);
    if (!a) return GKE_BADNAME;
    b = memchr(a + 1, '/', n - (size_t)(a + 1 - name));
    if (!b || memchr(b + 1, '/', n - (size_t)(b + 1 - name))) return GKE_BADNAME;
    if (unescape(name, (size_t)(a - name), service, GK_MAX_SERVICE + 1)
        || unescape(a + 1, (size_t)(b - a - 1), host, GK_MAX_PART + 1)
        || unescape(b + 1, n - (size_t)(b + 1 - name), user, GK_MAX_PART + 1)) return GKE_BADNAME;
    return gk_check_name(service, host, user);
}

int gkp_split(const char *name, char service[GK_MAX_SERVICE + 1], char host[GK_MAX_PART + 1], char user[GK_MAX_PART + 1])
{
    service[0] = host[0] = user[0] = 0;
    return name ? split_n(name, strlen(name), service, host, user) : GKE_BADNAME;
}

/* ---- the commands ---------------------------------------------------------- */

static const char *err_text(const gkp_ops *ops, int e)
{
    const char *t = ops->error_string ? ops->error_string(ops->u, e) : 0;
    return t ? t : "Error";
}

static int fail(const gkp_ops *ops, outbuf *o, int rc, int e)
{
    out_init(o, o->p, o->cap);
    out_s(o, err_text(ops, e));
    return rc;
}

static int say(outbuf *o, int rc, const char *text)
{
    out_init(o, o->p, o->cap);
    out_s(o, text);
    return rc;
}

static int cmd_status(const gkp_ops *ops, outbuf *o)
{
    gk_status st;
    memset(&st, 0, sizeof st);
    ops->status(ops->u, &st);
    out_s(o, "exists "); out_u(o, (unsigned)st.exists != 0);
    out_s(o, " unlocked "); out_u(o, (unsigned)st.unlocked != 0);
    out_s(o, " readonly "); out_u(o, (unsigned)st.readonly != 0);
    out_s(o, " count "); out_u(o, st.count);
    out_s(o, " left ");
    if (st.seconds_left == UINT32_MAX) out_s(o, "none"); else out_u(o, st.seconds_left);
    return GKP_RC_OK;
}

typedef struct list_ctx { outbuf *o; int lines; } list_ctx;

static int list_one(void *ctx, const gk_info *in)
{
    list_ctx *c = ctx;
    char name[GK_MAX_SERVICE * 3 + 2 * GK_MAX_PART * 3 + 8];
    size_t n = gkp_name(in->service, in->host, in->user, name, sizeof name);
    /* whole lines only: one that doesn't fit ends the list */
    if (c->o->n + n + (c->lines ? 1 : 0) + 1 > c->o->cap) { c->o->full = 1; return 1; }
    if (c->lines) out_s(c->o, "\n");
    out_s(c->o, name);
    c->lines++;
    return 0;
}

static int cmd_list(const gkp_ops *ops, outbuf *o, const char *args)
{
    char service[GK_MAX_SERVICE + 1];
    const char *a;
    size_t n = rest(args, &a);
    list_ctx c;
    int r;
    if (n >= 8 && word_is(a, 8, "SERVICE=")) { a += 8; n -= 8; }
    else if (n > 7 && word_is(a, 7, "SERVICE") && (a[7] == ' ' || a[7] == '\t')) {
        const char *b = skip_sp(a + 7);
        n -= (size_t)(b - a);
        a = b;
    }
    if (n > GK_MAX_SERVICE) return say(o, GKP_RC_ERROR, "No such service");
    memcpy(service, a, n);
    service[n] = 0;
    c.o = o; c.lines = 0;
    r = ops->list(ops->u, n ? service : 0, list_one, &c);
    if (r) return fail(ops, o, GKP_RC_ERROR, r);
    return o->full ? GKP_RC_WARN : GKP_RC_OK;   /* WARN: more names than RESULT holds */
}

static int cmd_delete(const gkp_ops *ops, outbuf *o, const char *args)
{
    char service[GK_MAX_SERVICE + 1], host[GK_MAX_PART + 1], user[GK_MAX_PART + 1];
    const char *a;
    size_t n = rest(args, &a);
    int r;
    if (!n) return say(o, GKP_RC_ERROR, "DELETE needs a name, as LIST gives it");
    service[0] = host[0] = user[0] = 0;
    if ((r = split_n(a, n, service, host, user))) return fail(ops, o, GKP_RC_ERROR, r);
    r = ops->del(ops->u, service, host, user);
    if (r == GKE_NOTFOUND) return fail(ops, o, GKP_RC_WARN, r);
    if (r) return fail(ops, o, GKP_RC_ERROR, r);
    return GKP_RC_OK;
}

static int cmd_timeout(const gkp_ops *ops, outbuf *o, const char *args)
{
    const char *a;
    size_t n = rest(args, &a);
    unsigned long long v;
    int r;
    if (number(a, n, 0xFFFFFFFFull, &v)) return say(o, GKP_RC_ERROR, "TIMEOUT needs seconds, 0 or more");
    if ((r = ops->set_timeout(ops->u, (uint32_t)v))) return fail(ops, o, GKP_RC_WARN, r);   /* set, but not kept */
    return GKP_RC_OK;
}

static int cmd_fault(const gkp_ops *ops, outbuf *o, const char *args)
{
    const char *a;
    size_t n = rest(args, &a);
    unsigned long long v;
    /* every GKE_ code is 0 or less, so 3 and -3 are the same one */
    if (n && a[0] == '-') { a++; n--; }
    if (number(a, n, 1000, &v)) return say(o, GKP_RC_ERROR, "FAULT needs an error number");
    out_s(o, err_text(ops, -(int)v));
    return GKP_RC_OK;
}

int gkp_rexx(const gkp_ops *ops, const char *line, char *result, size_t cap)
{
    outbuf o;
    const char *w, *e;
    size_t n;
    out_init(&o, result, cap);
    if (!line) return say(&o, GKP_RC_FAIL, "No command");
    w = skip_sp(line);
    for (e = w; *e && *e != ' ' && *e != '\t' && *e != '\n' && *e != '\r'; e++) ;
    n = (size_t)(e - w);
    if (word_is(w, n, "STATUS")) return cmd_status(ops, &o);
    if (word_is(w, n, "LOCK")) { ops->lock(ops->u); return GKP_RC_OK; }
    if (word_is(w, n, "LIST")) return cmd_list(ops, &o, e);
    if (word_is(w, n, "DELETE")) return cmd_delete(ops, &o, e);
    if (word_is(w, n, "TIMEOUT")) return cmd_timeout(ops, &o, e);
    if (word_is(w, n, "FAULT")) return cmd_fault(ops, &o, e);
    if (word_is(w, n, "VERSION")) { out_s(&o, GKP_VERSION); return GKP_RC_OK; }
    if (word_is(w, n, "HELP")) {
        out_s(&o, "STATUS LOCK LIST [SERVICE=word] DELETE name TIMEOUT seconds VERSION HELP FAULT n QUIT ACTIVATE DEACTIVATE");
        return GKP_RC_OK;
    }
    return say(&o, GKP_RC_FAIL, "Unknown command");
}

/* ---- kept elsewhere (docs/SURVEY-20261113.md) ------------------------------ */

static const gkp_elsewhere elsewhere[] = {
    { "gfopenmail: the account password", "ENVARC:GFOpenMail/Account", "Obscured, not encrypted" },
    { "gfopenmail: the OAuth2 token", "The file the account names", "Plain" },
    { "gfopenftp: site passwords", "ENVARC:GFOpenFTP/Sites", "Encrypted with a key kept beside it" },
    { "FileZilla: site passwords", "PROGDIR:Settings/", "Plain base64 unless a master password is set" },
    { "gfopentelegram: the API hash", "ENVARC:GFOpenTelegram/API", "Plain" },
    { "Network shares", "Kept by the host", "The Amiga never holds them" },
    { "Wi-Fi networks", "Kept by the card", "The Amiga never holds them" },
    { "gfopenremotedesktop", "Kept on the PC", "The Amiga never holds it" },
};

const gkp_elsewhere *gkp_kept_elsewhere(size_t *count)
{
    *count = sizeof elsewhere / sizeof elsewhere[0];
    return elsewhere;
}
