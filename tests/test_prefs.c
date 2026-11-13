/* test_prefs.c: host tests for gk_prefs, the Keys prefs editor's ARexx
 * commands, names and "kept elsewhere" list (DESIGN.md section 6), driven
 * through gk_lib on the in-memory file system.
 * MIT, Copyright (c) 2026 AmiCradle Team. */
#include "fake_env.h"
#include "gk_prefs.h"

static const gk_kdf KDF = { 1, 8, 1 };
#define PATH "ENVARC:GFOpenKeys/Default.keys"
#define SECRET "s3cr3t-never-shown"

/* ---- a requester that counts, and gk_lib as the ops --------------------- */

static int asked;
static int ui_ask(void *u, const char *owner, unsigned tries, int confirm, char *buf, size_t cap, size_t *len)
{
    (void)u; (void)owner; (void)tries; (void)confirm; (void)cap;
    asked++;
    memcpy(buf, "pass", 4);
    *len = 4;
    return 0;
}
static void ui_warn(void *u, int what, uint64_t a, uint64_t b) { (void)u; (void)what; (void)a; (void)b; }
static void ui_wait(void *u, uint32_t s) { (void)u; (void)s; }

static void o_status(void *u, gk_status *st) { gkl_status(u, st); }
static void o_lock(void *u) { gkl_lock(u); }
static int o_list(void *u, const char *service, int (*fn)(void *, const gk_info *), void *ctx)
{
    return gk_list(gkl_store(u), service, fn, ctx);
}
static int o_del(void *u, const char *service, const char *host, const char *user)
{
    return gkl_delete(u, "Keys", service, host, user, GKF_NOPROMPT);
}
static int o_timeout(void *u, uint32_t s) { return gkl_set_timeout(u, s); }
static const char *o_err(void *u, int e)
{
    (void)u;
    switch (e) {
    case GKE_NOTFOUND: return "No such entry";
    case GKE_LOCKED: return "The keys are locked";
    case GKE_BADPASS: return "Wrong passphrase";
    case GKE_BADNAME: return "Bad name";
    default: return NULL;
    }
}

typedef struct rig { fs x; gk_env e; gk_ui ui; gk_lib *l; gkp_ops ops; char r[1024]; } rig;

static void rig_open(rig *g)
{
    fs_init(&g->x, &g->e);
    g->ui.ask = ui_ask; g->ui.warn = ui_warn; g->ui.wait = ui_wait; g->ui.u = NULL;
    gkl_open(&g->l, &g->e, &g->ui, PATH, &KDF);
    g->ops.status = o_status; g->ops.lock = o_lock; g->ops.list = o_list; g->ops.del = o_del;
    g->ops.set_timeout = o_timeout; g->ops.error_string = o_err; g->ops.u = g->l;
    asked = 0;
}
static void rig_close(rig *g) { gkl_close(g->l); fs_free(&g->x); }
static int rx(rig *g, const char *line) { return gkp_rexx(&g->ops, line, g->r, sizeof g->r); }

static void put(rig *g, const char *service, const char *host, const char *user)
{
    CHECK(gkl_store_entry(g->l, "T", service, host, user, (const uint8_t *)SECRET, strlen(SECRET), "lbl", 0) == GKE_OK);
}

/* ---- names ---------------------------------------------------------------- */

static void test_names(void)
{
    char out[64], s[GK_MAX_SERVICE + 1], h[GK_MAX_PART + 1], u[GK_MAX_PART + 1], big[300];
    CHECK(gkp_name("ssh", "host", "dale", out, sizeof out) == 13 && !strcmp(out, "ssh/host/dale"));
    gkp_name("ssh", "", "a/b%c", out, sizeof out);
    CHECK(!strcmp(out, "ssh//a%2Fb%25c"));
    CHECK(gkp_split(out, s, h, u) == 0 && !strcmp(s, "ssh") && !h[0] && !strcmp(u, "a/b%c"));
    CHECK(gkp_split("ftp/Host.Example:2121/Joe Bloggs", s, h, u) == 0 && !strcmp(h, "Host.Example:2121") && !strcmp(u, "Joe Bloggs"));
    CHECK(gkp_split("ssh/h/x%2fy", s, h, u) == 0 && !strcmp(u, "x/y"));   /* hex in either case */
    CHECK(gkp_split("ssh/h", s, h, u) == GKE_BADNAME);
    CHECK(gkp_split("ssh/h/u/v", s, h, u) == GKE_BADNAME);
    CHECK(gkp_split("ssh/h/u%", s, h, u) == GKE_BADNAME);
    CHECK(gkp_split("ssh/h/u%4", s, h, u) == GKE_BADNAME);
    CHECK(gkp_split("ssh/h/u%zz", s, h, u) == GKE_BADNAME);
    CHECK(gkp_split("ssh/h/u%00x", s, h, u) == GKE_BADNAME);
    CHECK(gkp_split("SSH/h/u", s, h, u) == GKE_BADNAME);                 /* the naming rule still holds */
    CHECK(gkp_split("/h/u", s, h, u) == GKE_BADNAME);
    CHECK(gkp_split(NULL, s, h, u) == GKE_BADNAME);
    memset(big, 'x', sizeof big - 1); big[sizeof big - 1] = 0;
    memcpy(big, "ssh/h/", 6);
    CHECK(gkp_split(big, s, h, u) == GKE_BADNAME);                       /* a part over 255 bytes */
    memcpy(big, "abcdefghijklmnopqrstuvwxyzabcdefg/h/u", 38);
    CHECK(gkp_split(big, s, h, u) == GKE_BADNAME);                       /* a service over 31 */
    CHECK(gkp_name("ssh", "host", "dale", out, 6) == 5 && !strcmp(out, "ssh/h"));   /* cut, still ends in 0 */
    CHECK(gkp_name("ssh", "h", "u", out, 0) == 0);
}

/* ---- ARexx with no store, and locked: never a requester ------------------ */

static void test_rexx_locked(void)
{
    rig g;
    rig_open(&g);
    CHECK(rx(&g, "STATUS") == GKP_RC_OK && !strcmp(g.r, "exists 0 unlocked 0 readonly 0 count 0 left 0"));
    CHECK(rx(&g, "LIST") == GKP_RC_ERROR);
    CHECK(rx(&g, "DELETE ssh/h/u") == GKP_RC_WARN);         /* no store: nothing to delete */
    CHECK(!gk_exists(gkl_store(g.l)));                 /* nothing made */
    put(&g, "ssh", "h", "u");
    CHECK(asked == 1);
    CHECK(rx(&g, "LOCK") == GKP_RC_OK && !g.r[0]);
    CHECK(rx(&g, "STATUS") == GKP_RC_OK && !strcmp(g.r, "exists 1 unlocked 0 readonly 0 count 0 left 0"));
    CHECK(rx(&g, "LIST") == GKP_RC_ERROR && !strcmp(g.r, "The keys are locked"));
    CHECK(rx(&g, "DELETE ssh/h/u") == GKP_RC_ERROR && !strcmp(g.r, "The keys are locked"));
    CHECK(asked == 1);                                 /* no command asked */
    rig_close(&g);
}

/* ---- ARexx, unlocked ------------------------------------------------------- */

static void test_rexx_unlocked(void)
{
    rig g;
    rig_open(&g);
    put(&g, "ssh", "host", "dale");
    put(&g, "ssh", "other", "a/b");
    put(&g, "ftp", "files:2121", "Joe Bloggs");
    CHECK(rx(&g, "STATUS") == GKP_RC_OK && !strcmp(g.r, "exists 1 unlocked 1 readonly 0 count 3 left 900"));
    CHECK(rx(&g, "LIST") == GKP_RC_OK && !strcmp(g.r, "ssh/host/dale\nssh/other/a%2Fb\nftp/files:2121/Joe Bloggs"));
    CHECK(!strstr(g.r, SECRET) && !strstr(g.r, "lbl"));          /* names only */
    CHECK(rx(&g, "LIST SERVICE=ftp") == GKP_RC_OK && !strcmp(g.r, "ftp/files:2121/Joe Bloggs"));
    CHECK(rx(&g, "list service ssh ") == GKP_RC_OK && !strcmp(g.r, "ssh/host/dale\nssh/other/a%2Fb"));
    CHECK(rx(&g, "  List   ssh") == GKP_RC_OK && !strcmp(g.r, "ssh/host/dale\nssh/other/a%2Fb"));
    CHECK(rx(&g, "LIST nntp") == GKP_RC_OK && !g.r[0]);
    CHECK(rx(&g, "LIST abcdefghijklmnopqrstuvwxyzabcdefg") == GKP_RC_ERROR);
    /* listing is not a use: the timer runs on */
    g.x.clock += 100;
    rx(&g, "LIST");
    CHECK(rx(&g, "STATUS") == GKP_RC_OK && strstr(g.r, "left 800"));
    /* DELETE takes the name as LIST gives it */
    CHECK(rx(&g, "DELETE \"ftp/files:2121/Joe Bloggs\"") == GKP_RC_OK);
    CHECK(rx(&g, "DELETE ssh/other/a%2Fb") == GKP_RC_OK);
    CHECK(rx(&g, "LIST") == GKP_RC_OK && !strcmp(g.r, "ssh/host/dale"));
    CHECK(rx(&g, "DELETE ssh/other/a%2Fb") == GKP_RC_WARN && !strcmp(g.r, "No such entry"));
    CHECK(rx(&g, "DELETE ssh/host") == GKP_RC_ERROR && !strcmp(g.r, "Bad name"));
    CHECK(rx(&g, "DELETE") == GKP_RC_ERROR);
    CHECK(rx(&g, "DELETE \"\"") == GKP_RC_ERROR);
    CHECK(asked == 1);
    rig_close(&g);
}

static void test_rexx_timeout(void)
{
    rig g;
    rig_open(&g);
    put(&g, "ssh", "h", "u");
    CHECK(rx(&g, "TIMEOUT 60") == GKP_RC_OK);
    rx(&g, "STATUS");
    g.x.clock += 61;
    CHECK(rx(&g, "STATUS") == GKP_RC_OK && strstr(g.r, "unlocked 0"));
    CHECK(rx(&g, "LIST") == GKP_RC_ERROR);
    CHECK(gkl_unlock(g.l, "T", 0) == GKE_OK);
    CHECK(rx(&g, "TIMEOUT 0") == GKP_RC_OK);
    CHECK(rx(&g, "STATUS") == GKP_RC_OK && strstr(g.r, "unlocked 1") && strstr(g.r, "left none"));
    CHECK(rx(&g, "TIMEOUT") == GKP_RC_ERROR);
    CHECK(rx(&g, "TIMEOUT -1") == GKP_RC_ERROR);
    CHECK(rx(&g, "TIMEOUT 1x") == GKP_RC_ERROR);
    CHECK(rx(&g, "TIMEOUT 4294967296") == GKP_RC_ERROR);
    CHECK(rx(&g, "TIMEOUT 4294967295") == GKP_RC_OK);
    g.x.ops = 0; g.x.crash_at = 0;                     /* the .timeout file can't be written */
    CHECK(rx(&g, "TIMEOUT 120") == GKP_RC_WARN);
    g.x.crash_at = -1;
    CHECK(rx(&g, "STATUS") == GKP_RC_OK && strstr(g.r, "left 120"));   /* set for now all the same */
    rig_close(&g);
}

static void test_rexx_builtins(void)
{
    rig g;
    char small[24];
    rig_open(&g);
    CHECK(rx(&g, "VERSION") == GKP_RC_OK && !strcmp(g.r, GKP_VERSION));
    CHECK(rx(&g, "help") == GKP_RC_OK && strstr(g.r, "STATUS") && strstr(g.r, "TIMEOUT"));
    CHECK(rx(&g, "FAULT -3") == GKP_RC_OK && !strcmp(g.r, "Wrong passphrase"));
    CHECK(rx(&g, "FAULT 3") == GKP_RC_OK && !strcmp(g.r, "Wrong passphrase"));
    CHECK(rx(&g, "FAULT 99") == GKP_RC_OK && !strcmp(g.r, "Error"));
    CHECK(rx(&g, "FAULT x") == GKP_RC_ERROR);
    CHECK(rx(&g, "SHOW ssh/h/u") == GKP_RC_FAIL);      /* there is no command that returns a secret */
    CHECK(rx(&g, "STATUSX") == GKP_RC_FAIL);
    CHECK(rx(&g, "") == GKP_RC_FAIL);
    CHECK(gkp_rexx(&g.ops, NULL, g.r, sizeof g.r) == GKP_RC_FAIL);
    CHECK(gkp_rexx(&g.ops, "VERSION", NULL, 0) == GKP_RC_OK);   /* no room: nothing written */
    /* a RESULT too small: whole names only, and WARN */
    put(&g, "ssh", "first", "u");
    put(&g, "ssh", "second", "u");
    CHECK(gkp_rexx(&g.ops, "LIST", small, sizeof small) == GKP_RC_WARN && !strcmp(small, "ssh/first/u"));
    CHECK(gkp_rexx(&g.ops, "STATUS", small, sizeof small) == GKP_RC_OK && strlen(small) == sizeof small - 1);
    rig_close(&g);
}

static void test_elsewhere(void)
{
    size_t n, i;
    int host = 0, card = 0;
    const gkp_elsewhere *k = gkp_kept_elsewhere(&n);
    CHECK(n == 8);
    for (i = 0; i < n; i++) {
        CHECK(k[i].what && k[i].what[0] && k[i].where && k[i].where[0] && k[i].how && k[i].how[0]);
        host += !strcmp(k[i].where, "Kept by the host");
        card += !strcmp(k[i].where, "Kept by the card");
    }
    CHECK(host == 1 && card == 1);
}

int main(void)
{
    (void)fs_copy;                     /* fake_env.h: not needed here */
    test_names();
    test_rexx_locked();
    test_rexx_unlocked();
    test_rexx_timeout();
    test_rexx_builtins();
    test_elsewhere();
    printf("%d/%d prefs checks passed\n", checks - fails, checks);
    return fails != 0;
}
