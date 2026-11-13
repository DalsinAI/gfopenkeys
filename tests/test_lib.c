/* test_lib.c: host tests for gk_lib, the library's calls (DESIGN.md 2, 4, 5),
 * with a scripted requester in place of the GFOpenLayout one.
 * MIT, Copyright (c) 2026 AmiCradle Team. */
#include "fake_env.h"
#include "gk_lib.h"

static const gk_kdf KDF = { 1, 8, 1 };
#define PATH "ENVARC:GFOpenKeys/Default.keys"

/* ---- a scripted requester ------------------------------------------------- */

typedef struct ui_log {
    const char *answers[16];     /* NULL: cancel */
    int next, asked, confirms;
    unsigned last_tries;
    char last_owner[80];
    int warned[5];
    uint32_t waited[16];
    int waits;
} ui_log;

static int u_ask(void *u, const char *owner, unsigned tries, int confirm, char *buf, size_t cap, size_t *len)
{
    ui_log *g = u;
    const char *a = g->answers[g->next++];
    g->asked++;
    g->confirms += confirm;
    g->last_tries = tries;
    strncpy(g->last_owner, owner ? owner : "", sizeof g->last_owner - 1);
    if (!a) return GKE_CANCEL;
    *len = strlen(a) < cap ? strlen(a) : cap;
    memcpy(buf, a, *len);
    return 0;
}
static void u_warn(void *u, int what, uint64_t a, uint64_t b) { (void)a; (void)b; ((ui_log *)u)->warned[what]++; }
static void u_wait(void *u, uint32_t s) { ui_log *g = u; if (g->waits < 16) g->waited[g->waits++] = s; }

static void ui_init(gk_ui *ui, ui_log *g) { memset(g, 0, sizeof *g); ui->ask = u_ask; ui->warn = u_warn; ui->wait = u_wait; ui->u = g; }

static int has(gk_lib *l, const char *want)
{
    uint8_t b[32];
    size_t n = sizeof b;
    if (gkl_find(l, "T", "ssh", "h", "u", b, &n, GKF_NOPROMPT)) return 0;
    return n == strlen(want) && !memcmp(b, want, n);
}

/* ---- the tests ------------------------------------------------------------ */

static void test_owner(void)
{
    char o[GK_MAX_OWNER + 1], big[200];
    gkl_owner(o, NULL);           CHECK(!strcmp(o, "(unnamed)"));
    gkl_owner(o, "");             CHECK(!strcmp(o, "(unnamed)"));
    gkl_owner(o, "\n\t");         CHECK(!strcmp(o, "(unnamed)"));
    gkl_owner(o, "GFOpen\nPuTTY"); CHECK(!strcmp(o, "GFOpenPuTTY"));
    memset(big, 'x', sizeof big - 1); big[sizeof big - 1] = 0;
    gkl_owner(o, big);            CHECK(strlen(o) == GK_MAX_OWNER);
}

static void test_noprompt(void)
{
    fs x; gk_env e; gk_ui ui; ui_log g; gk_lib *l;
    uint8_t b[8]; size_t n = sizeof b;
    fs_init(&x, &e); ui_init(&ui, &g);
    CHECK(gkl_open(&l, &e, &ui, PATH, &KDF) == GKE_OK);
    /* no store: nothing is asked, nothing is made */
    CHECK(gkl_find(l, "T", "ssh", "h", "u", b, &n, GKF_NOPROMPT) == GKE_NOSTORE);
    CHECK(gkl_store_entry(l, "T", "ssh", "h", "u", (const uint8_t *)"pw", 2, NULL, GKF_NOPROMPT) == GKE_NOSTORE);
    CHECK(gkl_unlock(l, "T", GKF_NOPROMPT) == GKE_NOSTORE);
    CHECK(g.asked == 0 && !gk_exists(gkl_store(l)));
    /* a store, locked: GKE_LOCKED, still nothing asked */
    g.answers[0] = "pass";
    CHECK(gkl_store_entry(l, "T", "ssh", "h", "u", (const uint8_t *)"pw", 2, "lbl", 0) == GKE_OK);
    CHECK(g.asked == 1 && g.confirms == 1);          /* made: typed twice */
    gkl_lock(l);
    g.asked = 0;
    CHECK(gkl_find(l, "T", "ssh", "h", "u", b, &n, GKF_NOPROMPT) == GKE_LOCKED);
    CHECK(gkl_store_entry(l, "T", "ftp", "h", "u", (const uint8_t *)"x", 1, NULL, GKF_NOPROMPT) == GKE_LOCKED);
    CHECK(gkl_delete(l, "T", "ssh", "h", "u", GKF_NOPROMPT) == GKE_LOCKED);
    CHECK(gkl_change_pass(l, "T", NULL, GKF_NOPROMPT) == GKE_LOCKED);
    CHECK(gkl_find(l, "T", "SSH", "h", "u", b, &n, 0) == GKE_BADNAME);   /* a bad name never opens a requester */
    CHECK(g.asked == 0);
    gkl_close(l);
    fs_free(&x);
}

static void test_prompt_and_backoff(void)
{
    fs x; gk_env e; gk_ui ui; ui_log g; gk_lib *l;
    uint8_t b[8]; size_t n = sizeof b;
    int i;
    fs_init(&x, &e); ui_init(&ui, &g);
    gkl_open(&l, &e, &ui, PATH, &KDF);
    g.answers[0] = "pass";
    gkl_store_entry(l, "GFOpenPuTTY", "ssh", "h", "u", (const uint8_t *)"pw", 2, NULL, 0);
    gkl_lock(l);
    /* seven wrong, then right: no waits for the first five, then 2, 4 */
    memset(&g, 0, sizeof g);
    for (i = 0; i < 7; i++) g.answers[i] = "wrong";
    g.answers[7] = "pass";
    CHECK(gkl_find(l, "GFOpenPuTTY", "ssh", "h", "u", b, &n, 0) == GKE_OK && n == 2 && !memcmp(b, "pw", 2));
    CHECK(g.asked == 8 && g.last_tries == 7 && !strcmp(g.last_owner, "GFOpenPuTTY"));
    CHECK(g.waits == 3 && g.waited[0] == 2 && g.waited[1] == 4 && g.waited[2] == 8);
    gkl_lock(l);
    /* the count starts again after a right one; cancel answers GKE_CANCEL */
    memset(&g, 0, sizeof g);
    g.answers[0] = "wrong"; g.answers[1] = NULL;
    n = sizeof b;
    CHECK(gkl_find(l, "T", "ssh", "h", "u", b, &n, 0) == GKE_CANCEL);
    CHECK(g.asked == 2 && g.waits == 0 && !gk_is_unlocked(gkl_store(l)));
    gkl_close(l);
    fs_free(&x);
}

static void test_owner_recorded(void)
{
    fs x; gk_env e; gk_ui ui; ui_log g; gk_lib *l;
    gk_import_item it[2] = { { "ftp", "a:21", "u", NULL, (const uint8_t *)"p1", 2 },
                             { "ftp", "b:21", "u", "B", (const uint8_t *)"p2", 2 } };
    size_t added;
    fs_init(&x, &e); ui_init(&ui, &g);
    gkl_open(&l, &e, &ui, PATH, &KDF);
    g.answers[0] = "pass";
    CHECK(gkl_import(l, "GFOpenFTP", it, 2, 0, &added) == GKE_OK && added == 2);   /* makes the store */
    CHECK(gkl_import(l, "GFOpenFTP", it, 2, 0, &added) == GKE_OK && added == 0);
    {
        gk_status st;
        gkl_status(l, &st);
        CHECK(st.exists && st.unlocked && st.count == 2 && !st.readonly && !st.rolled_back && st.opened_from == 0);
    }
    gkl_close(l);
    fs_free(&x);
}

/* the .count file: an older whole store copied over the new one is noticed */
static void test_rollback(void)
{
    fs x, old; gk_env e, oe; gk_ui ui; ui_log g; gk_lib *l;
    gk_status st;
    fs_init(&x, &e); fs_init(&old, &oe); ui_init(&ui, &g);
    gkl_open(&l, &e, &ui, PATH, &KDF);
    g.answers[0] = "pass";
    gkl_store_entry(l, "T", "ssh", "h", "u", (const uint8_t *)"one", 3, NULL, 0);
    fs_copy(&old, &x);                                   /* a copy of the files as they were */
    gkl_store_entry(l, "T", "ssh", "h", "u", (const uint8_t *)"two", 3, NULL, GKF_REPLACE);
    gkl_store_entry(l, "T", "ftp", "h", "u", (const uint8_t *)"x", 1, NULL, 0);
    gkl_close(l);
    {   /* put the old store and its .bak back, keep the new .count */
        mfile *c = fs_get(&x, PATH ".count");
        uint8_t keep[16];
        memcpy(keep, c->data, 16);
        fs_copy(&x, &old);
        m_write(&x, PATH ".count", keep, 16);
    }
    gkl_open(&l, &e, &ui, PATH, &KDF);
    memset(&g, 0, sizeof g);
    g.answers[0] = "pass";
    CHECK(gkl_unlock(l, "T", 0) == GKE_OK);
    CHECK(g.warned[GKW_ROLLED_BACK] == 1 && has(l, "one"));
    gkl_status(l, &st);
    CHECK(st.rolled_back);
    gkl_close(l);
    /* without the trick: no warning */
    fs_copy(&x, &old);
    gkl_open(&l, &e, &ui, PATH, &KDF);
    memset(&g, 0, sizeof g);
    g.answers[0] = "pass";
    CHECK(gkl_unlock(l, "T", 0) == GKE_OK && g.warned[GKW_ROLLED_BACK] == 0);
    gkl_close(l);
    fs_free(&x); fs_free(&old);
}

/* .bak opened: warned; with an older passphrase, read-only and warned */
static void test_older_copy(void)
{
    fs x; gk_env e; gk_ui ui; ui_log g; gk_lib *l;
    gk_status st;
    mfile *m;
    fs_init(&x, &e); ui_init(&ui, &g);
    gkl_open(&l, &e, &ui, PATH, &KDF);
    g.answers[0] = "pass";
    gkl_store_entry(l, "T", "ssh", "h", "u", (const uint8_t *)"one", 3, NULL, 0);
    gkl_store_entry(l, "T", "ssh", "h", "u", (const uint8_t *)"two", 3, NULL, GKF_REPLACE);
    gkl_lock(l);
    m = fs_get(&x, PATH); m->data[m->len - 1] ^= 1;
    memset(&g, 0, sizeof g);
    g.answers[0] = "pass";
    CHECK(gkl_unlock(l, "T", 0) == GKE_OK);
    CHECK(g.warned[GKW_OLDER_COPY] == 1 && g.warned[GKW_READONLY] == 0 && has(l, "one"));
    gkl_status(l, &st);
    CHECK(st.opened_from == 2 && !st.readonly);
    gkl_lock(l);
    /* a half-done passphrase change: the old one opens .bak, read-only */
    memset(&g, 0, sizeof g);
    g.answers[0] = "pass";
    g.answers[1] = "pass";        /* the current one */
    g.answers[2] = "newer";       /* the new one, typed twice */
    gkl_unlock(l, "T", 0);
    x.ops = 0; x.crash_at = 4;
    CHECK(gkl_change_pass(l, "T", NULL, 0) == GKE_OK);
    x.crash_at = -1;
    gkl_lock(l);
    memset(&g, 0, sizeof g);
    g.answers[0] = "pass";
    CHECK(gkl_unlock(l, "T", 0) == GKE_OK);
    CHECK(g.warned[GKW_READONLY] == 1);
    CHECK(gkl_store_entry(l, "T", "ftp", "h", "u", (const uint8_t *)"x", 1, NULL, 0) == GKE_READONLY);
    gkl_status(l, &st);
    CHECK(st.readonly && st.opened_from == 2);
    gkl_lock(l);
    memset(&g, 0, sizeof g);
    g.answers[0] = "newer";
    CHECK(gkl_unlock(l, "T", 0) == GKE_OK && g.warned[GKW_READONLY] == 0);
    CHECK(gkl_store_entry(l, "T", "ftp", "h", "u", (const uint8_t *)"x", 1, NULL, 0) == GKE_OK);
    gkl_close(l);
    fs_free(&x);
}

/* the current passphrase first: an unlocked store is not enough */
static void test_change_pass(void)
{
    fs x; gk_env e; gk_ui ui; ui_log g; gk_lib *l;
    fs_init(&x, &e); ui_init(&ui, &g);
    gkl_open(&l, &e, &ui, PATH, &KDF);
    g.answers[0] = "pass";
    gkl_store_entry(l, "T", "ssh", "h", "u", (const uint8_t *)"pw", 2, NULL, 0);
    memset(&g, 0, sizeof g);
    g.answers[0] = "guess"; g.answers[1] = NULL;          /* a wrong current one, then cancel */
    CHECK(gkl_change_pass(l, "Evil", NULL, 0) == GKE_CANCEL);
    CHECK(g.asked == 2 && g.confirms == 0);
    memset(&g, 0, sizeof g);
    g.answers[0] = "pass"; g.answers[1] = "newer";
    CHECK(gkl_change_pass(l, "Prefs", NULL, 0) == GKE_OK);
    CHECK(g.asked == 2 && g.confirms == 1);
    gkl_lock(l);
    memset(&g, 0, sizeof g);
    g.answers[0] = "pass"; g.answers[1] = "newer";
    CHECK(gkl_unlock(l, "T", 0) == GKE_OK && g.asked == 2);
    CHECK(has(l, "pw"));
    gkl_close(l);
    fs_free(&x);
}

static void test_no_count_and_no_store(void)
{
    fs x; gk_env e; gk_ui ui; ui_log g; gk_lib *l;
    fs_init(&x, &e); ui_init(&ui, &g);
    gkl_open(&l, &e, &ui, PATH, &KDF);
    CHECK(gkl_change_pass(l, "T", NULL, 0) == GKE_NOSTORE && g.asked == 0);   /* no store made by a change */
    g.answers[0] = "pass";
    gkl_store_entry(l, "T", "ssh", "h", "u", (const uint8_t *)"pw", 2, NULL, 0);
    gkl_lock(l);
    memset(&g, 0, sizeof g); g.answers[0] = "pass";
    CHECK(gkl_unlock(l, "T", 0) == GKE_OK && g.warned[GKW_NO_COUNT] == 0);
    gkl_lock(l);
    m_remove(&x, PATH ".count");                         /* deleted: said, then written again */
    memset(&g, 0, sizeof g); g.answers[0] = "pass";
    CHECK(gkl_unlock(l, "T", 0) == GKE_OK && g.warned[GKW_NO_COUNT] == 1);
    CHECK(fs_get(&x, PATH ".count") != NULL);
    gkl_lock(l);
    m_write(&x, PATH ".count", (const uint8_t *)"zz", 2);  /* garbled */
    memset(&g, 0, sizeof g); g.answers[0] = "pass";
    CHECK(gkl_unlock(l, "T", 0) == GKE_OK && g.warned[GKW_NO_COUNT] == 1);
    gkl_close(l);
    fs_free(&x);
}

/* the timeout is kept in "<store>.timeout" and read at the next open */
static void test_timeout_kept(void)
{
    fs x; gk_env e; gk_ui ui; ui_log g; gk_lib *l;
    gk_status st;
    uint8_t *p; size_t n;
    fs_init(&x, &e); ui_init(&ui, &g);
    gkl_open(&l, &e, &ui, PATH, &KDF);
    g.answers[0] = "pass";
    gkl_store_entry(l, "T", "ssh", "h", "u", (const uint8_t *)"pw", 2, NULL, 0);
    gkl_status(l, &st);
    CHECK(st.seconds_left == GK_DEFAULT_TIMEOUT);              /* no file yet: the default */
    CHECK(gkl_set_timeout(l, 60) == GKE_OK);
    CHECK(m_read(&x, PATH ".timeout", &p, &n) == 0 && n == 3 && !memcmp(p, "60\n", 3));
    free(p);
    gkl_close(l);
    /* the next boot */
    memset(&g, 0, sizeof g); g.answers[0] = "pass";
    gkl_open(&l, &e, &ui, PATH, &KDF);
    CHECK(gkl_unlock(l, "T", 0) == GKE_OK);
    gkl_status(l, &st);
    CHECK(st.seconds_left == 60);
    CHECK(gkl_set_timeout(l, 0) == GKE_OK);                    /* 0: never by itself, also kept */
    gkl_close(l);
    memset(&g, 0, sizeof g); g.answers[0] = "pass";
    gkl_open(&l, &e, &ui, PATH, &KDF);
    gkl_unlock(l, "T", 0);
    gkl_status(l, &st);
    CHECK(st.seconds_left == UINT32_MAX);
    CHECK(gkl_set_timeout(l, 86400) == GKE_OK);
    gkl_close(l);
    memset(&g, 0, sizeof g); g.answers[0] = "pass";
    gkl_open(&l, &e, &ui, PATH, &KDF);
    gkl_unlock(l, "T", 0);
    gkl_status(l, &st);
    CHECK(st.seconds_left == 86400);
    gkl_close(l);
    /* a file that isn't a number leaves the default */
    {
        static const char *bad[] = { "", "\n", "abc", "60x", "-5", "4294967296", "12345678901", "6 0" };
        size_t i;
        for (i = 0; i < sizeof bad / sizeof bad[0]; i++) {
            m_write(&x, PATH ".timeout", (const uint8_t *)bad[i], strlen(bad[i]));
            memset(&g, 0, sizeof g); g.answers[0] = "pass";
            gkl_open(&l, &e, &ui, PATH, &KDF);
            gkl_unlock(l, "T", 0);
            gkl_status(l, &st);
            CHECK(st.seconds_left == GK_DEFAULT_TIMEOUT);
            gkl_close(l);
        }
    }
    /* a write that fails: set for now, GKE_IO */
    memset(&g, 0, sizeof g); g.answers[0] = "pass";
    gkl_open(&l, &e, &ui, PATH, &KDF);
    gkl_unlock(l, "T", 0);
    x.ops = 0; x.crash_at = 0;
    CHECK(gkl_set_timeout(l, 30) == GKE_IO);
    x.crash_at = -1;
    gkl_status(l, &st);
    CHECK(st.seconds_left == 30);
    gkl_close(l);
    fs_free(&x);
}

int main(void)
{
    test_owner();
    test_noprompt();
    test_prompt_and_backoff();
    test_owner_recorded();
    test_rollback();
    test_older_copy();
    test_change_pass();
    test_no_count_and_no_store();
    test_timeout_kept();
    printf("%d/%d library checks passed\n", checks - fails, checks);
    return fails != 0;
}
