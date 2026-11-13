/* gk_lib: what gfopenkeys.library does on top of gk_store, in plain C so the
 * host tests build it (DESIGN.md sections 2, 4 and 5). The Amiga part (PR 3b)
 * is only glue: a gk_env on dos.library, a gk_ui on the GFOpenLayout
 * requester, a semaphore round each call and the LVO table.
 * MIT, Copyright (c) 2026 AmiCradle Team. */
#ifndef GK_LIB_H
#define GK_LIB_H

#include "gk_store.h"

#define GK_PASS_MAX 256              /* bytes of passphrase the requester takes */

/* What the library tells the user about (gk_ui.warn) */
#define GKW_OLDER_COPY   1           /* .bak or .new was opened: the newest change may be gone */
#define GKW_ROLLED_BACK  2           /* the store's write counter is lower than one seen before */
#define GKW_READONLY     3           /* an older passphrase opened .bak: read-only until the user locks and
                                        unlocks again with the newer passphrase */
#define GKW_NO_COUNT     4           /* the .count file is missing or unreadable: the rollback check starts again */

typedef struct gk_ui {
    /* Ask for the passphrase into buf (at most cap bytes, *len set). owner is
     * the asking program's name as it gives it (not proof: "a program calling
     * itself ..."); tries counts wrong ones so far. confirm: a new passphrase,
     * typed twice. 0, or GKE_CANCEL. The caller wipes buf. */
    int (*ask)(void *u, const char *owner, unsigned tries, int confirm, char *buf, size_t cap, size_t *len);
    void (*warn)(void *u, int what, uint64_t counter, uint64_t seen);
    void (*wait)(void *u, uint32_t seconds);      /* the backoff after wrong passphrases */
    void *u;
} gk_ui;

typedef struct gk_status {
    int exists, unlocked, readonly, rolled_back;
    int opened_from;                 /* 0 the store, 1 .new, 2 .bak, -1 locked */
    size_t count;
    uint32_t seconds_left;           /* UINT32_MAX with no timeout */
    uint64_t counter;
} gk_status;

typedef struct gk_lib gk_lib;

int gkl_open(gk_lib **out, const gk_env *env, const gk_ui *ui, const char *path, const gk_kdf *kdf);
void gkl_close(gk_lib *l);
gk_store *gkl_store(gk_lib *l);

/* The owner tag: at most GK_MAX_OWNER bytes of raw (a task's ln_Name, which
 * may be NULL), control bytes dropped; "(unnamed)" for NULL or empty */
void gkl_owner(char out[GK_MAX_OWNER + 1], const char *raw);

/* The library calls. With GKF_NOPROMPT a locked store answers GKE_LOCKED and
 * a missing one GKE_NOSTORE, and ui.ask is never called. */
int gkl_unlock(gk_lib *l, const char *owner, unsigned long flags);
void gkl_lock(gk_lib *l);
int gkl_find(gk_lib *l, const char *owner, const char *service, const char *host, const char *user,
             uint8_t *buf, size_t *len, unsigned long flags);
int gkl_store_entry(gk_lib *l, const char *owner, const char *service, const char *host, const char *user,
                    const uint8_t *secret, size_t len, const char *label, unsigned long flags);
int gkl_delete(gk_lib *l, const char *owner, const char *service, const char *host, const char *user, unsigned long flags);
int gkl_import(gk_lib *l, const char *owner, const gk_import_item *list, size_t count, unsigned long flags, size_t *added);
/* Asks for the current passphrase first, then the new one twice */
int gkl_change_pass(gk_lib *l, const char *owner, const gk_kdf *kdf, unsigned long flags);
void gkl_status(gk_lib *l, gk_status *st);   /* not a use */
/* Sets the timeout and keeps it in "<store>.timeout" for the next boot:
 * 0, or GKE_IO when it couldn't be written (it is set for now either way) */
int gkl_set_timeout(gk_lib *l, uint32_t seconds);

#endif
