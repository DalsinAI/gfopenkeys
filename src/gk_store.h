/* gk_store: the keystore's core, plain C with no Amiga calls, so the host
 * tests build exactly the code the library runs (DESIGN.md sections 3 to 5).
 * The file system, the random source and the clock come in through gk_env;
 * the crypto is gfopencrypto's oc_* calls (the real code on the host, the
 * stub that calls gfopencrypto.library on the Amiga).
 * MIT, Copyright (c) 2026 AmiCradle Team. */
#ifndef GK_STORE_H
#define GK_STORE_H

#include <stddef.h>
#include <stdint.h>

#include "libraries/gfopenkeys.h"

typedef struct gk_env {
    /* The whole file into *data (malloc'ed, the caller frees): 0, GKE_NOTFOUND or GKE_IO */
    int (*read)(void *u, const char *name, uint8_t **data, size_t *len);
    /* Write the whole file and flush it: 0 or GKE_IO */
    int (*write)(void *u, const char *name, const uint8_t *data, size_t len);
    /* Rename; the target must not exist (as AmigaDOS): 0 or GKE_IO */
    int (*rename)(void *u, const char *from, const char *to);
    /* Delete: 0 or GKE_IO. A missing file may answer either way (DeleteFile() fails on one) */
    int (*remove)(void *u, const char *name);
    /* Random bytes: 0, or GKE_CRYPTO */
    int (*random)(void *u, uint8_t *out, size_t len);
    /* Seconds, for the timeout (any epoch) */
    uint64_t (*now)(void *u);
    /* Argon2id's work area: malloc and free, or a static block on a small machine */
    void *(*alloc)(void *u, size_t len);
    void (*release)(void *u, void *p, size_t len);
    void *u;
} gk_env;

typedef struct gk_kdf {
    uint32_t passes, m_kib, lanes;
} gk_kdf;

typedef struct gk_info {             /* what GK_List hands out: never the secret */
    const char *service, *host, *user, *label, *owner;
    uint64_t created, last_used;
} gk_info;

typedef struct gk_import {
    const char *service, *host, *user, *label;
    const uint8_t *secret;
    size_t secret_len;
} gk_import_item;

typedef struct gk_store gk_store;

/* path is the store file, such as "ENVARC:GFOpenKeys/Default.keys"; ".new" and ".bak" go beside it */
int gk_open(gk_store **out, const gk_env *env, const char *path);
void gk_close(gk_store *s);

int gk_exists(gk_store *s);          /* 1 when any copy of the file is there */
/* create and change_pass make a new Argon2id salt and a new nonce for the data
 * key's seal every time. GKE_NOMEM when env->alloc can't give Argon2id's area. */
int gk_create(gk_store *s, const char *pass, size_t pass_len, const gk_kdf *kdf);
int gk_unlock(gk_store *s, const char *pass, size_t pass_len);
void gk_lock(gk_store *s);
int gk_is_unlocked(gk_store *s);     /* locks first when the timeout has passed */
/* What counts as use (restarts the timer): unlock, create, find, put, delete,
 * import, change_pass. Not a use: is_unlocked, seconds_left, count, list. */
void gk_set_timeout(gk_store *s, uint32_t seconds);
uint32_t gk_seconds_left(gk_store *s);   /* 0 when locked; UINT32_MAX with no timeout */
size_t gk_count(gk_store *s);
/* Which copy the last unlock opened: 0 the store, 1 ".new", 2 ".bak" (-1 locked).
 * 2 means the store was damaged or missing: the caller warns the user that the
 * last change may be lost, or that an older copy was put back (DESIGN.md 4). */
int gk_opened_from(gk_store *s);
uint64_t gk_generation(gk_store *s);  /* the write counter: one more each save */
/* 1 after an older passphrase opened .bak while the store file is under a
 * newer one: every write answers GKE_READONLY, and lock writes nothing */
int gk_is_readonly(gk_store *s);
/* 0 when pass opens the store as it is now, GKE_BADPASS when not */
int gk_check_pass(gk_store *s, const char *pass, size_t pass_len);

/* The secret is copied into buf: cleansing that copy is the caller's job */
int gk_find(gk_store *s, const char *service, const char *host, const char *user, uint8_t *buf, size_t *len);
int gk_put(gk_store *s, const char *service, const char *host, const char *user,
           const uint8_t *secret, size_t secret_len, const char *label, const char *owner, unsigned long flags);
int gk_delete(gk_store *s, const char *service, const char *host, const char *user);
/* fn returns nonzero to stop; service NULL for every entry */
/* The timeout doesn't lock while fn runs, so fn may call gk_find, gk_list
 * and the status calls. fn must not change the store (put, remove, import,
 * change_pass, lock): the library answers those GKE_BUSY from a hook. */
int gk_list(gk_store *s, const char *service, int (*fn)(void *ctx, const gk_info *info), void *ctx);
/* One write for a program's migration; *added: how many went in */
int gk_import(gk_store *s, const gk_import_item *list, size_t count, const char *from, unsigned long flags, size_t *added);
int gk_change_pass(gk_store *s, const char *pass, size_t pass_len, const gk_kdf *kdf);

/* service/host/user for display: '/', '%' and control bytes as %XX. The length written (out always ends in 0). */
size_t gk_escape(const char *in, char *out, size_t cap);
/* The rule of DESIGN.md section 3: 0 or GKE_BADNAME */
int gk_check_name(const char *service, const char *host, const char *user);

/* The AEAD on its own, for the tests: ChaCha20-Poly1305 with a 64-bit nonce
 * (draft-agl-tls-chacha20poly1305; libsodium's crypto_aead_chacha20poly1305). */
void gk_seal(uint8_t *out, uint8_t tag[16], const uint8_t *in, size_t len,
             const uint8_t *ad, size_t ad_len, const uint8_t key[32], const uint8_t nonce[8]);
int gk_unseal(uint8_t *out, const uint8_t *in, size_t len, const uint8_t tag[16],
              const uint8_t *ad, size_t ad_len, const uint8_t key[32], const uint8_t nonce[8]);

#endif
