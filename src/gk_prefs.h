/* gk_prefs: what the Keys prefs editor (SYS:Prefs/Keys) does that isn't
 * drawing: its ARexx commands (port GFOPENKEYS.1, DESIGN.md section 6) and
 * the "kept elsewhere" list. Plain C, so the host tests build it. No
 * command here returns a secret, and every one runs with GKF_NOPROMPT
 * (ARexx-RULE.md rule 4: no requester may block an ARexx command).
 * MIT, Copyright (c) 2026 AmiCradle Team. */
#ifndef GK_PREFS_H
#define GK_PREFS_H

#include "gk_lib.h"

/* ARexx return codes (ARexx-RULE.md rule 3) */
#define GKP_RC_OK      0
#define GKP_RC_WARN    5
#define GKP_RC_ERROR  10
#define GKP_RC_FAIL   20

/* The library calls the commands use. The prefs program fills these with
 * the GK_* calls of gfopenkeys.library; the host tests with gk_lib.
 * delete always means GKF_NOPROMPT. */
typedef struct gkp_ops {
    void (*status)(void *u, gk_status *st);
    void (*lock)(void *u);
    int (*list)(void *u, const char *service, int (*fn)(void *ctx, const gk_info *info), void *ctx);
    int (*del)(void *u, const char *service, const char *host, const char *user);
    int (*set_timeout)(void *u, uint32_t seconds);   /* 0, or GKE_IO when it couldn't be kept for the next boot */
    const char *(*error_string)(void *u, int error);
    void *u;
} gkp_ops;

#define GKP_VERSION "Keys 1.0 (13.11.2026)"

/* One ARexx command line. The text goes in result (always ends in 0): RESULT
 * when 0 is returned, else the reason, for RC2/LASTERROR. The app host
 * answers QUIT, ACTIVATE and DEACTIVATE itself.
 *   STATUS                 "exists 1 unlocked 1 readonly 0 count 3 left 840" (left: seconds, or none)
 *   LOCK
 *   LIST [[SERVICE=]word]  escaped names, one a line; 10 when locked
 *   DELETE name            name as LIST gives it, quotes allowed
 *   TIMEOUT seconds        0 keeps the keys open until reboot; 5 when set but not saved
 *   VERSION, HELP, FAULT n (n a GKE_ code; 3 is taken as -3) */
int gkp_rexx(const gkp_ops *ops, const char *line, char *result, size_t cap);

/* "service/host/user" with each part escaped (gk_escape), and back.
 * gkp_split: 0, or GKE_BADNAME when it isn't three parts or an escape is bad. */
size_t gkp_name(const char *service, const char *host, const char *user, char *out, size_t cap);
int gkp_split(const char *name, char service[GK_MAX_SERVICE + 1], char host[GK_MAX_PART + 1], char user[GK_MAX_PART + 1]);

/* The "kept elsewhere" section: programs not moved over yet and secrets the
 * host keeps (docs/SURVEY-20261113.md). Read-only text for the list. */
typedef struct gkp_elsewhere { const char *what, *where, *how; } gkp_elsewhere;
const gkp_elsewhere *gkp_kept_elsewhere(size_t *count);

#endif
