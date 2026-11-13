/* GFOpenKeysTry: the lab's driver for gfopenkeys.library (docs/PR3B-AMIGA.md).
 *   GFOpenKeysTry STATUS | NOPROMPT | STORE | FIND | DELETE | LOCK | CHANGE | TIMEOUT=<s>
 * It uses the service "gfopenkeys-try" only, and never prints a secret: FIND
 * prints its length and whether it matches.
 * MIT, Copyright (c) 2026 AmiCradle Team. */
#include <exec/types.h>
#include <proto/exec.h>
#include <proto/dos.h>
#include <proto/gfopenkeys.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct Library *GFOpenKeysBase;

#define SVC "gfopenkeys-try"
#define HOST "lab.example"
#define USER "tester"
#define SECRET "not-a-real-secret"

static void say(const char *what, LONG r)
{
    printf("%-10s %ld (%s)\n", what, (long)r, (const char *)GK_ErrorString(r));
}

int main(int argc, char **argv)
{
    const char *cmd = argc > 1 ? argv[1] : "STATUS";
    struct GKStatus st;
    if (!(GFOpenKeysBase = OpenLibrary((CONST_STRPTR)GFOPENKEYS_NAME, GFOPENKEYS_VERSION))) {
        printf("can't open %s %d: it needs gfopencrypto.library 2.4 and gfopentls.library 1.5 or newer in LIBS:\n",
               GFOPENKEYS_NAME, GFOPENKEYS_VERSION);
        return 20;
    }
    printf("gfopenkeys.library %lu.%lu\n", (unsigned long)(GK_Version() >> 16), (unsigned long)(GK_Version() & 0xffff));
    if (!strcmp(cmd, "NOPROMPT")) {
        UBYTE buf[64];
        ULONG len = sizeof buf;
        say("find", GK_Find((CONST_STRPTR)SVC, (CONST_STRPTR)HOST, (CONST_STRPTR)USER, buf, &len, GKF_NOPROMPT));
    } else if (!strcmp(cmd, "STORE")) {
        say("store", GK_Store((CONST_STRPTR)SVC, (CONST_STRPTR)HOST, (CONST_STRPTR)USER, (CONST UBYTE *)SECRET,
                              strlen(SECRET), (CONST_STRPTR)"Lab try", GKF_REPLACE));
    } else if (!strcmp(cmd, "FIND")) {
        UBYTE buf[64];
        ULONG len = sizeof buf;
        LONG r = GK_Find((CONST_STRPTR)SVC, (CONST_STRPTR)HOST, (CONST_STRPTR)USER, buf, &len, 0);
        say("find", r);
        if (!r) printf("length %lu, %s\n", (unsigned long)len, len == strlen(SECRET) && !memcmp(buf, SECRET, len) ? "matches" : "DIFFERS");
        memset(buf, 0, sizeof buf);
    } else if (!strcmp(cmd, "DELETE")) {
        say("delete", GK_Delete((CONST_STRPTR)SVC, (CONST_STRPTR)HOST, (CONST_STRPTR)USER, 0));
    } else if (!strcmp(cmd, "LOCK")) {
        GK_Lock();
        printf("locked\n");
    } else if (!strcmp(cmd, "CHANGE")) {
        say("change", GK_ChangePassphrase(NULL, 0));
    } else if (!strncmp(cmd, "TIMEOUT=", 8)) {
        say("timeout", GK_SetTimeout(strtoul(cmd + 8, NULL, 10)));
    }
    if (!GK_Status(&st))
        printf("exists %ld unlocked %ld readonly %ld rolled-back %ld from %ld count %lu left %lu counter %lu\n",
               (long)st.gs_Exists, (long)st.gs_Unlocked, (long)st.gs_ReadOnly, (long)st.gs_RolledBack,
               (long)st.gs_OpenedFrom, (unsigned long)st.gs_Count, (unsigned long)st.gs_SecondsLeft, (unsigned long)st.gs_CounterLo);
    CloseLibrary(GFOpenKeysBase);
    return 0;
}
