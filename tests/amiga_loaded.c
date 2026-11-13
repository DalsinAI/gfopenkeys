/* amiga_loaded.c: GFOpenKeysLoaded, for the lab. Says whether
 * gfopenkeys.library is in memory (on exec's library list) and whether its
 * timeout process is running, without opening the library, so it can check
 * that QUIT plus Avail FLUSH really unloads it. RC 0 when gone, 5 when
 * still there.
 * MIT, Copyright (c) 2026 AmiCradle Team. */
#include <exec/types.h>
#include <exec/execbase.h>
#include <exec/libraries.h>
#include <proto/exec.h>
#include <stdio.h>

#include <libraries/gfopenkeys.h>

int main(void)
{
    struct Library *lib;
    struct Task *ticker;
    UWORD ver = 0, rev = 0, opens = 0;
    Forbid();
    lib = (struct Library *)FindName(&SysBase->LibList, (CONST_STRPTR)GFOPENKEYS_NAME);
    if (lib) { ver = lib->lib_Version; rev = lib->lib_Revision; opens = lib->lib_OpenCnt; }
    ticker = FindTask((CONST_STRPTR)"gfopenkeys timeout");
    Permit();
    if (lib) printf("%s %u.%u in memory, open %u times\n", GFOPENKEYS_NAME, (unsigned)ver, (unsigned)rev, (unsigned)opens);
    else printf("%s not in memory\n", GFOPENKEYS_NAME);
    printf("timeout process: %s\n", ticker ? "running" : "gone");
    return lib || ticker ? 5 : 0;
}
