/* gk_amiga.h: what the library's Amiga files share (PR 3b).
 * MIT, Copyright (c) 2026 AmiCradle Team. */
#ifndef GK_AMIGA_H
#define GK_AMIGA_H

#include <exec/types.h>
#include <intuition/intuition.h>

#include "../src/gk_lib.h"

void gk_amiga_env(gk_env *e);
void gk_amiga_make_drawer(const char *drawer);

/* The requester. parent is the window to open it over (NULL: the default
 * public screen); it is set by the library call before gk_lib asks. */
void gk_amiga_ui(gk_ui *ui, struct Window **parent);

#endif
