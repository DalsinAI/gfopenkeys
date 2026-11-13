/*
 * arexx/apphost.h: a program's ARexx port on arexx.class, for C programs,
 * the way every one of our programs has it (wx programs have the same
 * thing as wxARexxPort in the GFOpenWX Toolkit). Header only: include it
 * in one source file of the program.
 *
 * The program gives a table of its own commands (name, ReadArgs template,
 * function) and three hooks; the port has these from the start:
 *
 *   QUIT FORCE/S       the program's quit hook (FORCE: it cannot refuse)
 *   ACTIVATE           the activate hook: main window to the front
 *   DEACTIVATE         the deactivate hook: main window to its icon
 *   VERSION            RESULT: the program's name and version
 *   HELP COMMAND       RESULT: the commands, or one command's template
 *   FAULT CODE/N/A     RESULT: the text of a DOS error number
 *
 * A command of the program's own with one of those names is used instead.
 * The port is NAME.1, NAME.2 for a second copy. The program adds
 * ah_sigmask() to its Wait() and calls ah_handle() when that signal comes:
 * commands run there, in the program's own task. RC is 0, or what
 * ah_error() gives (5 a warning, 10 an error, 20 a failure); RESULT goes
 * back only when the script asked for it (OPTIONS RESULTS).
 *
 *   static void cmd_open(ah_call *c)
 *   {
 *       if (!open_file(ah_str(c, 0)))
 *           ah_error(c, 10, IoErr());
 *   }
 *   static const ah_cmd cmds[] = { { "OPEN", "FILE/A", cmd_open }, { 0 } };
 *   static const ah_hooks hooks = { "GFOpenFiles 0.4.2", my_quit, my_front, my_icon, NULL };
 *   ah_host *rexx = ah_open("GFOPENFILES", cmds, &hooks);   (NULL: no port, go on)
 *   ...  got = Wait(... | ah_sigmask(rexx));  if (got & ah_sigmask(rexx)) ah_handle(rexx);
 *   ah_close(rexx);
 *
 * arexx.class is OS 3.2's or ours (amicradle-guest libraries/openreaction).
 *
 * Copyright (c) 2026 AmiCradle Team. MIT.
 */
#ifndef AREXX_APPHOST_H
#define AREXX_APPHOST_H

#include <exec/types.h>
#include <exec/memory.h>
#include <intuition/classes.h>
#include <intuition/classusr.h>
#include <classes/arexx.h>
#include <dos/dos.h>
#include <rexx/storage.h>
#include <utility/tagitem.h>
#include <proto/exec.h>
#include <proto/intuition.h>
#include <proto/dos.h>
#include <clib/alib_protos.h>   /* DoMethod (amiga.lib) */
#include <inline/macros.h>      /* LP0 */
#include <string.h>
#include <stdio.h>
#include <stdarg.h>

#ifndef AH_RESULT_MAX
#define AH_RESULT_MAX 2048
#endif

typedef struct ah_host ah_host;

typedef struct ah_call
{
    ah_host         *host;
    struct ARexxCmd *cmd;
} ah_call;

typedef struct ah_cmd
{
    const char *name;               /* in capitals */
    const char *tmpl;               /* ReadArgs template, "" for none */
    void      (*fn)(ah_call *c);
} ah_cmd;

typedef struct ah_hooks
{
    const char *version;            /* VERSION's answer: "GFOpenFiles 0.4.2" */
    int       (*quit)(void *user, int force);   /* 0: refused (RC 5) */
    void      (*activate)(void *user);
    void      (*deactivate)(void *user);
    void       *user;
} ah_hooks;

struct ah_host
{
    struct Library        *lib;
    Object                *obj;
    ULONG                  sigmask;
    const ah_cmd          *mine;
    const ah_hooks        *hooks;
    int                    nmine;
    struct ARexxCmd       *table;   /* the program's, then the standard ones */
    int                    ntable;
    char                   result[AH_RESULT_MAX];
};

/* ---- for a command's function ---- */

/* argument i of the template (0 the first): given or not */
static __attribute__((unused)) int ah_has(ah_call *c, int i)
{
    return c->cmd->ac_ArgList && c->cmd->ac_ArgList[i] != 0;
}

/* a string argument (/A, /K or plain), "" when not given */
static __attribute__((unused)) const char *ah_str(ah_call *c, int i)
{
    return ah_has(c, i) ? (const char *)c->cmd->ac_ArgList[i] : "";
}

/* a number (/N), def when not given */
static __attribute__((unused)) LONG ah_num(ah_call *c, int i, LONG def)
{
    return ah_has(c, i) ? *(LONG *)c->cmd->ac_ArgList[i] : def;
}

/* a switch (/S) */
static __attribute__((unused)) int ah_switch(ah_call *c, int i)
{
    return ah_has(c, i);
}

/* a list (/M): its strings, ended by NULL */
static __attribute__((unused)) const char **ah_multi(ah_call *c, int i)
{
    static const char *none[1] = { NULL };
    return ah_has(c, i) ? (const char **)c->cmd->ac_ArgList[i] : none;
}

/* RESULT, as printf; cut at AH_RESULT_MAX */
static __attribute__((unused)) void ah_result(ah_call *c, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(c->host->result, sizeof c->host->result, fmt, ap);
    va_end(ap);
    c->cmd->ac_Result = (STRPTR)c->host->result;
}

/* RC (and RC2) instead of 0; no RESULT then */
static __attribute__((unused)) void ah_error(ah_call *c, LONG rc, LONG rc2)
{
    c->cmd->ac_RC = rc;
    c->cmd->ac_RC2 = rc2;
    c->cmd->ac_Result = NULL;
}

/* ---- the port ---- */

enum { AH_QUIT = 1000, AH_ACTIVATE, AH_DEACTIVATE, AH_VERSION, AH_HELP, AH_FAULT };

static __attribute__((unused)) ah_host *ah__now;

/* names compared without case (ASCII), so no utility.library is needed */
static __attribute__((unused)) int ah__same(const char *a, const char *b)
{
    for (;; a++, b++) {
        int x = (unsigned char)*a, y = (unsigned char)*b;
        if (x >= 'a' && x <= 'z')
            x -= 32;
        if (y >= 'a' && y <= 'z')
            y -= 32;
        if (x != y)
            return 0;
        if (!x)
            return 1;
    }
}            /* the port whose ah_handle() runs */

static __attribute__((unused)) void ah__standard(ah_call *c, int id)
{
    ah_host *h = c->host;
    const ah_hooks *k = h->hooks;
    switch (id) {
    case AH_QUIT:
        if (!k->quit || !k->quit(k->user, ah_has(c, 0)))
            ah_error(c, 5, 0);
        break;
    case AH_ACTIVATE:
        if (k->activate)
            k->activate(k->user);
        break;
    case AH_DEACTIVATE:
        if (k->deactivate)
            k->deactivate(k->user);
        else
            ah_error(c, 5, 0);
        break;
    case AH_VERSION:
        ah_result(c, "%s", k->version ? k->version : "");
        break;
    case AH_HELP: {
        const char *want = ah_str(c, 0);
        size_t n = 0;
        int i;
        h->result[0] = 0;
        for (i = 0; i < h->ntable; i++) {
            struct ARexxCmd *t = &h->table[i];
            if (*want) {
                if (ah__same(want, (const char *)t->ac_Name)) {
                    ah_result(c, "%s%s%s", (char *)t->ac_Name, t->ac_ArgTemplate && *t->ac_ArgTemplate ? " " : "",
                              t->ac_ArgTemplate ? (char *)t->ac_ArgTemplate : "");
                    return;
                }
                continue;
            }
            n += snprintf(h->result + n, n < sizeof h->result ? sizeof h->result - n : 0, "%s%s", n ? " " : "",
                          (char *)t->ac_Name);
        }
        if (*want)
            ah_error(c, 10, ERROR_OBJECT_NOT_FOUND);
        else
            c->cmd->ac_Result = (STRPTR)h->result;
        break;
    }
    case AH_FAULT:
        Fault(ah_num(c, 0, 0), NULL, (STRPTR)h->result, sizeof h->result);
        c->cmd->ac_Result = (STRPTR)h->result;
        break;
    }
}

/* arexx.class calls this (A0 the command, A1 the message) from inside
 * AM_HANDLEEVENT, in the program's own task */
static __attribute__((unused)) void ah__func(struct ARexxCmd *cmd __asm("a0"), struct RexxMsg *msg __asm("a1"))
{
    ah_call c;
    (void)msg;
    if (!ah__now)
        return;
    c.host = ah__now;
    c.cmd = cmd;
    cmd->ac_RC = 0;
    cmd->ac_RC2 = 0;
    cmd->ac_Result = NULL;
    if (cmd->ac_ID >= AH_QUIT)
        ah__standard(&c, cmd->ac_ID);
    else if (cmd->ac_ID < ah__now->nmine && ah__now->mine[cmd->ac_ID].fn)
        ah__now->mine[cmd->ac_ID].fn(&c);
}

static __attribute__((unused)) void ah_close(ah_host *h)
{
    if (!h)
        return;
    if (h->obj)
        DisposeObject(h->obj);
    if (h->lib)
        CloseLibrary(h->lib);
    if (h->table)
        FreeVec(h->table);
    FreeVec(h);
}

/* the port: name in capitals without the slot; NULL when arexx.class or
 * the port can't be had (the program goes on without one) */
static __attribute__((unused)) ah_host *ah_open(const char *name, const ah_cmd *cmds, const ah_hooks *hooks)
{
    static const struct { const char *name, *tmpl; int id; } std[] = {
        { "QUIT", "FORCE/S", AH_QUIT }, { "ACTIVATE", "", AH_ACTIVATE }, { "DEACTIVATE", "", AH_DEACTIVATE },
        { "VERSION", "", AH_VERSION }, { "HELP", "COMMAND", AH_HELP }, { "FAULT", "CODE/N/A", AH_FAULT },
    };
    ah_host *h;
    int i, j, n = 0, k;
    while (cmds && cmds[n].name)
        n++;
    if (!(h = (ah_host *)AllocVec(sizeof *h, MEMF_CLEAR)))
        return NULL;
    h->mine = cmds;
    h->nmine = n;
    h->hooks = hooks;
    h->table = (struct ARexxCmd *)AllocVec(sizeof(struct ARexxCmd) * (n + 7), MEMF_CLEAR);
    if (!h->table)
        goto fail;
    for (i = 0; i < n; i++) {
        h->table[i].ac_Name = (STRPTR)cmds[i].name;
        h->table[i].ac_ID = (UWORD)i;
        h->table[i].ac_Func = (void (*)(struct ARexxCmd *, struct RexxMsg *))ah__func;   /* A0, A1 */
        h->table[i].ac_ArgTemplate = (STRPTR)(cmds[i].tmpl ? cmds[i].tmpl : "");
    }
    k = n;
    for (j = 0; j < (int)(sizeof std / sizeof std[0]); j++) {
        int dup = 0;
        for (i = 0; i < n; i++)
            if (ah__same(cmds[i].name, std[j].name))
                dup = 1;
        if (dup)
            continue;
        h->table[k].ac_Name = (STRPTR)std[j].name;
        h->table[k].ac_ID = (UWORD)std[j].id;
        h->table[k].ac_Func = (void (*)(struct ARexxCmd *, struct RexxMsg *))ah__func;   /* A0, A1 */
        h->table[k].ac_ArgTemplate = (STRPTR)std[j].tmpl;
        k++;
    }
    h->ntable = k;
    if (!(h->lib = OpenLibrary((CONST_STRPTR)"arexx.class", 44)) &&
        !(h->lib = OpenLibrary((CONST_STRPTR)"classes/arexx.class", 44)))
        goto fail;
    /* the class from AREXX_GetClass (-30): OS 3.2's arexx.class does
       not answer NewObject by its public name */
    {
        struct Library *ah__base = h->lib;
        Class *cl = LP0(0x1e, Class *, AREXX_GetClass, , ah__base);
        struct TagItem tags[3];
        if (!cl)
            goto fail;
        tags[0].ti_Tag = AREXX_HostName;  tags[0].ti_Data = (ULONG)name;
        tags[1].ti_Tag = AREXX_Commands;  tags[1].ti_Data = (ULONG)h->table;
        tags[2].ti_Tag = TAG_END;         tags[2].ti_Data = 0;
        h->obj = (Object *)NewObjectA(cl, NULL, tags);
    }
    if (!h->obj)
        goto fail;
    GetAttr(AREXX_SigMask, h->obj, &h->sigmask);
    return h;
fail:
    ah_close(h);
    return NULL;
}

/* the port's signal, for Wait(); 0 without a port */
static __attribute__((unused)) ULONG ah_sigmask(ah_host *h)
{
    return h ? h->sigmask : 0;
}

/* the port's name with its slot (GFOPENFILES.1), or "" */
static __attribute__((unused)) const char *ah_portname(ah_host *h)
{
    STRPTR s = NULL;
    if (h && h->obj)
        GetAttr(AREXX_HostName, h->obj, (ULONG *)&s);
    return s ? (const char *)s : "";
}

/* runs the commands that have come; call it when ah_sigmask()'s signal comes */
static __attribute__((unused)) void ah_handle(ah_host *h)
{
    ah_host *was;
    if (!h || !h->obj)
        return;
    was = ah__now;
    ah__now = h;
    DoMethod(h->obj, AM_HANDLEEVENT);
    ah__now = was;
}

#endif /* AREXX_APPHOST_H */
