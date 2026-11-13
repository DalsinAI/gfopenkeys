/* keys_prefs.c: SYS:Prefs/Keys, the keystore's prefs editor (DESIGN.md
 * section 6). A GadTools window (gfopengadtools lands it on GFOpenLayout,
 * UI-LAYER-RULE.md rule 3) on gfopenkeys.library's GK_* calls:
 *   - the list of keys (service/host/user, label, program, last use), never
 *     a secret, and only while the keys are unlocked;
 *   - Unlock, Lock now, Delete (with a check), Delete all of one service,
 *     Change passphrase and the timeout;
 *   - the read-only "kept elsewhere" list (gk_prefs.c).
 * The ARexx port GFOPENKEYS.1 (gfopensdk arexx/apphost.h) runs the
 * commands of gk_prefs.c with GKF_NOPROMPT: no requester ever opens for it.
 * MIT, Copyright (c) 2026 AmiCradle Team. */
#include <exec/types.h>
#include <exec/memory.h>
#include <exec/lists.h>
#include <intuition/intuition.h>
#include <libraries/gadtools.h>
#include <utility/hooks.h>
#include <dos/dos.h>
#include <dos/datetime.h>
#include <proto/exec.h>
#include <proto/dos.h>
#include <proto/intuition.h>
#include <proto/gadtools.h>
#include <proto/gfopenkeys.h>

#include <stdio.h>
#include <string.h>

#include "arexx/apphost.h"
#include "gk_prefs.h"

static const char version[] __attribute__((used)) = "$VER: Keys 1.0 (13.11.2026)";

struct Library *GFOpenKeysBase;

/* ---- the library calls, for gk_prefs.c's commands ------------------------- */

static void op_status(void *u, gk_status *st)
{
    struct GKStatus s;
    (void)u;
    memset(st, 0, sizeof *st);
    if (GK_Status(&s)) return;
    st->exists = s.gs_Exists; st->unlocked = s.gs_Unlocked; st->readonly = s.gs_ReadOnly;
    st->rolled_back = s.gs_RolledBack; st->opened_from = s.gs_OpenedFrom; st->count = s.gs_Count;
    st->seconds_left = s.gs_SecondsLeft;
    st->counter = ((uint64_t)s.gs_CounterHi << 32) | s.gs_CounterLo;
}

static void op_lock(void *u) { (void)u; GK_Lock(); }

typedef struct list_call { int (*fn)(void *ctx, const gk_info *in); void *ctx; } list_call;

static ULONG list_hook(struct Hook *h __asm("a0"), APTR o __asm("a2"), struct GKEntryInfo *e __asm("a1"))
{
    list_call *c = h->h_Data;
    gk_info in;
    (void)o;
    in.service = (const char *)e->ge_Service; in.host = (const char *)e->ge_Host; in.user = (const char *)e->ge_User;
    in.label = (const char *)e->ge_Label; in.owner = (const char *)e->ge_Owner;
    in.created = ((uint64_t)e->ge_CreatedHi << 32) | e->ge_CreatedLo;
    in.last_used = ((uint64_t)e->ge_LastUsedHi << 32) | e->ge_LastUsedLo;
    return (ULONG)c->fn(c->ctx, &in);
}

static int op_list(void *u, const char *service, int (*fn)(void *ctx, const gk_info *in), void *ctx)
{
    struct Hook h;
    list_call c;
    (void)u;
    memset(&h, 0, sizeof h);
    c.fn = fn; c.ctx = ctx;
    h.h_Entry = (HOOKFUNC)(APTR)list_hook;
    h.h_Data = &c;
    return (int)GK_List(&h, (CONST_STRPTR)service, GKF_NOPROMPT);
}

static int op_del(void *u, const char *service, const char *host, const char *user)
{
    (void)u;
    return (int)GK_Delete((CONST_STRPTR)service, (CONST_STRPTR)host, (CONST_STRPTR)user, GKF_NOPROMPT);
}

static void op_timeout(void *u, uint32_t seconds) { (void)u; GK_SetTimeout(seconds); }
static const char *op_err(void *u, int e) { (void)u; return (const char *)GK_ErrorString(e); }

static const gkp_ops ops = { op_status, op_lock, op_list, op_del, op_timeout, op_err, NULL };

/* ---- the window ----------------------------------------------------------- */

enum { G_LIST, G_STATE, G_UNLOCK, G_LOCK, G_DELETE, G_DELSVC, G_CHANGE, G_TIMEOUT, G_ELSE, G_COUNT };

typedef struct row {
    struct Node node;
    char service[GK_MAX_SERVICE + 1], host[GK_MAX_PART + 1], user[GK_MAX_PART + 1];
    char text[160];
} row;

static struct Window *win;
static struct Gadget *glist, *gad[G_COUNT];
static APTR vi;
static struct List keys, elsewhere;
static LONG chosen = -1;            /* the selected row of the keys list */
static int quit, dirty = 1, was_unlocked = -1;
static char state[120];

static void free_rows(struct List *l)
{
    struct Node *n;
    while ((n = RemHead(l))) FreeVec(n);
}

static row *row_at(LONG i)
{
    struct Node *n;
    for (n = keys.lh_Head; n->ln_Succ; n = n->ln_Succ, i--) if (!i) return (row *)n;
    return NULL;
}

static void when(char *out, size_t cap, uint64_t s)
{
    struct DateTime dt;
    char day[LEN_DATSTRING];
    if (!s) { snprintf(out, cap, "never"); return; }
    memset(&dt, 0, sizeof dt);
    dt.dat_Stamp.ds_Days = (LONG)(s / 86400);
    dt.dat_Stamp.ds_Minute = (LONG)(s % 86400 / 60);
    dt.dat_Format = FORMAT_DOS;
    dt.dat_StrDate = (STRPTR)day;
    day[0] = 0;
    DateToStr(&dt);
    snprintf(out, cap, "%s", day);
}

static int add_key(void *ctx, const gk_info *in)
{
    row *r = AllocVec(sizeof *r, MEMF_ANY | MEMF_CLEAR);
    char name[96], used[LEN_DATSTRING + 8];
    (void)ctx;
    if (!r) return 1;
    strncpy(r->service, in->service, sizeof r->service - 1);
    strncpy(r->host, in->host, sizeof r->host - 1);
    strncpy(r->user, in->user, sizeof r->user - 1);
    gkp_name(in->service, in->host, in->user, name, sizeof name);
    when(used, sizeof used, in->last_used);
    snprintf(r->text, sizeof r->text, "%-40.40s %-16.16s %-14.14s %s", name,
             in->label && *in->label ? in->label : "-", in->owner && *in->owner ? in->owner : "-", used);
    r->node.ln_Name = r->text;
    AddTail(&keys, &r->node);
    return 0;
}

static void fill_elsewhere(void)
{
    size_t n, i;
    const gkp_elsewhere *k = gkp_kept_elsewhere(&n);
    NewList(&elsewhere);
    for (i = 0; i < n; i++) {
        row *r = AllocVec(sizeof *r, MEMF_ANY | MEMF_CLEAR);
        if (!r) break;
        snprintf(r->text, sizeof r->text, "%-34.34s %-26.26s %s", k[i].what, k[i].where, k[i].how);
        r->node.ln_Name = r->text;
        AddTail(&elsewhere, &r->node);
    }
}

static void set_state(const char *s)
{
    snprintf(state, sizeof state, "%s", s);
    if (win) GT_SetGadgetAttrs(gad[G_STATE], win, NULL, GTTX_Text, (ULONG)state, TAG_END);
}

static void show_status(void)
{
    gk_status st;
    op_status(NULL, &st);
    if (!st.exists)
        set_state("No keys yet: a program makes them the first time it saves one");
    else if (!st.unlocked)
        set_state("Locked: Unlock to see your keys");
    else {
        char t[120];
        if (st.seconds_left == UINT32_MAX)
            snprintf(t, sizeof t, "Unlocked, %lu keys, until you lock them%s", (unsigned long)st.count,
                     st.readonly ? " (read-only)" : "");
        else
            snprintf(t, sizeof t, "Unlocked, %lu keys, locks in %lu min%s", (unsigned long)st.count,
                     (unsigned long)(st.seconds_left + 59) / 60, st.readonly ? " (read-only)" : "");
        set_state(t);
    }
    if (st.unlocked != was_unlocked) { was_unlocked = st.unlocked; dirty = 1; }
}

static void refill(void)
{
    if (win) GT_SetGadgetAttrs(gad[G_LIST], win, NULL, GTLV_Labels, ~0UL, TAG_END);
    free_rows(&keys);
    NewList(&keys);
    op_list(NULL, NULL, add_key, NULL);
    chosen = -1;
    if (win) GT_SetGadgetAttrs(gad[G_LIST], win, NULL, GTLV_Labels, (ULONG)&keys, GTLV_Selected, ~0UL, TAG_END);
    dirty = 0;
    show_status();
}

static int ask(const char *title, const char *text, const char *buttons, const char *arg)
{
    struct EasyStruct es = { sizeof(struct EasyStruct), 0, (UBYTE *)title, (UBYTE *)text, (UBYTE *)buttons };
    return (int)EasyRequest(win, &es, NULL, (ULONG)arg);
}

static void report(LONG r)
{
    if (r && r != GKE_CANCEL) set_state((const char *)GK_ErrorString(r));
    else dirty = 1;
}

static void delete_chosen(int whole_service)
{
    row *r = chosen >= 0 ? row_at(chosen) : NULL;
    char name[96];
    LONG first = 0, e;
    if (!r) { set_state("Choose a key in the list first"); return; }
    if (whole_service) {
        struct Node *n, *next;
        if (!ask("Keys", "Delete every key of the service\n%s?", "Delete|Cancel", r->service)) return;
        for (n = keys.lh_Head; (next = n->ln_Succ); n = next) {
            row *x = (row *)n;
            if (!strcmp(x->service, r->service) && x != r) {
                e = GK_Delete((CONST_STRPTR)x->service, (CONST_STRPTR)x->host, (CONST_STRPTR)x->user, 0);
                if (e && !first) first = e;       /* the first failure is the one to show */
            }
        }
    } else {
        gkp_name(r->service, r->host, r->user, name, sizeof name);
        if (!ask("Keys", "Delete the key\n%s?", "Delete|Cancel", name)) return;
    }
    e = GK_Delete((CONST_STRPTR)r->service, (CONST_STRPTR)r->host, (CONST_STRPTR)r->user, 0);
    report(first ? first : e);
    dirty = 1;                                    /* some may have gone even when one failed */
}

static int open_window(void)
{
    struct Screen *scr = LockPubScreen(NULL);
    struct NewGadget ng;
    struct Gadget *g;
    WORD fh, w, top, bw;
    if (!scr) return 0;
    fh = scr->Font->ta_YSize;
    w = 78 * (fh * 3 / 4);                   /* about 78 characters of the screen font */
    bw = (w - 16 - 4 * 8) / 5;
    top = scr->WBorTop + fh + 1 + 6;
    if (!(vi = GetVisualInfo(scr, TAG_END))) { UnlockPubScreen(NULL, scr); return 0; }
    g = CreateContext(&glist);
    memset(&ng, 0, sizeof ng);
    ng.ng_VisualInfo = vi; ng.ng_TextAttr = scr->Font;

    ng.ng_LeftEdge = scr->WBorLeft + 8; ng.ng_TopEdge = top + fh + 4; ng.ng_Width = w - 16; ng.ng_Height = 10 * (fh + 2);
    ng.ng_GadgetText = (UBYTE *)"Your keys"; ng.ng_Flags = PLACETEXT_ABOVE; ng.ng_GadgetID = G_LIST;
    g = gad[G_LIST] = CreateGadget(LISTVIEW_KIND, g, &ng, GTLV_Labels, (ULONG)&keys, GTLV_ShowSelected, 0UL, TAG_END);

    ng.ng_TopEdge += ng.ng_Height + 4; ng.ng_Height = fh + 4; ng.ng_GadgetText = NULL; ng.ng_GadgetID = G_STATE;
    g = gad[G_STATE] = CreateGadget(TEXT_KIND, g, &ng, GTTX_Text, (ULONG)state, GTTX_Border, TRUE, TAG_END);

    ng.ng_TopEdge += fh + 10; ng.ng_Width = bw; ng.ng_Height = fh + 6; ng.ng_Flags = PLACETEXT_IN;
    ng.ng_GadgetText = (UBYTE *)"_Unlock"; ng.ng_GadgetID = G_UNLOCK;
    g = gad[G_UNLOCK] = CreateGadget(BUTTON_KIND, g, &ng, GT_Underscore, '_', TAG_END);
    ng.ng_LeftEdge += bw + 8; ng.ng_GadgetText = (UBYTE *)"_Lock now"; ng.ng_GadgetID = G_LOCK;
    g = gad[G_LOCK] = CreateGadget(BUTTON_KIND, g, &ng, GT_Underscore, '_', TAG_END);
    ng.ng_LeftEdge += bw + 8; ng.ng_GadgetText = (UBYTE *)"_Delete..."; ng.ng_GadgetID = G_DELETE;
    g = gad[G_DELETE] = CreateGadget(BUTTON_KIND, g, &ng, GT_Underscore, '_', TAG_END);
    ng.ng_LeftEdge += bw + 8; ng.ng_GadgetText = (UBYTE *)"Delete _service..."; ng.ng_GadgetID = G_DELSVC;
    g = gad[G_DELSVC] = CreateGadget(BUTTON_KIND, g, &ng, GT_Underscore, '_', TAG_END);
    ng.ng_LeftEdge += bw + 8; ng.ng_GadgetText = (UBYTE *)"_Passphrase..."; ng.ng_GadgetID = G_CHANGE;
    g = gad[G_CHANGE] = CreateGadget(BUTTON_KIND, g, &ng, GT_Underscore, '_', TAG_END);

    ng.ng_LeftEdge = scr->WBorLeft + 8 + 30 * (fh * 3 / 4); ng.ng_TopEdge += fh + 12; ng.ng_Width = 6 * (fh * 3 / 4) + 12;
    ng.ng_Height = fh + 6; ng.ng_GadgetText = (UBYTE *)"Lock after (minutes, 0 never)"; ng.ng_Flags = PLACETEXT_LEFT;
    ng.ng_GadgetID = G_TIMEOUT;
    g = gad[G_TIMEOUT] = CreateGadget(INTEGER_KIND, g, &ng, GTIN_Number, GK_DEFAULT_TIMEOUT / 60, GTIN_MaxChars, 4, TAG_END);

    ng.ng_LeftEdge = scr->WBorLeft + 8; ng.ng_TopEdge += fh + 12 + fh + 4; ng.ng_Width = w - 16; ng.ng_Height = 6 * (fh + 2);
    ng.ng_GadgetText = (UBYTE *)"Kept elsewhere (not in your keys)"; ng.ng_Flags = PLACETEXT_ABOVE; ng.ng_GadgetID = G_ELSE;
    g = gad[G_ELSE] = CreateGadget(LISTVIEW_KIND, g, &ng, GTLV_Labels, (ULONG)&elsewhere, GTLV_ReadOnly, TRUE, TAG_END);
    if (!g) { UnlockPubScreen(NULL, scr); return 0; }

    win = OpenWindowTags(NULL, WA_Title, (ULONG)"Keys", WA_PubScreen, (ULONG)scr,
                         WA_InnerWidth, w, WA_InnerHeight, ng.ng_TopEdge + ng.ng_Height + 8 - scr->WBorTop - fh - 1,
                         WA_Gadgets, (ULONG)glist, WA_Activate, TRUE, WA_DragBar, TRUE, WA_DepthGadget, TRUE,
                         WA_CloseGadget, TRUE,
                         WA_IDCMP, IDCMP_CLOSEWINDOW | IDCMP_REFRESHWINDOW | IDCMP_VANILLAKEY | IDCMP_INTUITICKS
                                   | LISTVIEWIDCMP | BUTTONIDCMP | INTEGERIDCMP,
                         TAG_END);
    UnlockPubScreen(NULL, scr);
    if (!win) return 0;
    GT_RefreshWindow(win, NULL);
    return 1;
}

static void close_window(void)
{
    if (win) CloseWindow(win);
    win = NULL;
    FreeGadgets(glist);
    glist = NULL;
    if (vi) FreeVisualInfo(vi);
    vi = NULL;
}

static void press(UWORD id, UWORD code)
{
    switch (id) {
    case G_LIST: chosen = code; break;
    case G_UNLOCK: report(GK_Unlock(win, 0)); break;
    case G_LOCK: GK_Lock(); dirty = 1; break;
    case G_DELETE: delete_chosen(0); break;
    case G_DELSVC: delete_chosen(1); break;
    case G_CHANGE: report(GK_ChangePassphrase(win, 0)); break;
    case G_TIMEOUT: {
        struct StringInfo *si = (struct StringInfo *)gad[G_TIMEOUT]->SpecialInfo;
        LONG m = si->LongInt;
        if (m < 0 || m > 24 * 60) { set_state("The timeout is 0 to 1440 minutes"); break; }
        GK_SetTimeout((ULONG)m * 60);
        show_status();
        break;
    }
    }
}

static void window_events(void)
{
    struct IntuiMessage *m;
    static int ticks;
    while (win && (m = GT_GetIMsg(win->UserPort))) {
        ULONG cls = m->Class;
        UWORD code = m->Code;
        struct Gadget *g = (struct Gadget *)m->IAddress;
        GT_ReplyIMsg(m);
        switch (cls) {
        case IDCMP_CLOSEWINDOW: quit = 1; break;
        case IDCMP_REFRESHWINDOW: GT_BeginRefresh(win); GT_EndRefresh(win, TRUE); break;
        case IDCMP_GADGETUP: press(g->GadgetID, code); break;
        case IDCMP_VANILLAKEY:
            if (code == 27) quit = 1;
            else if (code == 'u' || code == 'U') press(G_UNLOCK, 0);
            else if (code == 'l' || code == 'L') press(G_LOCK, 0);
            break;
        case IDCMP_INTUITICKS:
            if (++ticks >= 10) { ticks = 0; show_status(); }   /* about once a second */
            break;
        }
    }
}

/* ---- the ARexx port: gk_prefs.c's commands -------------------------------- */

static char rx_out[AH_RESULT_MAX];

static void rx_run(ah_call *c, const char *line)
{
    int rc = gkp_rexx(&ops, line, rx_out, sizeof rx_out);
    if (rc) ah_error(c, rc, 0);
    else if (rx_out[0]) ah_result(c, "%s", rx_out);
    dirty = 1;
}

static void cmd_status(ah_call *c) { rx_run(c, "STATUS"); }
static void cmd_lock(ah_call *c) { rx_run(c, "LOCK"); }

static void cmd_list(ah_call *c)
{
    char line[48];
    snprintf(line, sizeof line, "LIST SERVICE=%.31s", ah_str(c, 0));
    rx_run(c, line);
}

static void cmd_delete(ah_call *c)
{
    static char line[GK_MAX_SERVICE * 3 + 2 * GK_MAX_PART * 3 + 16];
    snprintf(line, sizeof line, "DELETE %s", ah_str(c, 0));
    rx_run(c, line);
}

static void cmd_timeout(ah_call *c)
{
    char line[32];
    snprintf(line, sizeof line, "TIMEOUT %ld", (long)ah_num(c, 0, -1));
    rx_run(c, line);
}

static void cmd_fault(ah_call *c)
{
    char line[32];
    snprintf(line, sizeof line, "FAULT %ld", (long)ah_num(c, 0, 0));
    rx_run(c, line);
}

static const ah_cmd cmds[] = {
    { "STATUS", "", cmd_status },
    { "LOCK", "", cmd_lock },
    { "LIST", "SERVICE", cmd_list },
    { "DELETE", "NAME/A", cmd_delete },
    { "TIMEOUT", "SECONDS/N/A", cmd_timeout },
    { "FAULT", "CODE/N/A", cmd_fault },              /* a GKE_ code, not a DOS one */
    { 0, 0, 0 }
};

static int rx_quit(void *u, int force) { (void)u; (void)force; quit = 1; return 1; }
static void rx_activate(void *u)
{
    (void)u;
    if (win) { WindowToFront(win); ActivateWindow(win); }
}

static const ah_hooks hooks = { GKP_VERSION, rx_quit, rx_activate, NULL, NULL };

/* ---- main ------------------------------------------------------------------ */

int main(void)
{
    ah_host *rexx;
    int rc = 0;
    if (!(GFOpenKeysBase = OpenLibrary((CONST_STRPTR)GFOPENKEYS_NAME, GFOPENKEYS_VERSION))) {
        printf("Keys needs %s %d, with gfopencrypto.library 2.4 and gfopentls.library 1.5, in LIBS:\n",
               GFOPENKEYS_NAME, GFOPENKEYS_VERSION);
        return 20;
    }
    NewList(&keys);
    fill_elsewhere();
    rexx = ah_open("GFOPENKEYS", cmds, &hooks);     /* NULL: no port, the window still works */
    if (!open_window()) {
        rc = 20;
        quit = 1;
    }
    while (!quit) {
        ULONG got;
        if (dirty) refill();
        got = Wait((1UL << win->UserPort->mp_SigBit) | ah_sigmask(rexx) | SIGBREAKF_CTRL_C);
        if (got & SIGBREAKF_CTRL_C) quit = 1;
        if (got & ah_sigmask(rexx)) ah_handle(rexx);
        window_events();
    }
    close_window();
    ah_close(rexx);
    free_rows(&keys);
    free_rows(&elsewhere);
    CloseLibrary(GFOpenKeysBase);
    return rc;
}
