/* gk_amiga_ui.c: the unlock requester, a gk_ui on GadTools (which
 * gfopengadtools lands on GFOpenLayout, UI-LAYER-RULE.md rule 3), and the
 * warnings through EasyRequest (themed by gfopengadtools, REQUESTERS.md).
 *
 * The passphrase field shows '*': a string edit hook keeps what is typed in
 * the library's own buffer and puts '*' in the gadget's, so neither the
 * gadget's buffer nor its UndoBuffer ever holds the passphrase. Both are
 * wiped anyway when the requester closes.
 * MIT, Copyright (c) 2026 AmiCradle Team. */
#include <exec/types.h>
#include <exec/memory.h>
#include <intuition/intuition.h>
#include <intuition/sghooks.h>
#include <intuition/gadgetclass.h>
#include <libraries/gadtools.h>
#include <utility/hooks.h>
#include <proto/exec.h>
#include <proto/dos.h>
#include <proto/intuition.h>
#include <proto/gadtools.h>
#include "gfopencrypto/gfopencrypto.h"   /* oc_cleanse, through libgfopencrypto.a */

#include <string.h>

#include "gk_amiga.h"

#define REG(r, decl) register decl __asm(#r)

enum { G_TEXT, G_PASS, G_PASS2, G_OK, G_CANCEL, G_COUNT };

/* one masked field: what is typed, kept here */
typedef struct field {
    struct Hook hook;
    char real[GK_PASS_MAX];
    UWORD len;
} field;

static ULONG edit_hook(REG(a0, struct Hook *h), REG(a2, struct SGWork *sgw), REG(a1, ULONG *msg))
{
    field *f = (field *)h->h_Data;
    UWORD old_pos, new_pos, i;
    if (*msg != SGH_KEY) return 0;
    old_pos = sgw->StringInfo->BufferPos;
    new_pos = sgw->BufferPos;
    switch (sgw->EditOp) {
    case EO_INSERTCHAR:
    case EO_REPLACECHAR:
        if (!new_pos || new_pos > sizeof f->real) { sgw->Actions &= ~SGA_USE; break; }
        if (sgw->EditOp == EO_INSERTCHAR) {
            if (f->len >= sizeof f->real) { sgw->Actions &= ~SGA_USE; break; }
            memmove(f->real + new_pos, f->real + new_pos - 1, f->len - (new_pos - 1));
            f->len++;
        }
        f->real[new_pos - 1] = (char)sgw->WorkBuffer[new_pos - 1];
        sgw->WorkBuffer[new_pos - 1] = '*';
        break;
    case EO_DELBACKWARD:
        if (old_pos && old_pos <= f->len) {
            memmove(f->real + old_pos - 1, f->real + old_pos, f->len - old_pos);
            f->len--;
        }
        break;
    case EO_DELFORWARD:
        if (old_pos < f->len) {
            memmove(f->real + old_pos, f->real + old_pos + 1, f->len - old_pos - 1);
            f->len--;
        }
        break;
    case EO_MOVECURSOR:
    case EO_NOOP:
    case EO_ENTER:
    case EO_SPECIAL:
        break;
    default:   /* clear, paste, undo and the rest: start the field again */
        f->len = 0;
        for (i = 0; i < sgw->StringInfo->MaxChars; i++) sgw->WorkBuffer[i] = 0;
        sgw->NumChars = 0;
        sgw->BufferPos = 0;
        sgw->Actions |= SGA_REDISPLAY;
        break;
    }
    oc_cleanse(f->real + f->len, sizeof f->real - f->len);
    return ~0UL;
}

static void wipe_gadget(struct Gadget *g)
{
    struct StringInfo *si;
    if (!g || !(si = (struct StringInfo *)g->SpecialInfo)) return;
    if (si->Buffer) oc_cleanse(si->Buffer, si->MaxChars);
    if (si->UndoBuffer) oc_cleanse(si->UndoBuffer, si->MaxChars);
}

typedef struct ui_ctx {
    struct Window **parent;
} ui_ctx;

static ui_ctx ctx;

static int ask(void *u, const char *owner, unsigned tries, int confirm, char *buf, size_t cap, size_t *len)
{
    ui_ctx *c = u;
    struct Screen *scr = *c->parent ? (*c->parent)->WScreen : LockPubScreen(NULL);
    struct Window *win = NULL;
    struct Gadget *glist = NULL, *g, *gad[G_COUNT];
    struct NewGadget ng;
    APTR vi = NULL;
    static field f1, f2;
    static char line[160];
    int result = GKE_CANCEL, done = 0;
    UWORD fh, w, top;
    memset(gad, 0, sizeof gad);
    memset(&f1, 0, sizeof f1); memset(&f2, 0, sizeof f2);
    f1.hook.h_Entry = (HOOKFUNC)(APTR)edit_hook; f1.hook.h_Data = &f1;
    f2.hook.h_Entry = (HOOKFUNC)(APTR)edit_hook; f2.hook.h_Data = &f2;
    if (!scr) return GKE_CANCEL;
    if (!(vi = GetVisualInfo(scr, TAG_END))) goto out;
    fh = scr->Font->ta_YSize;
    w = 40 * fh;
    top = scr->WBorTop + fh + 1 + 4;
    if (confirm) strcpy(line, "Choose a passphrase for your keys (twice)");
    else if (tries) strcpy(line, "Wrong passphrase. A program calling itself ");
    else strcpy(line, "A program calling itself ");
    if (!confirm) {
        strncat(line, owner, 63);
        strcat(line, " asks for your keys");
    }
    g = CreateContext(&glist);
    memset(&ng, 0, sizeof ng);
    ng.ng_VisualInfo = vi; ng.ng_TextAttr = scr->Font;
    ng.ng_LeftEdge = scr->WBorLeft + 8; ng.ng_TopEdge = top; ng.ng_Width = w - 16; ng.ng_Height = fh + 4;
    ng.ng_GadgetID = G_TEXT;
    g = gad[G_TEXT] = CreateGadget(TEXT_KIND, g, &ng, GTTX_Text, (ULONG)line, TAG_END);
    ng.ng_TopEdge += fh + 10; ng.ng_GadgetID = G_PASS;
    g = gad[G_PASS] = CreateGadget(STRING_KIND, g, &ng, GTST_MaxChars, GK_PASS_MAX - 1,
                                   GTST_EditHook, (ULONG)&f1.hook, TAG_END);
    if (confirm) {
        ng.ng_TopEdge += fh + 10; ng.ng_GadgetID = G_PASS2;
        g = gad[G_PASS2] = CreateGadget(STRING_KIND, g, &ng, GTST_MaxChars, GK_PASS_MAX - 1,
                                        GTST_EditHook, (ULONG)&f2.hook, TAG_END);
    }
    ng.ng_TopEdge += fh + 14; ng.ng_Width = 10 * fh; ng.ng_GadgetID = G_OK;
    ng.ng_GadgetText = (UBYTE *)"_Unlock"; ng.ng_Flags = PLACETEXT_IN;
    if (confirm) ng.ng_GadgetText = (UBYTE *)"_Make";
    g = gad[G_OK] = CreateGadget(BUTTON_KIND, g, &ng, GT_Underscore, '_', TAG_END);
    ng.ng_LeftEdge = scr->WBorLeft + w - 8 - ng.ng_Width; ng.ng_GadgetID = G_CANCEL;
    ng.ng_GadgetText = (UBYTE *)"_Cancel";
    g = gad[G_CANCEL] = CreateGadget(BUTTON_KIND, g, &ng, GT_Underscore, '_', TAG_END);
    if (!g) goto out;
    win = OpenWindowTags(NULL,
                         WA_Title, (ULONG)"Keys", WA_PubScreen, (ULONG)scr,
                         WA_InnerWidth, w, WA_InnerHeight, ng.ng_TopEdge + fh + 10 - scr->WBorTop - fh - 1,
                         WA_Gadgets, (ULONG)glist, WA_Activate, TRUE, WA_DragBar, TRUE, WA_DepthGadget, TRUE,
                         WA_CloseGadget, TRUE, WA_RMBTrap, TRUE,
                         WA_IDCMP, IDCMP_CLOSEWINDOW | IDCMP_REFRESHWINDOW | IDCMP_VANILLAKEY | STRINGIDCMP | BUTTONIDCMP,
                         TAG_END);
    if (!win) goto out;
    GT_RefreshWindow(win, NULL);
    ActivateGadget(gad[G_PASS], win, NULL);
    while (!done) {
        struct IntuiMessage *m;
        WaitPort(win->UserPort);
        while (!done && (m = GT_GetIMsg(win->UserPort))) {
            ULONG cls = m->Class;
            UWORD code = m->Code;
            struct Gadget *hit = (struct Gadget *)m->IAddress;
            GT_ReplyIMsg(m);
            switch (cls) {
            case IDCMP_REFRESHWINDOW:
                GT_BeginRefresh(win); GT_EndRefresh(win, TRUE);
                break;
            case IDCMP_CLOSEWINDOW:
                done = 1;
                break;
            case IDCMP_VANILLAKEY:
                if (code == 0x1b || code == 'c' || code == 'C') done = 1;
                else if (code == 'u' || code == 'U' || code == 'm' || code == 'M' || code == '\r') { result = 1; done = 1; }
                break;
            case IDCMP_GADGETUP:
                if (hit->GadgetID == G_CANCEL) done = 1;
                else if (hit->GadgetID == G_OK) { result = 1; done = 1; }
                else if (hit->GadgetID == G_PASS && confirm) ActivateGadget(gad[G_PASS2], win, NULL);
                else { result = 1; done = 1; }   /* Return in the last field */
                break;
            }
            if (done && result == 1 && confirm && (f1.len != f2.len || memcmp(f1.real, f2.real, f1.len) || !f1.len)) {
                GT_SetGadgetAttrs(gad[G_TEXT], win, NULL, GTTX_Text,
                                  (ULONG)(f1.len ? "The two don't match: type them again" : "The passphrase can't be empty"), TAG_END);
                result = GKE_CANCEL; done = 0;
                ActivateGadget(gad[G_PASS], win, NULL);
            }
        }
    }
    if (result == 1) {
        *len = f1.len < cap ? f1.len : cap;
        memcpy(buf, f1.real, *len);
        result = GKE_OK;
    }
out:
    wipe_gadget(gad[G_PASS]); wipe_gadget(gad[G_PASS2]);
    oc_cleanse(&f1, sizeof f1); oc_cleanse(&f2, sizeof f2);
    if (win) CloseWindow(win);
    FreeGadgets(glist);
    if (vi) FreeVisualInfo(vi);
    if (!*c->parent) UnlockPubScreen(NULL, scr);
    return result;
}

static void warn(void *u, int what, uint64_t counter, uint64_t seen)
{
    ui_ctx *c = u;
    struct EasyStruct es;
    const char *text;
    switch (what) {
    case GKW_OLDER_COPY: text = "An older copy of your keys was opened.\nThe last change may be missing."; break;
    case GKW_ROLLED_BACK: text = "These keys are older than ones used before on this Amiga\n(count %lu, seen %lu)."; break;
    case GKW_READONLY: text = "Opened with an older passphrase.\nNothing can be saved: lock the keys, then\nunlock them with the newer passphrase."; break;
    case GKW_NO_COUNT: text = "The keys' counter file was missing or unreadable.\nAn older copy of the keys can't be told this time."; break;
    default: return;
    }
    es.es_StructSize = sizeof es; es.es_Flags = 0;
    es.es_Title = (UBYTE *)"Keys"; es.es_TextFormat = (UBYTE *)text; es.es_GadgetFormat = (UBYTE *)"OK";
    EasyRequest(*c->parent, &es, NULL, (ULONG)counter, (ULONG)seen);
}

/* "Keys: wrong passphrase. Wait n s" with no stdio (the library has none) */
static void wait_title(char out[48], uint32_t n)
{
    static const char head[] = "Keys: wrong passphrase. Wait ";
    char d[12];
    int i = 0;
    size_t o = sizeof head - 1;
    memcpy(out, head, o);
    do { d[i++] = (char)('0' + n % 10); n /= 10; } while (n && i < 10);
    while (i) out[o++] = d[--i];
    out[o++] = ' '; out[o++] = 's'; out[o] = 0;
}

/* The backoff after wrong passphrases: a small window that counts down
 * "Wait n s", so the user sees why nothing is asked. No IDCMP: it can't be
 * closed early. Without a window it just waits. */
static void wait_s(void *u, uint32_t seconds)
{
    ui_ctx *c = u;
    struct Screen *scr = *c->parent ? (*c->parent)->WScreen : NULL;
    struct Screen *locked = NULL;
    struct Window *win = NULL;
    static char title[48];
    uint32_t left = seconds;
    if (!scr) scr = locked = LockPubScreen(NULL);
    wait_title(title, left);
    if (scr)
        win = OpenWindowTags(NULL, WA_Title, (ULONG)title, WA_PubScreen, (ULONG)scr,
                             WA_InnerWidth, 26 * scr->Font->ta_YSize, WA_InnerHeight, 2,
                             WA_DragBar, TRUE, WA_DepthGadget, TRUE, WA_RMBTrap, TRUE, WA_IDCMP, 0UL, TAG_END);
    if (locked) UnlockPubScreen(NULL, locked);
    for (; left; left--) {
        if (win) {
            wait_title(title, left);
            SetWindowTitles(win, (UBYTE *)title, (UBYTE *)~0);
        }
        Delay(50);
    }
    if (win) CloseWindow(win);
}

void gk_amiga_ui(gk_ui *ui, struct Window **parent)
{
    ctx.parent = parent;
    ui->ask = ask; ui->warn = warn; ui->wait = wait_s; ui->u = &ctx;
}
