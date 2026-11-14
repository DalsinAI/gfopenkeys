/* libraries/gfopenkeys.h: gfopenkeys.library, the GFOS keystore (DESIGN.md).
 * Error codes, flags and the service registry shared by every program that
 * keeps a secret. MIT, Copyright (c) 2026 AmiCradle Team. */
#ifndef LIBRARIES_GFOPENKEYS_H
#define LIBRARIES_GFOPENKEYS_H

#define GFOPENKEYS_NAME    "gfopenkeys.library"
#define GFOPENKEYS_VERSION 1

/* Results: 0 is success; the rest are negative. */
#define GKE_OK          0
#define GKE_NOTFOUND   (-1)   /* no such entry */
#define GKE_LOCKED     (-2)   /* the store is locked and GKF_NOPROMPT was given */
#define GKE_BADPASS    (-3)   /* the passphrase doesn't open the store */
#define GKE_DAMAGED    (-4)   /* no copy of the store file opens */
#define GKE_NOSTORE    (-5)   /* no store file yet */
#define GKE_EXISTS     (-6)   /* already there (GK_Store without GKF_REPLACE, or a store made twice) */
#define GKE_SHORT      (-7)   /* the buffer is too small: *len says how much is needed */
#define GKE_BADNAME    (-8)   /* a service, host or user that breaks the naming rule */
#define GKE_TOOBIG     (-9)   /* a secret over GK_MAX_SECRET, or a store over GK_MAX_ENTRIES */
#define GKE_IO        (-10)   /* the file couldn't be read or written */
#define GKE_NOMEM     (-11)
#define GKE_CANCEL    (-12)   /* the user cancelled the passphrase requester */
#define GKE_CRYPTO    (-13)   /* gfopencrypto or the random number source failed */
#define GKE_READONLY  (-14)   /* an older copy was opened with an older passphrase: no writes until the newer one is used */
#define GKE_BUSY      (-15)   /* GKF_NOPROMPT, GK_Status or GK_SetTimeout while another call holds the library (a requester, the timeout check, Argon2): retry; also GK_Store/Delete/Import/ChangePassphrase from a GK_List hook */

/* Flags */
#define GKF_NOPROMPT  (1UL << 0)   /* never open a requester (ARexx callers must pass it) */
#define GKF_REPLACE   (1UL << 1)   /* GK_Store, GK_Import: replace an entry that is there */

/* Limits */
#define GK_MAX_PART     255        /* bytes in a service, host or user */
#define GK_MAX_SERVICE   31
#define GK_MAX_LABEL    127
#define GK_MAX_OWNER     63
#define GK_MAX_SECRET  4096
#define GK_MAX_ENTRIES 4096
#define GK_DEFAULT_TIMEOUT 900     /* seconds after the last use; 0 = never by itself */

/* The library's structures (Amiga programs; the host tests use src/gk_lib.h) */
#ifdef EXEC_TYPES_H
struct GKStatus {                 /* GK_Status: nothing secret */
    LONG  gs_Exists, gs_Unlocked, gs_ReadOnly, gs_RolledBack;
    LONG  gs_OpenedFrom;          /* 0 the store, 1 .new, 2 .bak, -1 locked */
    ULONG gs_Count;
    ULONG gs_SecondsLeft;         /* 0xFFFFFFFF with no timeout */
    ULONG gs_CounterHi, gs_CounterLo;
};

struct GKEntryInfo {              /* GK_List's hook message: never the secret */
    CONST_STRPTR ge_Service, ge_Host, ge_User, ge_Label, ge_Owner;
    ULONG ge_CreatedHi, ge_CreatedLo, ge_LastUsedHi, ge_LastUsedLo;
};

struct GKImport {                 /* one entry for GK_Import */
    CONST_STRPTR gi_Service, gi_Host, gi_User, gi_Label;
    CONST UBYTE *gi_Secret;
    ULONG gi_SecretLen;
};
#endif

/* The service registry (DESIGN.md section 3). A new program adds its word here. */
#define GKS_SSH           "ssh"
#define GKS_SSH_KEY       "ssh-key"       /* host empty, user the key's fingerprint */
#define GKS_FTP           "ftp"
#define GKS_FTPS          "ftps"
#define GKS_SFTP          "sftp"
#define GKS_MAIL_IMAP     "mail-imap"
#define GKS_MAIL_SMTP     "mail-smtp"
#define GKS_MAIL_OAUTH    "mail-oauth"
#define GKS_NNTP          "nntp"
#define GKS_IRC_SASL      "irc-sasl"
#define GKS_IRC_SERVER    "irc-server"
#define GKS_IRC_NICKSERV  "irc-nickserv"
#define GKS_RDP           "rdp"
#define GKS_HTTP          "http"
#define GKS_HTTP_PROXY    "http-proxy"
#define GKS_TELEGRAM_API  "telegram-api"

#endif
