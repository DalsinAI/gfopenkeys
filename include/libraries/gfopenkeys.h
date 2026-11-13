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
#define GK_DEFAULT_TIMEOUT 900     /* seconds after the last use; 0 = until reboot */

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
