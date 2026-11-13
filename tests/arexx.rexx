/* tests/arexx.rexx: the Keys prefs editor's ARexx port GFOPENKEYS.1 against
   ARexx-RULE.md (return codes 0/5/10/20, no requester holds up a command).
   rx tests/arexx.rexx   (SYS:Prefs/Keys running)
   Run it with a keys file there: LIST and DELETE must answer RC 10 at once,
   with no window. It changes nothing but the timeout, which it puts back
   to 900 s (15 minutes). Prints PASS/FAIL lines, then ALL PASS or n FAILED. */
OPTIONS RESULTS
port = 'GFOPENKEYS.1'
IF ~SHOW('P', port) THEN DO
    SAY 'FAIL' port 'is not there: start SYS:Prefs/Keys first'
    EXIT 20
END
ADDRESS VALUE port
fails = 0

CALL want 'VERSION', 0
CALL want 'HELP', 0
CALL want 'FAULT -2', 0
CALL want 'FAULT x', 10
CALL want 'NOSUCHCOMMAND', 20
CALL want 'SHOW ssh/host/user', 20          /* no command returns a secret */
CALL want 'LOCK', 0
CALL want 'STATUS', 0
IF WORD(res, 4) ~= '0' THEN CALL bad 'STATUS after LOCK gave' res
/* locked: answered at once, never a passphrase requester */
CALL want 'LIST', 10
CALL want 'LIST SERVICE=ssh', 10
CALL want 'DELETE gfopenkeys-try/nohost/nouser', 10
CALL want 'DELETE ssh/host', 10             /* not three parts */
CALL want 'TIMEOUT', 10
CALL want 'TIMEOUT 1x', 10
CALL want 'TIMEOUT 900', 0

CALL want 'DEACTIVATE', 0
CALL want 'ACTIVATE', 0
CALL want 'QUIT', 0

IF fails = 0 THEN SAY 'ALL PASS'
ELSE SAY fails 'FAILED'
EXIT fails

want: PROCEDURE EXPOSE fails res
    PARSE ARG cmd, rcwant
    res = ''
    cmd
    got = rc
    IF got = 0 THEN res = result
    IF got = rcwant THEN SAY 'PASS' cmd 'RC' got
    ELSE CALL bad cmd 'RC' got '(wanted' rcwant')'
    RETURN

bad:
    PARSE ARG why
    SAY 'FAIL' why
    fails = fails + 1
    RETURN
