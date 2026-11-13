/* KeysStatus.rexx: say whether your keys are unlocked, and list their names
   (never a secret). Needs SYS:Prefs/Keys running.
   MIT, Copyright (c) 2026 AmiCradle Team. */
OPTIONS RESULTS
IF ~SHOW('P', 'GFOPENKEYS.1') THEN DO
    SAY 'Start SYS:Prefs/Keys first'
    EXIT 10
END
ADDRESS 'GFOPENKEYS.1'
'STATUS'
PARSE VAR result . exists . unlocked . readonly . count . left
IF exists = 0 THEN DO
    SAY 'No keys yet'
    EXIT 0
END
IF unlocked = 0 THEN DO
    SAY 'Your keys are locked'
    EXIT 0
END
SAY 'Unlocked:' count 'keys, locks in' left 'seconds'
'LIST'
IF rc = 0 THEN SAY result
EXIT 0
