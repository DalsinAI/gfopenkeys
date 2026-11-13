#!/bin/sh
# gfopenkeys.library for AmigaOS 3.x (68040), on the os32-gcc16 stove.
#   STOVE        the stove (default ~/AmiCradle/stoves/os32-gcc16)
#   OPENAMIGATLS an openamigatls checkout already built with its build-amiga.sh
#                (for libgfopencrypto.a, libgfopentls.a and their headers)
#   OUT          the output directory (default build-amiga)
# Outputs: lib/gfopenkeys.library, tests/GFOpenKeysTry, and include/ for programs.
# MIT, Copyright (c) 2026 AmiCradle Team.
set -eu
HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
STOVE=${STOVE:-"$HOME/AmiCradle/stoves/os32-gcc16"}
P="$STOVE/prefix"
CC=${CC:-"$P/bin/m68k-amigaos-gcc"}
OUT=${OUT:-"$HERE/build-amiga"}
TLS=${OPENAMIGATLS:?set OPENAMIGATLS to an openamigatls checkout built with its build-amiga.sh}
TLSOUT="$TLS/build-amiga"
SPECS="$TLS/specs/m68k-soft-m68040.specs"

python3 "$HERE/tools/gen_headers.py"
mkdir -p "$OUT/lib" "$OUT/tests" "$OUT/obj" "$OUT/include"
cp -R "$HERE/include/." "$OUT/include/"

# The same flags as gfopencrypto's own build (openamigatls build-amiga.sh says why each is there)
CFLAGS="-m68040 -specs=$SPECS -O2 -fno-tree-loop-distribute-patterns -fno-delete-null-pointer-checks
        -fomit-frame-pointer -Wall -Wextra -Werror -Wno-unused-parameter
        -I$HERE/include -I$HERE/src -I$TLSOUT/include -I$TLS/include"

# malloc and free are the library's own (library/gk_amiga_env.c): a library has no libnix start-up
"$CC" $CFLAGS -mcrt=nix20 -fno-toplevel-reorder -nostartfiles -fno-builtin-malloc -fno-builtin-free \
  -o "$OUT/lib/gfopenkeys.library" \
  "$HERE/library/gfopenkeys_lib.c" "$HERE/library/gk_amiga_env.c" "$HERE/library/gk_amiga_ui.c" \
  "$HERE/src/gk_store.c" "$HERE/src/gk_lib.c" \
  -L"$TLSOUT/lib" -lgfopencrypto -lgfopentls -lamiga -lgcc -Wl,-Map,"$OUT/lib/gfopenkeys.library.map"
echo "$OUT/lib/gfopenkeys.library ($(wc -c < "$OUT/lib/gfopenkeys.library") bytes)"
if "$P/bin/m68k-amigaos-nm" -u "$OUT/lib/gfopenkeys.library" | grep .; then
    echo "unresolved symbols above"; exit 1
fi

"$CC" $CFLAGS -noixemul -I"$OUT/include" -o "$OUT/tests/GFOpenKeysTry" "$HERE/tests/amiga_try.c"
echo "$OUT/tests/GFOpenKeysTry"
