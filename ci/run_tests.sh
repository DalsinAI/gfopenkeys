#!/bin/sh
# Host tests for gfopenkeys: builds the keystore core against gfopencrypto's
# own C (openamigatls src/, at the pin below) and runs it plain and under
# ASan/UBSan. OPENAMIGATLS=<path> uses a checkout already there.
# MIT, Copyright (c) 2026 AmiCradle Team.
set -eu
PIN=28b5bf5955bdde4805e60d8f07f8bf2d8c4c5352
here=$(cd "$(dirname "$0")/.." && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
tls=${OPENAMIGATLS:-}
if [ -z "$tls" ]; then
    tls="$work/openamigatls"
    git init -q "$tls"
    git -C "$tls" fetch -q --depth 1 https://github.com/dalsinai/openamigatls "$PIN"
    git -C "$tls" checkout -q FETCH_HEAD
fi
CC=${CC:-cc}
oc="sha1 sha256 sha512 hmac chacha20 argon2"
srcs=""
for f in $oc; do srcs="$srcs $tls/src/opencrypto_$f.c"; done
flags="-std=c99 -Wall -Wextra -Werror -I$here/include -I$here/src -I$tls/include"
build() {
    out=$1; shift
    # gfopencrypto's own files are built without -Werror: they are not ours
    objs=""
    for f in $srcs; do
        o="$work/$(basename "$f" .c)-$out.o"
        $CC -std=c99 -O1 -I"$tls/include" -I"$tls/src" "$@" -c "$f" -o "$o"
        objs="$objs $o"
    done
    $CC $flags -O1 "$@" "$here/src/gk_store.c" "$here/tests/test_store.c" $objs -o "$work/$out"
}
build plain
"$work/plain"
build asan -g -fsanitize=address,undefined -fno-omit-frame-pointer -fno-sanitize-recover=all
"$work/asan"
echo "gfopenkeys host tests: PASS"
