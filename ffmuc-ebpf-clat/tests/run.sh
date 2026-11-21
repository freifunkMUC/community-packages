#!/bin/sh
# Test of the stats files between the daemon and the respondd module. Needs a
# C compiler and Linux headers. On another OS:
#   docker run --rm -v "$PWD":/p -w /p gcc:14 sh tests/run.sh
set -e
cd "$(dirname "$0")"
out=$(mktemp)
trap 'rm -f "$out"' EXIT
${CC:-cc} -Wall -Werror -fsanitize=address,undefined -I../src -o "$out" statsfile-test.c ../src/statsfile.c
"$out"
