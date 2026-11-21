#!/bin/sh
# Build ebpf-clat and respondd.so, then run e2e-test.py as root. Needs clang
# 20 or later, bpftool, libbpf, libjson-c, the respondd.h header of Gluon,
# python3, iproute2, and a kernel with eBPF and clsact. Run it in a
# privileged container, for example:
#   docker run --rm --privileged -v "$PWD":/p -w /p <image> sh tests/e2e.sh
set -e
cd "$(dirname "$0")/.."
build=$(mktemp -d)
trap 'rm -rf "$build"' EXIT
cp -r src/. "$build"
arch=$(uname -m)
make -s -C "$build" CLANG="${CLANG:-clang}" BPFTOOL="${BPFTOOL:-bpftool}" ARCH="$arch" \
	CLANG_INCLUDES="-I/usr/include/${arch}-linux-gnu" \
	CLAT_CFLAGS="-Wall -Wextra -Wno-unused-parameter -Wno-sign-compare -Werror"
python3 tests/e2e-test.py "$build"
