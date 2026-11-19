#!/bin/sh
# Test patch 2003 (skip stale gateways) in a QEMU VM. Needs docker and
# qemu-system-aarch64 on an arm64 host (for example macOS with hvf).
set -e
cd "$(dirname "$0")"
mkdir -p out
docker run --rm --platform linux/arm64 -v "$PWD":/host debian:bookworm sh /host/build.sh
accel=kvm; [ "$(uname)" = Darwin ] && accel=hvf
for t in stock patched; do
	qemu-system-aarch64 -M virt -accel $accel -cpu host -m 512 -nographic -nic none \
		-kernel out/vmlinuz -initrd out/initrd-$t.gz -append "console=ttyAMA0 quiet mod=$t" \
		> out/run-$t.log 2>&1 || true
	grep -E '===|---|SWITCH|SELECTED|UEVENT' out/run-$t.log
done
