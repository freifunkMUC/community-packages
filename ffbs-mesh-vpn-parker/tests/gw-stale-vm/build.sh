#!/bin/sh
# shellcheck disable=SC2012,SC2046,SC2086
# Runs in debian:bookworm (arm64). Builds batman-adv 2024.3 as in the
# firmware (OpenWrt patches, Gluon patch 2002) without and with patch 2003,
# and makes one initrd for each module.
set -e
H=/host
apt-get -qq update
apt-get -qq install -y --no-install-recommends build-essential linux-headers-arm64 \
	linux-image-arm64 batctl busybox-static iproute2 cpio git ca-certificates curl patch >/dev/null
KV=$(ls /lib/modules | head -1)
cd /tmp
curl -sSfL -o b.tgz https://downloads.open-mesh.org/batman/releases/batman-adv-2024.3/batman-adv-2024.3.tar.gz
git clone -q --filter=blob:none --sparse https://github.com/openwrt/routing.git routing
git -C routing sparse-checkout set batman-adv >/dev/null
git -C routing checkout -q 00619bc7
curl -sSfL -o g2002.patch https://raw.githubusercontent.com/ffbs/gluon-parker/029ea6027c5b88740b653daeb30c002ec15d294c/patches/packages/routing/0002-batman-adv-Introduce-no-noflood-mark.patch
for t in stock patched; do
	rm -rf $t; mkdir $t; tar -xzf b.tgz -C $t --strip-components=1
	for p in routing/batman-adv/patches/*.patch; do patch -s -p1 -d $t < $p; done
	# Gluon 0002 is a patch for the routing feed: take the patch it adds.
	sed -n '/^+++ b\/batman-adv\/patches\//,$p' g2002.patch | sed '1d;s/^+//;/^-- $/,$d' | patch -s -p1 -d $t
	[ $t = patched ] && patch -s -p1 -d $t < $H/2003-batman-adv-gw-skip-stale-gateways.patch
	find $t -name '*.orig' -delete; find $t -type f -empty -delete
	make -s -C $t KCFLAGS="-include $H/compat-test.h" KERNELPATH=/lib/modules/$KV/build \
		CONFIG_BATMAN_ADV_BATMAN_V=y
done
M=/lib/modules/$KV/kernel
for t in stock patched; do
	R=/tmp/ir-$t; rm -rf $R; mkdir -p $R/bin $R/usr/sbin $R/lib/mods $R/proc $R/sys $R/run $R/dev $R/var $R/tmp $R/etc
	cp /bin/busybox $R/bin/
	for a in uevent sh mount insmod sleep echo cat grep awk cut poweroff dmesg mkdir ln; do ln -sf busybox $R/bin/$a; done
	for b in /usr/sbin/ip /usr/sbin/batctl; do
		cp $b $R/usr/sbin/
		for l in $(ldd $b | grep -o '/[^ ]*'); do mkdir -p $R$(dirname $l); cp -L $l $R$l; done
	done
	for m in lib/crc16 crypto/crc32c_generic lib/libcrc32c net/rfkill/rfkill net/wireless/cfg80211 \
		net/llc/llc net/802/stp net/bridge/bridge drivers/net/veth; do
		cp $M/$m.ko $R/lib/mods/ 2>/dev/null || true
	done
	cp /tmp/$t/net/batman-adv/batman-adv.ko $R/lib/mods/
	cp $H/init $R/init; cp $H/hotplug $R/bin/hotplug; chmod +x $R/init $R/bin/hotplug
	(cd $R && find . | cpio -o -H newc 2>/dev/null | gzip -1) > $H/out/initrd-$t.gz
done
cp /boot/vmlinuz-$KV $H/out/vmlinuz
