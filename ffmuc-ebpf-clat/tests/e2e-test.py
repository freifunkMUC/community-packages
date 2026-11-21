#!/usr/bin/env python3
"""End-to-end test of the CLAT counters.

Starts ebpf-clat on a TUN device (no L2 header, like WireGuard), sends one
packet in each direction, and checks the stats file, the respondd output, and
the cleanup at SIGTERM. Needs root, a kernel with eBPF and clsact, the built
clat and respondd.so (see e2e.sh).
"""
import ctypes
import fcntl
import json
import os
import select
import socket
import struct
import subprocess
import sys
import time

SRC = sys.argv[1] if len(sys.argv) > 1 else "."
IFNAME = "clat0"
CLAT_PREFIX = "2001:db8:64::"
PLAT_PREFIX = "64:ff9b::"
LOCAL4 = "192.0.0.1"
REMOTE4 = "198.51.100.7"
STATS = "/var/run/ebpf-clat/" + IFNAME
PAYLOAD = b"hello clat"


def csum(data):
    if len(data) % 2:
        data += b"\0"
    s = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return ~s & 0xFFFF


def v6(prefix, addr4):
    raw = bytearray(socket.inet_pton(socket.AF_INET6, prefix))
    raw[12:16] = socket.inet_aton(addr4)
    return bytes(raw)


def udp6(src, dst, sport, dport, payload):
    length = 8 + len(payload)
    pseudo = src + dst + struct.pack("!I3xB", length, 17)
    udp = struct.pack("!HHHH", sport, dport, length, 0) + payload
    udp = udp[:6] + struct.pack("!H", csum(pseudo + udp)) + udp[8:]
    hdr = struct.pack("!IHBB", 6 << 28, length, 17, 64) + src + dst
    return hdr + udp


def open_tun(name):
    fd = os.open("/dev/net/tun", os.O_RDWR)
    # TUNSETIFF, IFF_TUN | IFF_NO_PI
    fcntl.ioctl(fd, 0x400454CA, struct.pack("16sH", name.encode(), 0x0001 | 0x1000))
    return fd


def respondd_statistics():
    json_c = ctypes.CDLL("libjson-c.so.5")
    json_c.json_object_to_json_string.restype = ctypes.c_char_p
    json_c.json_object_to_json_string.argtypes = [ctypes.c_void_p]
    mod = ctypes.CDLL(os.path.join(SRC, "respondd.so"))

    class Provider(ctypes.Structure):
        _fields_ = [("request", ctypes.c_char_p),
                    ("provider", ctypes.CFUNCTYPE(ctypes.c_void_p))]

    providers = ctypes.cast(mod.respondd_providers, ctypes.POINTER(Provider))
    assert providers[0].request == b"statistics"
    return json.loads(json_c.json_object_to_json_string(providers[0].provider()))


def check(cond, msg):
    if not cond:
        print("FAIL:", msg)
        sys.exit(1)


def main():
    fd = open_tun(IFNAME)
    subprocess.run(["ip", "link", "set", IFNAME, "up"], check=True)
    subprocess.run(["ip", "addr", "add", LOCAL4 + "/32", "dev", IFNAME], check=True)
    subprocess.run(["ip", "route", "add", REMOTE4 + "/32", "dev", IFNAME], check=True)
    ifindex = socket.if_nametoindex(IFNAME)

    check(respondd_statistics() == {}, "clat data without a running CLAT")

    clat = subprocess.Popen([os.path.join(SRC, "clat"), str(ifindex), CLAT_PREFIX, PLAT_PREFIX],
                            stdout=subprocess.DEVNULL)
    try:
        for _ in range(50):
            if os.path.exists(STATS):
                break
            time.sleep(0.1)
        check(os.path.exists(STATS), "no stats file after start")

        # 4to6: an IPv4 packet goes out of the tunnel as IPv6.
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind((LOCAL4, 4000))
        sock.sendto(PAYLOAD, (REMOTE4, 5000))
        out = None
        while select.select([fd], [], [], 2)[0]:
            pkt = os.read(fd, 2048)
            if pkt[0] >> 4 == 6 and pkt[6] == 17:
                out = pkt
                break
        check(out is not None, "no translated IPv6 packet on the tunnel")
        check(out[24:40] == v6(PLAT_PREFIX, REMOTE4), "wrong IPv6 destination")

        # 6to4: an IPv6 packet comes in from the tunnel and arrives as IPv4.
        os.write(fd, udp6(v6(PLAT_PREFIX, REMOTE4), v6(CLAT_PREFIX, LOCAL4), 5000, 4000, PAYLOAD))
        sock.settimeout(2)
        data, peer = sock.recvfrom(2048)
        check(data == PAYLOAD and peer == (REMOTE4, 5000), "wrong translated IPv4 packet")

        # A packet that the CLAT does not translate (wrong prefix) does not count.
        os.write(fd, udp6(v6("2001:db8:99::", REMOTE4), v6(CLAT_PREFIX, LOCAL4), 5000, 4000, PAYLOAD))

        # The daemon writes the file every 10 s.
        v4len = 20 + 8 + len(PAYLOAD)
        counter = {"packets": 1, "bytes": v4len}
        want = {"clat": {"v4_to_v6": counter, "v6_to_v4": counter}}
        got = None
        for _ in range(150):
            got = respondd_statistics()
            if got == want:
                break
            time.sleep(0.1)
        check(got == want, "respondd: got %s, want %s" % (got, want))
        print("respondd statistics:", json.dumps(got))
    finally:
        clat.terminate()
        clat.wait(timeout=5)

    check(not os.path.exists(STATS), "stats file stays after SIGTERM")
    check(respondd_statistics() == {}, "clat data after stop")
    print("e2e-test: OK")


main()
