// SPDX-License-Identifier: MIT
//
// Send a router advertisement with router lifetime 0 in the name of another
// router: from its link-local address and its MAC address. The clients then
// remove their default route through this router at once, and deprecate the
// listed prefixes (preferred lifetime 0, valid lifetime 0 or the value of -v).
//
// The frame goes directly out of each interface on the command line (packet
// socket). It does not pass the bridge. Thus give only the local client ports,
// never bat0.
//
// Usage: ra-goodbye -s ROUTER_LLADDR -m ROUTER_MAC [-p PREFIX/LEN]...
//                   [-v VALID] [-n COUNT] [-t SECONDS] IFACE...

#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <netinet/icmp6.h>
#include <netinet/in.h>
#include <netinet/ip6.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define MAX_PREFIXES 16
#define ETH_HLEN_ 14
#define IP6_HLEN 40
#define RA_HLEN 16
#define SLLA_LEN 8
#define PI_LEN 32

static void usage(void)
{
	fprintf(stderr, "Usage: ra-goodbye -s ROUTER_LLADDR -m ROUTER_MAC [-p PREFIX/LEN]... "
		"[-v VALID] [-n COUNT] [-t SECONDS] IFACE...\n");
	exit(2);
}

static int parse_mac(const char *s, uint8_t mac[6])
{
	unsigned int b[6];
	char end;

	if (sscanf(s, "%x:%x:%x:%x:%x:%x%c", &b[0], &b[1], &b[2], &b[3], &b[4], &b[5], &end) != 6)
		return -1;
	for (int i = 0; i < 6; i++) {
		if (b[i] > 0xff)
			return -1;
		mac[i] = b[i];
	}
	return 0;
}

static int parse_prefix(const char *s, struct in6_addr *addr, uint8_t *len)
{
	char buf[INET6_ADDRSTRLEN + 4];
	char *slash, *end;
	long l;

	if (strlen(s) >= sizeof(buf))
		return -1;
	strcpy(buf, s);
	slash = strchr(buf, '/');
	if (!slash)
		return -1;
	*slash = '\0';
	l = strtol(slash + 1, &end, 10);
	if (*end || l < 0 || l > 128)
		return -1;
	*len = l;
	return inet_pton(AF_INET6, buf, addr) == 1 ? 0 : -1;
}

static uint16_t checksum(const uint8_t *src, const uint8_t *dst, const uint8_t *data, size_t len)
{
	uint32_t sum = 0;
	size_t i;

	for (i = 0; i < 16; i += 2)
		sum += (src[i] << 8 | src[i + 1]) + (dst[i] << 8 | dst[i + 1]);
	sum += len;
	sum += IPPROTO_ICMPV6;
	for (i = 0; i + 1 < len; i += 2)
		sum += data[i] << 8 | data[i + 1];
	if (len & 1)
		sum += data[len - 1] << 8;
	while (sum >> 16)
		sum = (sum & 0xffff) + (sum >> 16);
	return ~sum;
}

int main(int argc, char *argv[])
{
	struct in6_addr src = {}, dst, prefixes[MAX_PREFIXES];
	uint8_t prefix_lens[MAX_PREFIXES];
	uint8_t mac[6], frame[ETH_HLEN_ + IP6_HLEN + RA_HLEN + SLLA_LEN + MAX_PREFIXES * PI_LEN];
	int n_prefixes = 0, count = 1, interval = 3, have_src = 0, have_mac = 0;
	int opt, fd, sent = 0;
	uint32_t valid = 0;
	char *end;

	while ((opt = getopt(argc, argv, "s:m:p:v:n:t:")) != -1) {
		switch (opt) {
		case 's':
			if (inet_pton(AF_INET6, optarg, &src) != 1 || !IN6_IS_ADDR_LINKLOCAL(&src))
				usage();
			have_src = 1;
			break;
		case 'm':
			if (parse_mac(optarg, mac))
				usage();
			have_mac = 1;
			break;
		case 'p':
			if (n_prefixes == MAX_PREFIXES ||
			    parse_prefix(optarg, &prefixes[n_prefixes], &prefix_lens[n_prefixes]))
				usage();
			n_prefixes++;
			break;
		case 'v':
			valid = strtoul(optarg, &end, 10);
			if (!*optarg || *end)
				usage();
			break;
		case 'n':
			count = atoi(optarg);
			break;
		case 't':
			interval = atoi(optarg);
			break;
		default:
			usage();
		}
	}
	if (!have_src || !have_mac || optind == argc || count < 1 || interval < 0)
		usage();

	inet_pton(AF_INET6, "ff02::1", &dst);

	uint8_t *icmp = frame + ETH_HLEN_ + IP6_HLEN;
	size_t icmp_len = RA_HLEN + SLLA_LEN + n_prefixes * PI_LEN;

	memset(frame, 0, sizeof(frame));
	// Ethernet: all-nodes multicast, from the router MAC
	memcpy(frame, (uint8_t[]){0x33, 0x33, 0, 0, 0, 1}, 6);
	memcpy(frame + 6, mac, 6);
	frame[12] = 0x86;
	frame[13] = 0xdd;

	// IPv6
	uint8_t *ip6 = frame + ETH_HLEN_;
	ip6[0] = 0x60;
	ip6[4] = icmp_len >> 8;
	ip6[5] = icmp_len & 0xff;
	ip6[6] = IPPROTO_ICMPV6;
	ip6[7] = 255;
	memcpy(ip6 + 8, &src, 16);
	memcpy(ip6 + 24, &dst, 16);

	// Router advertisement: router lifetime 0, no other change
	icmp[0] = ND_ROUTER_ADVERT;

	// Source link-layer address
	uint8_t *opt_p = icmp + RA_HLEN;
	opt_p[0] = ND_OPT_SOURCE_LINKADDR;
	opt_p[1] = 1;
	memcpy(opt_p + 2, mac, 6);
	opt_p += SLLA_LEN;

	// Prefix information: on-link, autonomous, preferred lifetime 0
	for (int i = 0; i < n_prefixes; i++, opt_p += PI_LEN) {
		opt_p[0] = ND_OPT_PREFIX_INFORMATION;
		opt_p[1] = 4;
		opt_p[2] = prefix_lens[i];
		opt_p[3] = ND_OPT_PI_FLAG_ONLINK | ND_OPT_PI_FLAG_AUTO;
		opt_p[4] = valid >> 24;
		opt_p[5] = valid >> 16;
		opt_p[6] = valid >> 8;
		opt_p[7] = valid;
		memcpy(opt_p + 16, &prefixes[i], 16);
	}

	uint16_t sum = checksum(ip6 + 8, ip6 + 24, icmp, icmp_len);
	icmp[2] = sum >> 8;
	icmp[3] = sum & 0xff;

	fd = socket(AF_PACKET, SOCK_RAW, 0);
	if (fd < 0) {
		perror("socket");
		return 1;
	}

	for (int round = 0; round < count; round++) {
		if (round)
			sleep(interval);
		for (int i = optind; i < argc; i++) {
			struct sockaddr_ll addr = {
				.sll_family = AF_PACKET,
				.sll_protocol = htons(ETH_P_IPV6),
				.sll_ifindex = if_nametoindex(argv[i]),
				.sll_halen = 6,
			};

			if (!addr.sll_ifindex)
				continue;
			memcpy(addr.sll_addr, frame, 6);
			if (sendto(fd, frame, ETH_HLEN_ + IP6_HLEN + icmp_len, 0,
				   (struct sockaddr *)&addr, sizeof(addr)) >= 0)
				sent++;
		}
	}

	close(fd);
	return sent ? 0 : 1;
}
