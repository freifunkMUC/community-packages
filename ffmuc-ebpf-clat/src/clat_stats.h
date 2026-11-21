// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#ifndef CLAT_STATS_H
#define CLAT_STATS_H

#include <linux/types.h>

/* Keys of the clat_stats map. */
enum {
	CLAT_STATS_4TO6 = 0, /* egress: IPv4 from the clients to IPv6 */
	CLAT_STATS_6TO4 = 1, /* ingress: IPv6 to IPv4 for the clients */
	CLAT_STATS_MAX,
};

struct clat_stats {
	__u64 packets;
	__u64 bytes;
};

#endif
