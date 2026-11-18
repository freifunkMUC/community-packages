#include <respondd.h>

#include <json-c/json.h>
#include <libgluonutil.h>
#include <net/ethernet.h>
#include <stdio.h>
#include <string.h>

#include <netlink/netlink.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/ctrl.h>
#include <batadv-genl.h>

#include "mac.h"

struct mode_netlink_opts {
	bool is_server;
	struct batadv_nlquery_opts query_opts;
};

static const enum batadv_nl_attrs mode_mandatory[] = {
	BATADV_ATTR_GW_MODE,
};

static int parse_mode_netlink_cb(struct nl_msg *msg, void *arg)
{
	struct nlattr *attrs[BATADV_ATTR_MAX+1];
	struct nlmsghdr *nlh = nlmsg_hdr(msg);
	struct batadv_nlquery_opts *query_opts = arg;
	struct genlmsghdr *ghdr;
	struct mode_netlink_opts *opts;
	uint8_t mode;

	opts = batadv_container_of(query_opts, struct mode_netlink_opts,
				   query_opts);

	if (!genlmsg_valid_hdr(nlh, 0))
		return NL_OK;

	ghdr = nlmsg_data(nlh);

	if (ghdr->cmd != BATADV_CMD_GET_MESH_INFO)
		return NL_OK;

	if (nla_parse(attrs, BATADV_ATTR_MAX, genlmsg_attrdata(ghdr, 0),
	    genlmsg_len(ghdr), batadv_genl_policy))
		return NL_OK;

	if (batadv_genl_missing_attrs(attrs, mode_mandatory,
	    BATADV_ARRAY_SIZE(mode_mandatory)))
		return NL_OK;

	mode = nla_get_u8(attrs[BATADV_ATTR_GW_MODE]);

	opts->is_server = mode == BATADV_GW_MODE_SERVER;

	return NL_OK;
}

static bool is_batman_gateway() {
	struct mode_netlink_opts opts = {
		.is_server = false,
		.query_opts = {
			.err = 0,
		},
	};

	batadv_genl_query("bat0", BATADV_CMD_GET_MESH_INFO,
			  parse_mode_netlink_cb, 0,
			  &opts.query_opts);

	return opts.is_server;
}

#define DEFAULT_DST "00000000000000000000000000000000"
#define CLIENT_IF "br-client"

/*
 * Return the MAC address of the IPv6 default router on the client interface.
 * The router address is a link-local EUI-64 address, as Gluon uses for its
 * client bridge. Thus the MAC address is taken from the interface identifier.
 */
static struct json_object * get_gateway6(void) {
	FILE *f = fopen("/proc/net/ipv6_route", "r");
	char dst[33], nexthop[33], dev[17];
	unsigned int dst_len;
	unsigned char iid[8];
	struct ether_addr mac;
	char macstr[F_MAC_LEN + 1];
	int found = 0;

	if (!f)
		return NULL;

	while (fscanf(f, "%32s %x %*s %*s %32s %*s %*s %*s %*s %16s",
		      dst, &dst_len, nexthop, dev) == 4) {
		if (dst_len != 0 || strcmp(dst, DEFAULT_DST) != 0)
			continue;
		if (strcmp(dev, CLIENT_IF) != 0)
			continue;
		if (strncmp(nexthop, "fe80", 4) != 0)
			continue;
		if (sscanf(nexthop + 16, "%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx",
			   &iid[0], &iid[1], &iid[2], &iid[3],
			   &iid[4], &iid[5], &iid[6], &iid[7]) != 8)
			continue;
		if (iid[3] != 0xff || iid[4] != 0xfe)
			continue;

		found = 1;
		break;
	}

	fclose(f);

	if (!found)
		return NULL;

	mac.ether_addr_octet[0] = iid[0] ^ 0x02;
	mac.ether_addr_octet[1] = iid[1];
	mac.ether_addr_octet[2] = iid[2];
	mac.ether_addr_octet[3] = iid[5];
	mac.ether_addr_octet[4] = iid[6];
	mac.ether_addr_octet[5] = iid[7];

	snprintf(macstr, sizeof(macstr), F_MAC, F_MAC_VAR(mac));
	return gluonutil_wrap_string(macstr);
}

static struct json_object * respondd_provider_statistics() {
	struct json_object *ret = json_object_new_object();
	struct json_object *gateway6;

	// We are a batman gateway, do not write gateway6: we do not select a
	// gateway, and the package that made us a gateway describes our uplink
	// itself.
	if (is_batman_gateway())
		return ret;

	// Only report a gateway when we know one. Writing a null would
	// override what another respondd module has to say about gateway6.
	gateway6 = get_gateway6();
	if (gateway6)
		json_object_object_add(ret, "gateway6", gateway6);

	return ret;
}

const struct respondd_provider_info respondd_providers[] = {
	{"statistics", respondd_provider_statistics},
	{}
};
