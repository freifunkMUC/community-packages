// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include <respondd.h>

#include <json-c/json.h>

#include "statsfile.h"

static struct json_object *counter(const struct clat_stats *st) {
	struct json_object *ret = json_object_new_object();

	json_object_object_add(ret, "packets", json_object_new_int64(st->packets));
	json_object_object_add(ret, "bytes", json_object_new_int64(st->bytes));
	return ret;
}

static struct json_object *respondd_provider_statistics(void) {
	struct json_object *ret = json_object_new_object();
	struct json_object *clat;
	struct clat_stats sum[CLAT_STATS_MAX];

	/* No running CLAT (no 464XLAT on this node): send no clat data. */
	if (clat_stats_read_dir(CLAT_STATS_DIR, sum) <= 0)
		return ret;

	clat = json_object_new_object();
	json_object_object_add(clat, "v4_to_v6", counter(&sum[CLAT_STATS_4TO6]));
	json_object_object_add(clat, "v6_to_v4", counter(&sum[CLAT_STATS_6TO4]));
	json_object_object_add(ret, "clat", clat);

	return ret;
}

const struct respondd_provider_info respondd_providers[] = {
	{"statistics", respondd_provider_statistics},
	{}
};
