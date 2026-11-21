// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include "statsfile.h"

#include <dirent.h>
#include <inttypes.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static const char *const names[CLAT_STATS_MAX] = {
	[CLAT_STATS_4TO6] = "v4_to_v6",
	[CLAT_STATS_6TO4] = "v6_to_v4",
};

int clat_stats_write(const char *path, const struct clat_stats st[CLAT_STATS_MAX]) {
	char tmp[PATH_MAX];
	FILE *f;
	int i, ok;

	if (snprintf(tmp, sizeof(tmp), "%s.tmp", path) >= (int)sizeof(tmp))
		return -1;

	f = fopen(tmp, "w");
	if (!f)
		return -1;

	ok = 1;
	for (i = 0; i < CLAT_STATS_MAX; i++)
		if (fprintf(f, "%s %" PRIu64 " %" PRIu64 "\n", names[i],
		            (uint64_t)st[i].packets, (uint64_t)st[i].bytes) < 0)
			ok = 0;

	if (fclose(f) || !ok || rename(tmp, path)) {
		unlink(tmp);
		return -1;
	}
	return 0;
}

int clat_stats_read(const char *path, struct clat_stats sum[CLAT_STATS_MAX]) {
	struct clat_stats st[CLAT_STATS_MAX] = {};
	int seen[CLAT_STATS_MAX] = {};
	char line[128], name[16];
	uint64_t packets, bytes;
	FILE *f;
	int i;

	f = fopen(path, "r");
	if (!f)
		return -1;

	while (fgets(line, sizeof(line), f)) {
		if (sscanf(line, "%15s %" SCNu64 " %" SCNu64, name, &packets, &bytes) != 3)
			continue;
		for (i = 0; i < CLAT_STATS_MAX; i++) {
			if (!strcmp(name, names[i])) {
				st[i].packets = packets;
				st[i].bytes = bytes;
				seen[i] = 1;
			}
		}
	}
	fclose(f);

	for (i = 0; i < CLAT_STATS_MAX; i++)
		if (!seen[i])
			return -1;

	for (i = 0; i < CLAT_STATS_MAX; i++) {
		sum[i].packets += st[i].packets;
		sum[i].bytes += st[i].bytes;
	}
	return 0;
}

int clat_stats_read_dir(const char *dir, struct clat_stats sum[CLAT_STATS_MAX]) {
	char path[PATH_MAX];
	struct dirent *de;
	size_t len;
	DIR *d;
	int n = 0;

	memset(sum, 0, sizeof(struct clat_stats) * CLAT_STATS_MAX);

	d = opendir(dir);
	if (!d)
		return 0;

	while ((de = readdir(d))) {
		if (de->d_name[0] == '.')
			continue;
		/* Skip the temporary files of clat_stats_write(). */
		len = strlen(de->d_name);
		if (len >= 4 && !strcmp(de->d_name + len - 4, ".tmp"))
			continue;
		if (snprintf(path, sizeof(path), "%s/%s", dir, de->d_name) >= (int)sizeof(path))
			continue;
		if (!clat_stats_read(path, sum))
			n++;
	}
	closedir(d);

	return n;
}
