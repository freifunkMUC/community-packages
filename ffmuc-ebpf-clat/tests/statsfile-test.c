// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Test of the stats files that the daemon writes and respondd reads. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "statsfile.h"

static int failures;

#define CHECK(cond) do { \
	if (!(cond)) { \
		fprintf(stderr, "%s:%d: FAIL: %s\n", __FILE__, __LINE__, #cond); \
		failures++; \
	} \
} while (0)

static void put(const char *dir, const char *name, const char *content) {
	char path[512];
	FILE *f;

	snprintf(path, sizeof(path), "%s/%s", dir, name);
	f = fopen(path, "w");
	if (!f) {
		perror(path);
		exit(1);
	}
	fputs(content, f);
	fclose(f);
}

int main(void) {
	char dir[] = "/tmp/clat-stats-test.XXXXXX";
	char path[512], missing[600];
	struct clat_stats sum[CLAT_STATS_MAX];
	struct clat_stats st[CLAT_STATS_MAX] = {
		[CLAT_STATS_4TO6] = { .packets = 3, .bytes = 18446744073709551615ULL },
		[CLAT_STATS_6TO4] = { .packets = 0, .bytes = 0 },
	};

	if (!mkdtemp(dir)) {
		perror("mkdtemp");
		return 1;
	}

	/* No directory: no data (node without 464XLAT). */
	snprintf(missing, sizeof(missing), "%s/missing", dir);
	CHECK(clat_stats_read_dir(missing, sum) == 0);
	CHECK(sum[CLAT_STATS_4TO6].packets == 0);

	/* Empty directory: no data. */
	CHECK(clat_stats_read_dir(dir, sum) == 0);

	/* Write and read back, including the largest 64-bit value. */
	snprintf(path, sizeof(path), "%s/wg_mesh_vpn", dir);
	CHECK(clat_stats_write(path, st) == 0);
	CHECK(access(path, F_OK) == 0);
	snprintf(missing, sizeof(missing), "%s.tmp", path);
	CHECK(access(missing, F_OK) != 0);
	CHECK(clat_stats_read_dir(dir, sum) == 1);
	CHECK(sum[CLAT_STATS_4TO6].packets == 3);
	CHECK(sum[CLAT_STATS_4TO6].bytes == 18446744073709551615ULL);
	CHECK(sum[CLAT_STATS_6TO4].packets == 0);

	/* The write replaces the old values. */
	st[CLAT_STATS_4TO6].bytes = 1000;
	st[CLAT_STATS_6TO4].packets = 5;
	st[CLAT_STATS_6TO4].bytes = 700;
	CHECK(clat_stats_write(path, st) == 0);

	/* A second tunnel (multi-site), lines in other order. Junk files and
	 * temporary files do not count. */
	put(dir, "wg_site2", "v6_to_v4 10 2000\nv4_to_v6 7 900\n");
	put(dir, "broken", "v4_to_v6 1 1\n");
	put(dir, "garbage", "hello\n\n");
	put(dir, "wg_site3.tmp", "v4_to_v6 100 100\nv6_to_v4 100 100\n");
	put(dir, ".hidden", "v4_to_v6 100 100\nv6_to_v4 100 100\n");

	CHECK(clat_stats_read_dir(dir, sum) == 2);
	CHECK(sum[CLAT_STATS_4TO6].packets == 10);
	CHECK(sum[CLAT_STATS_4TO6].bytes == 1900);
	CHECK(sum[CLAT_STATS_6TO4].packets == 15);
	CHECK(sum[CLAT_STATS_6TO4].bytes == 2700);

	/* A read of a bad file leaves the sum unchanged. */
	snprintf(path, sizeof(path), "%s/broken", dir);
	CHECK(clat_stats_read(path, sum) == -1);
	CHECK(sum[CLAT_STATS_4TO6].packets == 10);

	/* Write to a missing directory fails and leaves no file. */
	snprintf(path, sizeof(path), "%s/missing/x", dir);
	CHECK(clat_stats_write(path, st) == -1);

	snprintf(path, sizeof(path), "rm -rf '%s'", dir);
	if (system(path))
		fprintf(stderr, "cleanup of %s failed\n", dir);

	if (failures) {
		fprintf(stderr, "%d failures\n", failures);
		return 1;
	}
	printf("statsfile-test: OK\n");
	return 0;
}
