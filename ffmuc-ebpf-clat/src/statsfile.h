// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#ifndef STATSFILE_H
#define STATSFILE_H

#include "clat_stats.h"

/* The daemon writes one file per interface into this directory. */
#define CLAT_STATS_DIR "/var/run/ebpf-clat"

/* Write the counters to path (atomically: temporary file and rename).
 * Return 0 on success, -1 on error. */
int clat_stats_write(const char *path, const struct clat_stats st[CLAT_STATS_MAX]);

/* Read one stats file and add its counters to sum. Return 0 if the file has
 * both lines, -1 if not (sum stays unchanged then). */
int clat_stats_read(const char *path, struct clat_stats sum[CLAT_STATS_MAX]);

/* Add the counters of all files in dir to sum (sum is set to zero first).
 * Return the number of files read, 0 if dir is missing or has no valid files. */
int clat_stats_read_dir(const char *dir, struct clat_stats sum[CLAT_STATS_MAX]);

#endif
