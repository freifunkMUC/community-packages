// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include <errno.h>
#include <limits.h>
#include <net/if.h>
#include <signal.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>
#include <arpa/inet.h>
#include "clat.skel.h"
#include "statsfile.h"

/* Seconds between two writes of the stats file. */
#define STATS_INTERVAL 10

static volatile sig_atomic_t exiting = 0;

static void sig_int(int signo)
{
	exiting = 1;
}

/* Add the per-CPU counters together and write them to the stats file. */
static void write_stats(struct clat_bpf *skel, const char *path) {
	int ncpus = libbpf_num_possible_cpus();
	struct clat_stats sum[CLAT_STATS_MAX] = {};
	struct clat_stats *values;
	__u32 key;
	int cpu;

	if (ncpus <= 0)
		return;
	values = calloc(ncpus, sizeof(*values));
	if (!values)
		return;

	for (key = 0; key < CLAT_STATS_MAX; key++) {
		if (bpf_map__lookup_elem(skel->maps.clat_stats, &key, sizeof(key),
		                         values, sizeof(*values) * ncpus, 0))
			goto out;
		for (cpu = 0; cpu < ncpus; cpu++) {
			sum[key].packets += values[cpu].packets;
			sum[key].bytes += values[cpu].bytes;
		}
	}

	/* The init script can clean the directory while we run. */
	mkdir(CLAT_STATS_DIR, 0755);
	if (clat_stats_write(path, sum))
		fprintf(stderr, "Failed to write %s: %s\n", path, strerror(errno));
out:
	free(values);
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args) {
	return vfprintf(stderr, format, args);
}

int main(int argc, char **argv) {
	if (argc < 4) {
		fprintf(stderr, "Usage: %s <ifindex> <clat addr> <plat addr>\n", argv[0]);
		return -1;
	}

	const int iface = atoi(argv[1]);
	struct clat_bpf *skel;
	int err;
	bool ingress_hooked = false, egress_hooked = false;
	char ifname[IF_NAMESIZE], stats_path[PATH_MAX] = "";
	struct sigaction sa = { .sa_handler = sig_int };
	unsigned int ticks = 0;

	libbpf_set_print(libbpf_print_fn);

	skel = clat_bpf__open_and_load();
	if (!skel) {
		fprintf(stderr, "Failed to open BPF skeleton\n");
		return -2;
	}

	// TODO: Handle size suffix correctly
	inet_pton(AF_INET6, argv[2], &skel->bss->CLAT_PREFIX);
	inet_pton(AF_INET6, argv[3], &skel->bss->PLAT_PREFIX);

	LIBBPF_OPTS(bpf_tc_hook, ingress_hook, .ifindex = iface, .attach_point = BPF_TC_INGRESS);
	err = bpf_tc_hook_create(&ingress_hook);
	if (err && err != -EEXIST) {
		fprintf(stderr, "Failed to create ingress hook: %d\n", err);
		goto cleanup;
	}
	ingress_hooked = true;

	LIBBPF_OPTS(bpf_tc_opts, ingress_tc_opts, .handle = 1, .priority = 1);
	ingress_tc_opts.prog_fd = bpf_program__fd(skel->progs.clat_ingress_6to4);
	err = bpf_tc_attach(&ingress_hook, &ingress_tc_opts);
	if (err) {
		fprintf(stderr, "Failed to attach ingress hook: %d\n", err);
		goto cleanup;
	}

	LIBBPF_OPTS(bpf_tc_hook, egress_hook, .ifindex = iface, .attach_point = BPF_TC_EGRESS);
	err = bpf_tc_hook_create(&egress_hook);
	if (err && err != -EEXIST) {
		fprintf(stderr, "Failed to create egress hook: %d\n", err);
		goto cleanup;
	}
	egress_hooked = true;

	LIBBPF_OPTS(bpf_tc_opts, egress_tc_opts, .handle = 1, .priority = 1);
	egress_tc_opts.prog_fd = bpf_program__fd(skel->progs.clat_egress_4to6);
	err = bpf_tc_attach(&egress_hook, &egress_tc_opts);
	if (err) {
		fprintf(stderr, "Failed to attach egress hook: %d\n", err);
		goto cleanup;
	}

	/* procd stops the service with SIGTERM: also detach the hooks then. */
	if (sigaction(SIGINT, &sa, NULL) || sigaction(SIGTERM, &sa, NULL)) {
		err = errno;
		fprintf(stderr, "Can't set signal handler: %s\n", strerror(errno));
		goto cleanup;
	}

	if (if_indextoname(iface, ifname)) {
		snprintf(stats_path, sizeof(stats_path), CLAT_STATS_DIR "/%s", ifname);
	} else {
		fprintf(stderr, "Cannot find the name of interface %d, no stats file\n", iface);
	}

	printf("Successfully started! Please run `sudo cat /sys/kernel/debug/tracing/trace_pipe` "
				 "to see output of the BPF program.\n");

	while (!exiting) {
		if (stats_path[0] && ticks++ % STATS_INTERVAL == 0)
			write_stats(skel, stats_path);
		sleep(1);
	}

	ingress_tc_opts.flags = ingress_tc_opts.prog_fd = ingress_tc_opts.prog_id = 0;
	err = bpf_tc_detach(&ingress_hook, &ingress_tc_opts);
	if (err) {
		fprintf(stderr, "Failed to detach TC: %d\n", err);
		goto cleanup;
	}

	egress_tc_opts.flags = egress_tc_opts.prog_fd = egress_tc_opts.prog_id = 0;
	err = bpf_tc_detach(&egress_hook, &egress_tc_opts);
	if (err) {
		fprintf(stderr, "Failed to detach TC: %d\n", err);
		goto cleanup;
	}

cleanup:
	if (stats_path[0])
		unlink(stats_path);
	if (ingress_hooked)
		bpf_tc_hook_destroy(&ingress_hook);
	if (egress_hooked)
		bpf_tc_hook_destroy(&egress_hook);
	clat_bpf__destroy(skel);
	return -err;
}
