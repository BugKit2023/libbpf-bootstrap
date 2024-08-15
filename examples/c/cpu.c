// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2020 Facebook */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include "cpu.skel.h"

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	return vfprintf(stderr, format, args);
}

int main(int argc, char **argv)
{
	struct cpu_bpf *skel;
	int err;

	/* Set up libbpf errors and debug info callback */
	libbpf_set_print(libbpf_print_fn);

	/* Open BPF application */
	skel = cpu_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open BPF skeleton\n");
		return 1;
	}

	/* Load & verify BPF programs */
	err = cpu_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load and verify BPF skeleton\n");
		goto cleanup;
	}

	/* Attach tracepoint handler */
	err = cpu_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto cleanup;
	}

	printf("Tracking CPU usage. Press Ctrl+C to stop.\n");

	_u32 pid = 0, next_pid;
    _u64 value;
    while (1) {
        while (bpf_map_get_next_key(bpf_map__fd(skel->maps.cpu_times), &pid, &next_pid) == 0) {
            if (bpf_map_lookup_elem(bpf_map__fd(skel->maps.cpu_times), &next_pid, &value) == 0) {
                printf("Process %u used %llu ns of CPU time\n", next_pid, value);
            }
            pid = next_pid;
        }
        sleep(1);
    }

cleanup:
	cpu_bpf__destroy(skel);
	return -err;
}
