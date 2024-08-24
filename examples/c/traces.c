#include <stdio.h>
#include <unistd.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include "traces.skel.h"

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	return vfprintf(stderr, format, args);
}

int main(int argc, char **argv)
{
	struct traces_bpf *skel;
	int err;

	/* Set up libbpf errors and debug info callback */
	libbpf_set_print(libbpf_print_fn);

	/* Open BPF application */
	skel = traces_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open BPF skeleton\n");
		return 1;
	}

	/* ensure BPF program only handles write() syscalls from our process */

	/* Load & verify BPF programs */
	err = traces_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load and verify BPF skeleton\n");
		goto cleanup;
	}

	/* Attach tracepoint handler */
	err = traces_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto cleanup;
	}

	printf("Successfully started! Please run `sudo cat /sys/kernel/debug/tracing/trace_pipe` "
	       "to see output of the BPF programs.\n");

	for (;;) {
		/* trigger our BPF program */
		fprintf(stderr, ".");
		sleep(1);
	}

cleanup:
	traces_bpf__destroy(skel);
	return -err;
}
